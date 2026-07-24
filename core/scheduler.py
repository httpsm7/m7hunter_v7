#!/usr/bin/env python3
# core/scheduler.py — True Authoritative Async Scheduler
# Buildmap 2: The ONLY execution authority. DAG + retry + timeout + orphan cleanup
# Buildmap 1: Fully asyncio-native — NO time.sleep(), NO rogue threads
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import asyncio, time, uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable
from core.error_handler import get_handler


class StageState(Enum):
    IDLE     = "idle"
    WARMING  = "warming"
    RUNNING  = "running"
    PAUSED   = "paused"
    FLUSHING = "flushing"
    SLEEPING = "sleeping"
    DONE     = "done"
    FAILED   = "failed"
    SKIPPED  = "skipped"


@dataclass
class StageExecution:
    name        : str
    state       : StageState = StageState.IDLE
    started_at  : float = 0.0
    finished_at : float = 0.0
    findings_n  : int   = 0
    error       : str   = ""
    retries     : int   = 0
    task        : asyncio.Task | None = None


class Scheduler:
    """
    Buildmap 2: TRUE authoritative async scheduler.

    Rules:
    - ONLY execution authority — no engine self-manages
    - Fully asyncio-native — no time.sleep(), no threads
    - DAG dependency enforcement
    - Retry with exponential backoff
    - Per-task timeout enforcement
    - Orphan task detection and cleanup
    - Pause/resume support
    - Checkpoint coordination after each stage

    Lifecycle per stage:
    IDLE → WARMING → RUNNING → FLUSHING → SLEEPING → DONE
    """

    POLL_INTERVAL   = 0.5     # seconds between scheduler ticks
    MAX_RETRIES     = 2
    DEFAULT_TIMEOUT = 1800.0  # 30 min per stage

    def __init__(self, pipeline, resource_ctrl, state_mgr, registry, log=None):
        self.p       = pipeline
        self.rctrl   = resource_ctrl
        self.state   = state_mgr
        self.registry = registry
        self.log     = log or pipeline.log
        self._scan_id = getattr(pipeline, "scan_id", str(uuid.uuid4())[:8])
        self._execs  : dict[str, StageExecution] = {}
        self._stop_event  = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # not paused by default
        self._done_callbacks : list[Callable] = []
        self._active_tasks   : dict[str, asyncio.Task] = {}
        self._lock           = asyncio.Lock()

    def on_stage_done(self, fn: Callable):
        self._done_callbacks.append(fn)

    # ── Main entry ────────────────────────────────────────────────────
    async def run_all(self, engine_names: list, resume: bool = False):
        ordered = self.registry.topological_order(engine_names)

        if resume:
            pending = self.state.get_pending_stages(self._scan_id, ordered)
            for name in ordered:
                if name not in pending:
                    self._mark(name, StageState.SKIPPED)
                    self.log.info(f"[Scheduler] SKIP (done): {name}")
            ordered = pending
        else:
            self.log.info(f"[Scheduler] Run {len(ordered)} stages (DAG order)")

        for name in ordered:
            if name not in self._execs:
                self._execs[name] = StageExecution(name=name)

        # Main async scheduling loop
        remaining = list(ordered)
        while remaining and not self._stop_event.is_set():
            await self._pause_event.wait()  # respect global pause

            progressed = False
            for name in list(remaining):
                if self._can_wake(name):
                    remaining.remove(name)
                    task = asyncio.create_task(
                        self._run_stage(name),
                        name=f"m7-stage-{name}"
                    )
                    async with self._lock:
                        self._active_tasks[name] = task
                    progressed = True

            if not progressed:
                await asyncio.sleep(self.POLL_INTERVAL)

        # Drain all running tasks
        await self._drain()
        await self._cleanup_orphans()
        self.log.info(f"[Scheduler] Complete — {self._summary()}")

    def stop(self):
        self._stop_event.set()

    async def pause_all(self):
        self._pause_event.clear()
        self.log.warn("[Scheduler] PAUSED")

    async def resume_all(self):
        self._pause_event.set()
        self.log.info("[Scheduler] RESUMED")

    # ── Stage execution ───────────────────────────────────────────────
    async def _run_stage(self, name: str):
        spec    = self.registry.get(name)
        ram_cls = spec.ram_class if spec else "medium"
        ex      = self._execs[name]

        self.rctrl.register_start(name, ram_cls)
        self.state.stage_start(self._scan_id, name)

        # Watchdog heartbeat
        if hasattr(self.p, "watchdog") and self.p.watchdog:
            self.p.watchdog.register_engine(name)

        try:
            # WARMING
            ex.state      = StageState.WARMING
            ex.started_at = time.time()
            self.log.info(f"[Scheduler] WARMING  {name}")

            engine = self.registry.instantiate(name, self.p)
            if not engine:
                raise RuntimeError(f"Cannot instantiate: {name}")

            # RUNNING — with timeout enforcement
            ex.state = StageState.RUNNING
            self.log.info(f"[Scheduler] RUNNING  {name}")

            timeout = getattr(spec, "timeout_s", self.DEFAULT_TIMEOUT)
            await asyncio.wait_for(
                self._execute_engine(engine, name),
                timeout=timeout
            )

            ex.findings_n  = getattr(engine, "_n_findings", 0)

            # FLUSHING
            ex.state = StageState.FLUSHING
            await self._flush_stage(name, engine)

            # SLEEPING
            ex.state = StageState.SLEEPING
            await asyncio.sleep(0.3)

            # DONE
            ex.state       = StageState.DONE
            ex.finished_at = time.time()
            elapsed = round(ex.finished_at - ex.started_at, 1)
            self.log.info(
                f"[Scheduler] DONE     {name} "
                f"({elapsed}s | {ex.findings_n} findings)"
            )
            self.state.stage_done(
                self._scan_id, name, findings_n=ex.findings_n
            )

        except asyncio.TimeoutError:
            ex.state = StageState.FAILED
            ex.error = f"timeout after {timeout}s"
            get_handler().capture(f"scheduler/{name}",
                                  asyncio.TimeoutError(), "timeout")
            self.log.error(f"[Scheduler] TIMEOUT  {name}")
            self.state.stage_done(self._scan_id, name,
                                  error=ex.error)
            await self._handle_retry(name)

        except asyncio.CancelledError:
            ex.state = StageState.FAILED
            ex.error = "cancelled"
            self.state.stage_done(self._scan_id, name, error="cancelled")
            raise

        except Exception as e:
            ex.state = StageState.FAILED
            ex.error = str(e)
            get_handler().capture(f"scheduler/{name}", e, "run_stage")
            self.log.error(f"[Scheduler] FAILED   {name}: {e}")
            self.state.stage_done(self._scan_id, name, error=str(e))
            await self._handle_retry(name)

        finally:
            self.rctrl.register_finish(name, ram_cls)
            if hasattr(self.p, "watchdog") and self.p.watchdog:
                self.p.watchdog.unregister_engine(name)
            async with self._lock:
                self._active_tasks.pop(name, None)
            for cb in self._done_callbacks:
                try:
                    cb(name, ex)
                except Exception as e:
                    get_handler().capture("scheduler", e, f"done_cb:{name}")

    async def _execute_engine(self, engine, name: str):
        """Execute engine — supports both async BaseEngine and legacy sync."""
        if hasattr(engine, "run_lifecycle"):
            # New BaseEngine — fully async
            await engine.run_lifecycle()
        elif hasattr(engine, "run"):
            # Legacy stepXX module — run in executor to avoid blocking loop
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, engine.run)

    async def _flush_stage(self, name: str, engine):
        """After stage: flush findings → SQLite, release handles."""
        try:
            if hasattr(self.p, "findings_engine"):
                findings = self.p.findings_engine.get_all()
                stage_findings = [f for f in findings
                                  if f.get("stage") == name]
                if stage_findings:
                    self.state.persist_findings_bulk(
                        self._scan_id, stage_findings
                    )
            # Release engine handles
            if hasattr(engine, "_close_handles"):
                engine._close_handles()
            elif hasattr(engine, "_release_handles"):
                engine._release_handles()
            # Checkpoint
            self.state.save_checkpoint(self._scan_id, f"{name}_done", {
                "ts"      : time.time(),
                "findings": getattr(engine, "_n_findings", 0),
                "ram"     : self.rctrl.status_str(),
            })
        except Exception as e:
            get_handler().capture(f"scheduler/{name}", e, "_flush_stage")

    async def _handle_retry(self, name: str):
        ex = self._execs.get(name)
        if not ex or ex.retries >= self.MAX_RETRIES:
            return
        ex.retries += 1
        ex.state = StageState.IDLE
        backoff  = 2 ** ex.retries * 3
        self.log.warn(
            f"[Scheduler] RETRY {name} "
            f"({ex.retries}/{self.MAX_RETRIES}) in {backoff}s"
        )
        await asyncio.sleep(backoff)

    # ── Dependency check ──────────────────────────────────────────────
    def _can_wake(self, name: str) -> bool:
        ex = self._execs.get(name)
        if not ex or ex.state != StageState.IDLE:
            return False
        spec = self.registry.get(name)
        if not spec:
            return False
        # All deps must be DONE or SKIPPED
        for dep in spec.dependencies:
            dep_ex = self._execs.get(dep)
            if dep_ex is None:
                continue
            if dep_ex.state not in (StageState.DONE,
                                    StageState.SKIPPED,
                                    StageState.FAILED):
                return False
        # Resource gate
        allowed, reason = self.rctrl.can_start(spec.ram_class)
        return allowed

    # ── Cleanup ───────────────────────────────────────────────────────
    async def _drain(self):
        """Wait for all active tasks to complete."""
        for attempt in range(120):
            async with self._lock:
                active = [t for t in self._active_tasks.values()
                          if not t.done()]
            if not active:
                break
            await asyncio.sleep(1.0)

    async def _cleanup_orphans(self):
        """Cancel any tasks that should be done but are still running."""
        async with self._lock:
            orphans = {
                n: t for n, t in self._active_tasks.items()
                if not t.done()
            }
        if orphans:
            self.log.warn(f"[Scheduler] Cleaning {len(orphans)} orphan tasks")
            for name, task in orphans.items():
                task.cancel()
                try:
                    await asyncio.wait_for(asyncio.shield(task), timeout=3)
                except Exception:
                    pass

    def _mark(self, name: str, state: StageState):
        if name not in self._execs:
            self._execs[name] = StageExecution(name=name)
        self._execs[name].state = state

    def _summary(self) -> str:
        counts = {}
        for ex in self._execs.values():
            s = ex.state.value
            counts[s] = counts.get(s, 0) + 1
        return " | ".join(f"{s}:{n}" for s, n in sorted(counts.items()))

    def stage_states(self) -> dict:
        return {n: ex.state.value for n, ex in self._execs.items()}

    def is_done(self) -> bool:
        terminal = {StageState.DONE, StageState.FAILED,
                    StageState.SKIPPED, StageState.SLEEPING}
        return all(ex.state in terminal for ex in self._execs.values())
