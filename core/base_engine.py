#!/usr/bin/env python3
# core/base_engine.py — BaseEngine: Unified Abstract Lifecycle
# Buildmap 5: ALL scan systems must use common engine interface + lifecycle
# Replaces old stepXX module pattern with unified architecture
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import asyncio, time
from abc import ABC, abstractmethod
from enum import Enum
from core.error_handler import get_handler


class EngineState(Enum):
    IDLE     = "idle"
    WARMING  = "warming"
    RUNNING  = "running"
    PAUSED   = "paused"
    FLUSHING = "flushing"
    SLEEPING = "sleeping"
    FAILED   = "failed"
    DONE     = "done"


class BaseEngine(ABC):
    """
    Buildmap 5: Unified engine base class.
    ALL scan modules MUST inherit this.
    Enforces lifecycle: IDLE→WARMING→RUNNING→FLUSHING→SLEEPING→DONE

    Lifecycle hooks (override as needed):
      warm()    → setup, validate tools
      execute() → main scan logic  [REQUIRED]
      flush()   → write findings, release handles
      sleep()   → brief cooldown before DONE

    Scheduler calls run_lifecycle() — never calls hooks directly.
    """

    # ── Engine metadata (override in subclass) ────────────────────────
    name        : str  = "unnamed_engine"
    description : str  = ""
    version     : str  = "1.0"
    dependencies: list = []
    resource_cost: str = "medium"    # minimal/low/medium/high/critical
    stage_group : str  = "vuln"
    safe_mode   : bool = False
    requires_lab: bool = False

    def __init__(self, pipeline):
        self.p          = pipeline
        self.log        = pipeline.log
        self.args       = pipeline.args
        self.target     = pipeline.target
        self._state     = EngineState.IDLE
        self._start_ts  = 0.0
        self._n_findings = 0
        self._handles   = []         # file/network/browser handles → closed in flush()
        self._pause_event : asyncio.Event | None = None  # created lazily in async context

    # ── Required override ─────────────────────────────────────────────
    @abstractmethod
    async def execute(self):
        """Main scan logic. MUST be async. MUST NOT block event loop."""

    # ── Optional lifecycle hooks ──────────────────────────────────────
    async def warm(self):
        """Warming phase: validate tools, setup resources."""

    async def flush(self):
        """Flushing phase: write all findings to SQLite, release handles."""
        self._close_handles()

    async def sleep(self):
        """Sleeping phase: brief cooldown."""
        await asyncio.sleep(0.2)

    # ── Scheduler calls this ──────────────────────────────────────────
    async def run_lifecycle(self) -> dict:
        """Full lifecycle execution — called by Scheduler only."""
        result = {
            "engine"    : self.name,
            "status"    : "unknown",
            "findings"  : 0,
            "duration_s": 0.0,
            "error"     : "",
        }
        self._start_ts = time.time()

        # WARMING
        try:
            self._transition(EngineState.WARMING)
            await self.warm()
        except Exception as e:
            get_handler().capture(self.name, e, "warm()")

        # RUNNING
        try:
            self._transition(EngineState.RUNNING)
            await self.execute()
        except Exception as e:
            self._transition(EngineState.FAILED)
            result["status"] = "failed"
            result["error"]  = str(e)
            get_handler().capture(self.name, e, "execute()")
            return result
        finally:
            self._transition(EngineState.FLUSHING)

        # FLUSHING
        try:
            await self.flush()
        except Exception as e:
            get_handler().capture(self.name, e, "flush()")

        # SLEEPING
        try:
            self._transition(EngineState.SLEEPING)
            await self.sleep()
        except Exception as e:
            get_handler().capture(self.name, e, "sleep()")

        # DONE
        self._transition(EngineState.DONE)
        duration = round(time.time() - self._start_ts, 2)
        result.update({
            "status"    : "done",
            "findings"  : self._n_findings,
            "duration_s": duration,
        })
        self.log.info(
            f"[{self.name}] ✓ {duration}s | findings:{self._n_findings}"
        )
        return result

    # ── Pause / resume (Scheduler controls this) ──────────────────────
    async def pause(self):
        if self._pause_event: self._pause_event.clear()
        self._transition(EngineState.PAUSED)

    async def resume(self):
        if self._pause_event: self._pause_event.set()
        if self._state == EngineState.PAUSED:
            self._transition(EngineState.RUNNING)

    async def wait_if_paused(self):
        """Call inside execute() hot loops to respect pause."""
        if self._pause_event is None:
            self._pause_event = asyncio.Event()
            self._pause_event.set()
        await self._pause_event.wait()

    # ── Handle tracking ───────────────────────────────────────────────
    def track(self, handle):
        """Register a file/network/browser handle for cleanup."""
        self._handles.append(handle)
        return handle

    def _close_handles(self):
        for h in self._handles:
            try:
                if hasattr(h, "close"): h.close()
                elif hasattr(h, "aclose"):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(h.aclose())
                    except RuntimeError:
                        pass  # no running loop
            except Exception as e:
                get_handler().capture(self.name, e, "close_handle")
        self._handles.clear()

    # ── Finding registration ──────────────────────────────────────────
    def add_finding(self, vuln_type: str, url: str, detail: str,
                    confidence: float, severity: str):
        self._n_findings += 1
        try:
            self.p.findings_engine.add(
                vuln_type=vuln_type, url=url, detail=detail,
                confidence=confidence, severity=severity, stage=self.name
            )
        except Exception as e:
            get_handler().capture(self.name, e, f"add_finding:{vuln_type}")

    # ── Heartbeat (Watchdog integration) ─────────────────────────────
    def heartbeat(self, progress: float = 0.0):
        try:
            from core.watchdog import Watchdog
            if hasattr(self.p, "watchdog") and self.p.watchdog:
                self.p.watchdog.heartbeat(self.name, self._state.value, progress)
        except Exception:
            pass

    # ── Shell execution (async-safe) ─────────────────────────────────
    async def shell_async(self, cmd: str, timeout: int = 300) -> str:
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return stdout.decode(errors="ignore")
            except asyncio.TimeoutError:
                proc.kill()
                return ""
        except Exception as e:
            get_handler().capture(self.name, e, f"shell_async:{cmd[:60]}")
            return ""

    def shell(self, cmd: str, timeout: int = 300) -> str:
        """Sync shell for backward compat — runs via pipeline.shell()."""
        try:
            return self.p.shell(cmd, timeout=timeout)
        except Exception as e:
            get_handler().capture(self.name, e, f"shell:{cmd[:60]}")
            return ""

    # ── Internal ──────────────────────────────────────────────────────
    def _transition(self, new_state: EngineState):
        self._state = new_state

    @property
    def state(self) -> str:
        return self._state.value

    @property
    def is_running(self) -> bool:
        return self._state == EngineState.RUNNING

    @classmethod
    def get_metadata(cls) -> dict:
        return {
            "name"         : cls.name,
            "version"      : cls.version,
            "description"  : cls.description,
            "dependencies" : cls.dependencies,
            "resource_cost": cls.resource_cost,
            "stage_group"  : cls.stage_group,
            "requires_lab" : cls.requires_lab,
        }
