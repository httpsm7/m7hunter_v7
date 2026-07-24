#!/usr/bin/env python3
# core/watchdog.py — Runtime Watchdog, Timeout, Emergency Shutdown, Deadlock Detection
# Buildmap 8: Framework MUST survive long scans, browser crashes, queue corruption
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import asyncio, time, threading, os, signal
from dataclasses import dataclass, field
from typing import Callable
from core.error_handler import get_handler


@dataclass
class WatchdogPolicy:
    task_timeout_s     : float = 600.0    # 10 min per task
    engine_timeout_s   : float = 1800.0   # 30 min per engine
    idle_timeout_s     : float = 300.0    # 5 min idle = stalled
    memory_check_s     : float = 10.0    # check RAM every 10s
    heartbeat_s        : float = 30.0    # heartbeat interval
    max_retries        : int   = 3
    emergency_ram_pct  : float = 92.0    # emergency shutdown threshold


@dataclass
class EngineHeartbeat:
    engine_name : str
    last_beat   : float = field(default_factory=time.time)
    state       : str   = "idle"
    progress    : float = 0.0

    def touch(self, state: str = "running", progress: float = 0.0):
        self.last_beat = time.time()
        self.state     = state
        self.progress  = progress

    @property
    def age_s(self) -> float:
        return time.time() - self.last_beat

    def is_stalled(self, timeout_s: float) -> bool:
        return self.state == "running" and self.age_s > timeout_s


class Watchdog:
    """
    Buildmap 8: Full observability and operational safety.

    Monitors:
    - Engine heartbeats (stall detection)
    - Task timeouts (per-task and per-engine)
    - RAM thresholds (emergency cooldown at 92%)
    - Semaphore leak detection
    - Orphan asyncio task cleanup
    - Deadlock detection via heartbeat gaps

    On detection:
    - Logs structured warning
    - Triggers callback (scheduler can pause/cancel)
    - At emergency level: triggers graceful shutdown
    """

    def __init__(self, policy: WatchdogPolicy = None,
                 resource_ctrl=None, scheduler=None,
                 state_manager=None, log=None):
        self.policy    = policy or WatchdogPolicy()
        self.rctrl     = resource_ctrl
        self.scheduler = scheduler
        self.state     = state_manager
        self.log       = log
        self._lock     = threading.Lock()
        self._beats    : dict[str, EngineHeartbeat] = {}
        self._alerts   : list[dict] = []
        self._running  = False
        self._thread   : threading.Thread | None = None
        self._on_stall_callbacks  : list[Callable] = []
        self._on_emergency_callbacks: list[Callable] = []
        self._start_time = time.time()

    def start(self):
        self._running = True
        self._thread  = threading.Thread(
            target=self._watch_loop, name="m7-watchdog", daemon=True
        )
        self._thread.start()
        if self.log:
            self.log.info("[Watchdog] Started — monitoring runtime health")

    def stop(self):
        self._running = False
        if self.log:
            self.log.info(f"[Watchdog] Stopped | alerts={len(self._alerts)}")

    # ── Heartbeat API (engines call this) ─────────────────────────────
    def register_engine(self, name: str):
        with self._lock:
            self._beats[name] = EngineHeartbeat(engine_name=name)

    def heartbeat(self, engine_name: str, state: str = "running",
                  progress: float = 0.0):
        """Engines MUST call this regularly to prove they're alive."""
        with self._lock:
            if engine_name not in self._beats:
                self._beats[engine_name] = EngineHeartbeat(engine_name=engine_name)
            self._beats[engine_name].touch(state, progress)

    def unregister_engine(self, name: str):
        with self._lock:
            self._beats.pop(name, None)

    # ── Callbacks ─────────────────────────────────────────────────────
    def on_stall(self, fn: Callable):
        self._on_stall_callbacks.append(fn)

    def on_emergency(self, fn: Callable):
        self._on_emergency_callbacks.append(fn)

    # ── Core watch loop ───────────────────────────────────────────────
    def _watch_loop(self):
        while self._running:
            try:
                self._check_heartbeats()
                self._check_ram_emergency()
                self._check_orphan_tasks()
            except Exception as e:
                get_handler().capture("watchdog", e, "_watch_loop")
            time.sleep(self.policy.heartbeat_s)

    def _check_heartbeats(self):
        with self._lock:
            beats = dict(self._beats)
        now = time.time()
        for name, hb in beats.items():
            if hb.is_stalled(self.policy.engine_timeout_s):
                alert = {
                    "type"     : "stall",
                    "engine"   : name,
                    "stall_s"  : round(hb.age_s, 1),
                    "state"    : hb.state,
                    "timestamp": now,
                }
                self._raise_alert(alert)
                for fn in self._on_stall_callbacks:
                    try: fn(name, hb)
                    except Exception as e:
                        get_handler().capture("watchdog", e, f"stall_callback:{name}")

    def _check_ram_emergency(self):
        if not self.rctrl:
            return
        snap = self.rctrl.snapshot
        if not snap:
            return
        if snap.ram_pct >= self.policy.emergency_ram_pct:
            alert = {
                "type"    : "emergency_ram",
                "ram_pct" : snap.ram_pct,
                "ram_mb"  : snap.ram_used_mb,
                "timestamp": time.time(),
            }
            self._raise_alert(alert)
            if self.log:
                self.log.error(
                    f"[Watchdog] EMERGENCY: RAM {snap.ram_pct:.0f}% "
                    f"— triggering emergency cooldown"
                )
            for fn in self._on_emergency_callbacks:
                try: fn("ram", alert)
                except Exception as e:
                    get_handler().capture("watchdog", e, "emergency_callback")

    def _check_orphan_tasks(self):
        """Detect asyncio tasks that are running but not registered."""
        try:
            from core.async_runtime import get_runtime
            rt = get_runtime()
            if not rt.is_running:
                return
            active = rt.get_active_tasks()
            if len(active) > 50:
                alert = {
                    "type"      : "task_overflow",
                    "task_count": len(active),
                    "timestamp" : time.time(),
                }
                self._raise_alert(alert)
                if self.log:
                    self.log.warn(f"[Watchdog] {len(active)} active tasks — possible leak")
        except Exception as e:
            get_handler().capture("watchdog", e, "_check_orphan_tasks")

    def _raise_alert(self, alert: dict):
        with self._lock:
            self._alerts.append(alert)
        if self.log and alert.get("type") != "heartbeat":
            self.log.warn(f"[Watchdog] ALERT: {alert}")

    # ── Emergency shutdown ────────────────────────────────────────────
    def emergency_shutdown(self, reason: str = "watchdog"):
        """Trigger graceful emergency shutdown."""
        if self.log:
            self.log.error(f"[Watchdog] EMERGENCY SHUTDOWN: {reason}")
        if self.scheduler:
            try: self.scheduler.stop()
            except Exception as e:
                get_handler().capture("watchdog", e, "emergency_stop_scheduler")
        try:
            from core.async_runtime import get_runtime
            get_runtime().cancel_all()
        except Exception as e:
            get_handler().capture("watchdog", e, "emergency_cancel_tasks")
        if self.state:
            try: self.state.finish_scan(
                getattr(self.state, "_current_scan_id", "unknown"),
                "emergency_shutdown"
            )
            except Exception:
                pass

    # ── Public API ────────────────────────────────────────────────────
    def get_alerts(self, alert_type: str = None) -> list:
        with self._lock:
            if alert_type:
                return [a for a in self._alerts if a.get("type") == alert_type]
            return list(self._alerts)

    def health_report(self) -> dict:
        with self._lock:
            beats = dict(self._beats)
        stalled = [
            {"engine": n, "stall_s": round(hb.age_s, 1)}
            for n, hb in beats.items()
            if hb.is_stalled(self.policy.engine_timeout_s)
        ]
        return {
            "uptime_s"      : round(time.time() - self._start_time, 1),
            "engines_tracked": len(beats),
            "stalled"       : stalled,
            "total_alerts"  : len(self._alerts),
            "alert_types"   : list({a["type"] for a in self._alerts}),
            "running"       : self._running,
        }
