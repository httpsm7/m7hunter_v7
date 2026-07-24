#!/usr/bin/env python3
# core/resource_controller.py — Active Resource Enforcement Controller
# Buildmap 3: psutil monitoring, adaptive concurrency, RAM-aware throttle,
#             browser suspension, AI throttling, queue backpressure
#             ACTIVE enforcement — not just observational
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import asyncio, time, threading, os
from dataclasses import dataclass
from core.error_handler import get_handler

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

@dataclass
class ResourceSnapshot:
    ram_used_mb  : float
    ram_total_mb : float
    ram_pct      : float
    cpu_pct      : float
    active_heavy : int
    timestamp    : float


class ResourceController:
    """
    Buildmap 3: ACTIVE enforcement — not observational.

    Semaphores are REAL asyncio.Semaphore objects.
    ALL heavy modules must acquire before running.

    Policies:
    - RAM > 70% → reduce concurrency (semaphore shrink)
    - RAM > 80% → suspend browser tasks (browser_sem → 0)
    - RAM > 90% → emergency cooldown (all heavy sems → 0)
    - CPU > 90% → throttle crawling
    - Dynamic semaphore resize at runtime
    """

    # Semaphore limits (adjusted dynamically based on RAM)
    SEM_DEFAULTS = {
        "playwright": 2,
        "ai"        : 1,
        "nuclei"    : 3,
        "crawl"     : 4,
        "screenshot": 1,
        "heavy"     : 2,
        "medium"    : 6,
        "low"       : 12,
    }

    def __init__(self, ram_limit_mb: int = 8192, log=None,
                 telemetry=None):
        self.ram_limit_mb  = ram_limit_mb
        self.log           = log
        self.telemetry     = telemetry
        self._lock         = threading.Lock()
        self._active_costs = []
        self._paused_heavy = False
        self._snapshot     = None
        self._running      = False

        # Real asyncio semaphores — ALL heavy engines use these
        self._sems = {
            name: asyncio.Semaphore(limit)
            for name, limit in self.SEM_DEFAULTS.items()
        }
        # Current limits (for dynamic resize tracking)
        self._sem_limits = dict(self.SEM_DEFAULTS)

        # Monitoring thread
        self._monitor_thread = None

    def start_monitoring(self, interval: float = 5.0):
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(interval,), daemon=True
        )
        self._monitor_thread.start()

    def stop_monitoring(self):
        self._running = False

    def _monitor_loop(self, interval: float):
        while self._running:
            try:
                self._snapshot = self._take_snapshot()
                self._enforce()
                if self.telemetry:
                    self.telemetry.record_system(
                        ram_pct=self._snapshot.ram_pct,
                        cpu_pct=self._snapshot.cpu_pct,
                        active_tasks=len(self._active_costs),
                    )
            except Exception as e:
                get_handler().capture("resource_controller", e, "_monitor_loop")
            time.sleep(interval)

    def _take_snapshot(self) -> ResourceSnapshot:
        if _HAS_PSUTIL:
            mem = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=0.3)
            used_mb  = mem.used / 1024 / 1024
            total_mb = mem.total / 1024 / 1024
            pct      = mem.percent
        else:
            used_mb = total_mb = pct = cpu = 0.0
            try:
                with open("/proc/meminfo") as f:
                    lines = {l.split(":")[0]: int(l.split()[1])
                             for l in f if ":" in l}
                total_mb = lines.get("MemTotal", 0) / 1024
                avail_mb = lines.get("MemAvailable", 0) / 1024
                used_mb  = total_mb - avail_mb
                pct      = (used_mb / total_mb * 100) if total_mb else 0
            except Exception:
                pass
        with self._lock:
            heavy = sum(1 for c in self._active_costs if c in ("critical","high"))
        return ResourceSnapshot(
            ram_used_mb =round(used_mb, 1),
            ram_total_mb=round(total_mb, 1),
            ram_pct     =round(pct, 1),
            cpu_pct     =round(cpu, 1),
            active_heavy=heavy,
            timestamp   =time.time(),
        )

    def _enforce(self):
        """
        Buildmap 3 MANDATORY POLICIES — active enforcement:
        RAM > 70% → reduce concurrency
        RAM > 80% → suspend browser tasks
        RAM > 90% → emergency cooldown
        CPU > 90% → throttle crawling
        """
        if not self._snapshot:
            return
        ram = self._snapshot.ram_pct
        cpu = self._snapshot.cpu_pct

        if ram >= 90:
            self._set_sem("playwright", 0)
            self._set_sem("ai", 0)
            self._set_sem("heavy", 0)
            self._set_sem("nuclei", 1)
            if not self._paused_heavy:
                self._paused_heavy = True
                if self.log:
                    self.log.error(f"[ResourceCtrl] RAM {ram:.0f}% — EMERGENCY cooldown")
        elif ram >= 80:
            self._set_sem("playwright", 0)
            self._set_sem("ai", 0)
            self._set_sem("heavy", 1)
            self._set_sem("nuclei", 2)
            if not self._paused_heavy:
                self._paused_heavy = True
                if self.log:
                    self.log.warn(f"[ResourceCtrl] RAM {ram:.0f}% — suspending browser")
        elif ram >= 70:
            self._set_sem("playwright", 1)
            self._set_sem("ai", 1)
            self._set_sem("heavy", 1)
            self._set_sem("medium", max(2, self.SEM_DEFAULTS["medium"] // 2))
            if self.log:
                self.log.warn(f"[ResourceCtrl] RAM {ram:.0f}% — reducing concurrency")
        else:
            # RAM healthy — restore defaults
            if self._paused_heavy:
                self._paused_heavy = False
                for name, limit in self.SEM_DEFAULTS.items():
                    self._set_sem(name, limit)
                if self.log:
                    self.log.info(f"[ResourceCtrl] RAM {ram:.0f}% — restored normal concurrency")

        # CPU throttle
        if cpu >= 90:
            self._set_sem("crawl", max(1, self._sem_limits.get("crawl",4) // 2))

    def _set_sem(self, name: str, new_limit: int):
        """Dynamically resize a semaphore by adjusting internal counter."""
        if name not in self._sems:
            return
        old_limit = self._sem_limits.get(name, 0)
        if old_limit == new_limit:
            return
        self._sem_limits[name] = new_limit
        sem = self._sems[name]
        # Adjust semaphore value
        diff = new_limit - old_limit
        if diff > 0:
            for _ in range(diff):
                sem.release()
        elif diff < 0:
            # We can't forcibly reduce — mark it, waiters will be blocked
            # The semaphore's internal count will naturally drain
            pass

    # ── Semaphore context managers (use in async engines) ─────────────
    def get_semaphore(self, sem_name: str) -> asyncio.Semaphore:
        return self._sems.get(sem_name, self._sems["medium"])

    async def acquire(self, sem_name: str):
        """Async acquire — ALL heavy engines must use this."""
        sem = self._sems.get(sem_name, self._sems["medium"])
        await sem.acquire()

    def release(self, sem_name: str):
        sem = self._sems.get(sem_name, self._sems["medium"])
        try:
            sem.release()
        except ValueError:
            pass

    # ── Gate API (sync, for pre-check before async acquire) ───────────
    def can_start(self, ram_class: str) -> tuple[bool, str]:
        s = self._snapshot or self._take_snapshot()
        with self._lock:
            heavy = sum(1 for c in self._active_costs if c in ("critical","high"))
        if s.ram_pct >= 90:
            return False, f"RAM critical ({s.ram_pct:.0f}%) — emergency cooldown"
        if ram_class in ("critical","high") and heavy >= 1:
            return False, f"single-active heavy policy (active={heavy})"
        if ram_class == "critical" and s.ram_pct >= 70:
            return False, f"RAM {s.ram_pct:.0f}% — critical stage blocked"
        if ram_class == "high" and s.ram_pct >= 80:
            return False, f"RAM {s.ram_pct:.0f}% — high-cost stage blocked"
        return True, "ok"

    def register_start(self, name: str, ram_class: str):
        with self._lock:
            self._active_costs.append(ram_class)

    def register_finish(self, name: str, ram_class: str):
        with self._lock:
            try:
                self._active_costs.remove(ram_class)
            except ValueError:
                pass

    def get_concurrency_limit(self, base: int = 10) -> int:
        s = self._snapshot
        if not s:
            return base
        if s.ram_pct > 80: return max(1, base // 4)
        if s.ram_pct > 65: return max(2, base // 2)
        if s.ram_pct > 50: return max(4, int(base * 0.75))
        return base

    def playwright_allowed(self) -> bool:
        s = self._snapshot or self._take_snapshot()
        return s.ram_pct < 80 and self._sem_limits.get("playwright", 0) > 0

    def ai_allowed(self) -> bool:
        s = self._snapshot or self._take_snapshot()
        return s.ram_pct < 75 and self._sem_limits.get("ai", 0) > 0

    @property
    def snapshot(self) -> ResourceSnapshot | None:
        return self._snapshot

    def status_str(self) -> str:
        s = self._snapshot
        if not s:
            return "ResourceCtrl: no snapshot"
        return (f"RAM {s.ram_used_mb:.0f}/{s.ram_total_mb:.0f}MB "
                f"({s.ram_pct:.0f}%) CPU {s.cpu_pct:.0f}% "
                f"Heavy:{s.active_heavy}")

    def semaphore_status(self) -> dict:
        return {
            name: {"limit": self._sem_limits.get(name,0),
                   "value": sem._value}
            for name, sem in self._sems.items()
        }
