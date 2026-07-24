#!/usr/bin/env python3
# core/telemetry.py — Runtime Telemetry, Metrics, Task Tracing
# Buildmap 8: Runtime telemetry, queue metrics, engine metrics, memory graphs
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import time, threading, json, collections
from dataclasses import dataclass, field
from typing import Any
from core.error_handler import get_handler


@dataclass
class MetricPoint:
    name      : str
    value     : float
    tags      : dict  = field(default_factory=dict)
    timestamp : float = field(default_factory=time.time)


class TimeSeries:
    """Rolling window time series — max N points."""
    def __init__(self, maxlen: int = 300):
        self._data = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, value: float, ts: float = None):
        with self._lock:
            self._data.append((ts or time.time(), value))

    def latest(self) -> float | None:
        with self._lock:
            return self._data[-1][1] if self._data else None

    def avg(self, window_s: float = 60) -> float:
        now = time.time()
        with self._lock:
            pts = [v for t, v in self._data if now - t <= window_s]
        return sum(pts) / len(pts) if pts else 0.0

    def all_points(self) -> list:
        with self._lock:
            return list(self._data)


class Telemetry:
    """
    Buildmap 8: Runtime telemetry and observability.

    Tracks:
    - RAM usage over time (memory graph)
    - CPU usage over time
    - Queue depth per engine
    - Active task count
    - Engine duration per stage
    - Findings rate
    - Retry counts
    - Browser context count
    - AI call count + token usage

    All data in-memory, structured for dashboard and report export.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._series  : dict[str, TimeSeries] = {}
        self._counters: dict[str, int]        = {}
        self._spans   : dict[str, dict]       = {}   # task trace spans
        self._events  : list[dict]            = []

        # Pre-create key series
        for name in ["ram_pct","cpu_pct","active_tasks","queue_depth",
                     "findings_total","ai_calls","browser_contexts",
                     "retries","errors"]:
            self._series[name] = TimeSeries(maxlen=500)

    # ── Metric recording ──────────────────────────────────────────────
    def gauge(self, name: str, value: float, tags: dict = None):
        """Record a gauge metric (instantaneous value)."""
        if name not in self._series:
            self._series[name] = TimeSeries()
        self._series[name].record(value)

    def increment(self, name: str, amount: int = 1):
        """Increment a counter."""
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def get_counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def latest(self, metric: str) -> float | None:
        s = self._series.get(metric)
        return s.latest() if s else None

    def avg(self, metric: str, window_s: float = 60) -> float:
        s = self._series.get(metric)
        return s.avg(window_s) if s else 0.0

    # ── Task span tracing ─────────────────────────────────────────────
    def span_start(self, span_id: str, name: str, tags: dict = None):
        """Start a trace span for a task/engine."""
        with self._lock:
            self._spans[span_id] = {
                "name"      : name,
                "start"     : time.time(),
                "end"       : None,
                "duration_s": None,
                "status"    : "running",
                "tags"      : tags or {},
            }

    def span_end(self, span_id: str, status: str = "done"):
        """End a trace span."""
        with self._lock:
            if span_id in self._spans:
                s = self._spans[span_id]
                s["end"]       = time.time()
                s["duration_s"]= round(s["end"] - s["start"], 2)
                s["status"]    = status

    def get_spans(self, status: str = None) -> list:
        with self._lock:
            spans = list(self._spans.values())
        if status:
            spans = [s for s in spans if s["status"] == status]
        return sorted(spans, key=lambda s: s["start"], reverse=True)

    # ── Event log ─────────────────────────────────────────────────────
    def event(self, name: str, data: dict = None, level: str = "info"):
        """Record a structured event."""
        with self._lock:
            self._events.append({
                "ts"   : time.time(),
                "name" : name,
                "level": level,
                "data" : data or {},
            })
            if len(self._events) > 2000:
                self._events = self._events[-1000:]

    def get_events(self, name: str = None, level: str = None,
                   last_n: int = 100) -> list:
        with self._lock:
            evts = list(self._events)
        if name  : evts = [e for e in evts if e["name"] == name]
        if level : evts = [e for e in evts if e["level"] == level]
        return evts[-last_n:]

    # ── Resource snapshot integration ─────────────────────────────────
    def record_system(self, ram_pct: float, cpu_pct: float,
                      active_tasks: int = 0, browser_contexts: int = 0):
        """Call every N seconds from ResourceController monitoring loop."""
        self.gauge("ram_pct",          ram_pct)
        self.gauge("cpu_pct",          cpu_pct)
        self.gauge("active_tasks",     active_tasks)
        self.gauge("browser_contexts", browser_contexts)

    # ── Dashboard summary ─────────────────────────────────────────────
    def summary(self) -> dict:
        return {
            "ram_pct_now"   : self.latest("ram_pct"),
            "ram_pct_avg60" : self.avg("ram_pct", 60),
            "cpu_pct_now"   : self.latest("cpu_pct"),
            "cpu_pct_avg60" : self.avg("cpu_pct", 60),
            "active_tasks"  : self.latest("active_tasks"),
            "findings_total": self.get_counter("findings_total"),
            "ai_calls"      : self.get_counter("ai_calls"),
            "retries"       : self.get_counter("retries"),
            "errors"        : self.get_counter("errors"),
            "spans_running" : len(self.get_spans(status="running")),
            "spans_done"    : len(self.get_spans(status="done")),
            "recent_errors" : self.get_events(level="error", last_n=5),
        }

    def memory_graph(self, points: int = 60) -> list[tuple]:
        """Return last N RAM data points as [(ts, ram_pct)]."""
        s = self._series.get("ram_pct")
        if not s:
            return []
        return s.all_points()[-points:]

    def export_json(self) -> str:
        return json.dumps(self.summary(), indent=2, default=str)


# Module-level singleton
_telemetry: Telemetry | None = None

def get_telemetry() -> Telemetry:
    global _telemetry
    if _telemetry is None:
        _telemetry = Telemetry()
    return _telemetry
