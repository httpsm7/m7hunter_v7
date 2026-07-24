#!/usr/bin/env python3
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_gauge_and_latest():
    from core.telemetry import Telemetry
    t = Telemetry()
    t.gauge("ram_pct", 65.0)
    assert t.latest("ram_pct") == 65.0

def test_increment_counter():
    from core.telemetry import Telemetry
    t = Telemetry()
    t.increment("findings_total", 5)
    t.increment("findings_total", 3)
    assert t.get_counter("findings_total") == 8

def test_span_tracing():
    from core.telemetry import Telemetry
    t = Telemetry()
    t.span_start("s1", "step01_subdomain")
    time.sleep(0.05)
    t.span_end("s1", "done")
    spans = t.get_spans(status="done")
    assert len(spans) == 1
    assert spans[0]["duration_s"] >= 0.04

def test_event_logging():
    from core.telemetry import Telemetry
    t = Telemetry()
    t.event("stage_start", {"stage":"step01"}, level="info")
    t.event("error_occurred", {"msg":"oops"}, level="error")
    errors = t.get_events(level="error")
    assert len(errors) == 1
    assert errors[0]["name"] == "error_occurred"

def test_memory_graph():
    from core.telemetry import Telemetry
    t = Telemetry()
    for v in [60.0, 65.0, 70.0]:
        t.gauge("ram_pct", v)
    graph = t.memory_graph(points=10)
    assert len(graph) == 3
    assert graph[-1][1] == 70.0

def test_summary_has_all_keys():
    from core.telemetry import Telemetry
    t = Telemetry()
    s = t.summary()
    for k in ("ram_pct_now","cpu_pct_now","active_tasks",
              "findings_total","ai_calls","errors"):
        assert k in s

def test_singleton():
    from core.telemetry import get_telemetry
    t1 = get_telemetry(); t2 = get_telemetry()
    assert t1 is t2

def test_avg_rolling():
    from core.telemetry import Telemetry
    t = Telemetry()
    for v in [50.0, 60.0, 70.0]:
        t.gauge("ram_pct", v)
    avg = t.avg("ram_pct", window_s=60)
    assert 50.0 <= avg <= 70.0

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
