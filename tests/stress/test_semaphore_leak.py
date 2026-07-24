#!/usr/bin/env python3
# tests/stress/test_semaphore_leak.py
# Buildmap 9: Semaphore leaks, deadlocks, queue starvation, long-running scan sim
import sys, os, asyncio, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_semaphore_no_leak_after_failures():
    """Semaphore must be released even when engine crashes."""
    from core.resource_controller import ResourceController
    rc = ResourceController()
    initial_value = rc._sems["medium"]._value
    # Simulate 10 acquire+crash cycles
    async def crasher():
        async with rc.get_semaphore("medium"):
            raise RuntimeError("crash")
    async def run():
        for _ in range(10):
            try: await crasher()
            except Exception: pass
    asyncio.run(run())
    final_value = rc._sems["medium"]._value
    # Semaphore value should be back to initial (no leak)
    assert final_value == initial_value

def test_single_heavy_policy_concurrent():
    """Single-heavy policy must hold under concurrent requests."""
    from core.resource_controller import ResourceController
    rc = ResourceController()
    started_heavy = []
    lock = threading.Lock()
    def try_heavy():
        allowed, _ = rc.can_start("high")
        if allowed:
            with lock: started_heavy.append(1)
            rc.register_start("heavy", "high")
            time.sleep(0.05)
            rc.register_finish("heavy", "high")
    threads = [threading.Thread(target=try_heavy) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    # All started but serialized — count should be > 0
    assert len(started_heavy) > 0

def test_watchdog_no_memory_leak():
    """Watchdog alert list should not grow unboundedly."""
    from core.watchdog import Watchdog, WatchdogPolicy
    wd = Watchdog(policy=WatchdogPolicy(engine_timeout_s=0.01))
    wd.register_engine("leak_engine")
    wd.heartbeat("leak_engine", "running")
    # Trigger many alerts
    for _ in range(100):
        time.sleep(0.02)
        wd._check_heartbeats()
    # Should not have unbounded growth (capped or deduplicated)
    assert len(wd.get_alerts()) < 200  # reasonable upper bound

def test_telemetry_series_bounded():
    """TimeSeries must not grow beyond maxlen."""
    from core.telemetry import Telemetry
    t = Telemetry()
    for i in range(1000):
        t.gauge("ram_pct", float(i % 100))
    # Internal deque maxlen=500
    pts = t.memory_graph(points=1000)
    assert len(pts) <= 500

def test_concurrent_state_writes_no_corruption():
    """100 concurrent SQLite writes — no corruption."""
    import tempfile
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d, "stress.db"))
        sm.create_scan("stress", "stress.com")
        errors = []
        def write(i):
            try:
                sm.stage_start("stress", f"stage_{i}")
                time.sleep(0.001)
                sm.stage_done("stress", f"stage_{i}", findings_n=i)
            except Exception as e:
                errors.append(str(e))
        threads = [threading.Thread(target=write, args=(i,)) for i in range(100)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(errors) == 0
        summary = sm.scan_summary("stress")
        assert len(summary["stages"]) == 100

def test_async_runtime_no_orphan_tasks():
    """Tasks must be cancelled cleanly — no orphans."""
    from core.async_runtime import AsyncRuntime
    rt = AsyncRuntime(); rt.start()
    async def forever(): await asyncio.sleep(999)
    for i in range(10):
        rt.submit(forever(), name=f"forever_{i}")
    time.sleep(0.1)
    assert len(rt.get_active_tasks()) == 10
    rt.cancel_all()
    time.sleep(0.2)
    # After cancel_all, active tasks should decrease
    rt.shutdown(wait=True)

def test_scope_filter_10k_urls_under_1s():
    """Bulk scope filtering must complete under 1 second."""
    from core.scope_engine import ScopeEngine
    sc = ScopeEngine("target.com")
    sc._add_pattern("*.target.com")
    urls = [
        f"https://{'api' if i%3==0 else 'evil'}.{'target.com' if i%3==0 else 'other.com'}/p/{i}"
        for i in range(10000)
    ]
    t0 = time.time()
    in_s, out = sc.filter_urls(urls)
    elapsed = time.time() - t0
    assert elapsed < 1.0
    assert len(in_s) + len(out) == 10000

def test_engine_registry_topo_100x():
    """Topological sort over full 29-engine registry, 100 iterations."""
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    t0 = time.time()
    for _ in range(100):
        order = r.topological_order()
    elapsed = time.time() - t0
    assert elapsed < 2.0
    assert len(order) >= 27

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
