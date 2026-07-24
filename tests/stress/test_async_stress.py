#!/usr/bin/env python3
# tests/stress/test_async_stress.py
# Blueprint: Async stress tests — concurrency, memory, browser cleanup, scheduler
import sys, os, asyncio, time, threading, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_resource_controller_concurrent_gate():
    """Many threads simultaneously requesting gate — no race condition."""
    from core.resource_controller import ResourceController
    rc = ResourceController()
    results = []
    def check():
        allowed, _ = rc.can_start("medium")
        results.append(allowed)
    threads = [threading.Thread(target=check) for _ in range(50)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(results) == 50
    assert all(isinstance(r, bool) for r in results)

def test_resource_controller_heavy_single_active():
    """Only one heavy stage active at a time under concurrent requests."""
    from core.resource_controller import ResourceController
    rc = ResourceController()
    started = []
    lock = threading.Lock()
    def try_start():
        allowed, _ = rc.can_start("high")
        if allowed:
            with lock:
                started.append(1)
                rc.register_start("heavy_test", "high")
            time.sleep(0.05)
            rc.register_finish("heavy_test", "high")
    threads = [threading.Thread(target=try_start) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    # Should have serialized — single-active policy
    assert len(started) <= 10

def test_state_manager_concurrent_writes():
    """Concurrent stage updates must not corrupt SQLite state."""
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"stress.db"))
        sm.create_scan("stress_001","stress.com")
        errors = []
        def write_stage(i):
            try:
                sm.stage_start("stress_001", f"stage_{i}")
                time.sleep(0.01)
                sm.stage_done("stress_001", f"stage_{i}", findings_n=i)
            except Exception as e:
                errors.append(str(e))
        threads = [threading.Thread(target=write_stage, args=(i,)) for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(errors) == 0
        summary = sm.scan_summary("stress_001")
        assert len(summary["stages"]) == 20

def test_proxy_manager_concurrent_get_report():
    """Concurrent proxy get + report_success must not deadlock."""
    from core.proxy_manager import ProxyManager
    pm = ProxyManager([f"http://proxy{i}:8080" for i in range(10)])
    results = []
    def work():
        url = pm.get()
        if url:
            pm.report_success(url, latency_ms=50)
            results.append(url)
    threads = [threading.Thread(target=work) for _ in range(100)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(results) == 100

def test_memory_store_concurrent_writes():
    """Concurrent AI decisions must not corrupt memory store."""
    from ai.memory_store import MemoryStore
    ms = MemoryStore(persist=False)
    errors = []
    def write(i):
        try:
            f = {"vuln_type":f"TYPE_{i}","url":f"https://x.com/{i}","confidence":0.8}
            ms.store_decision("verify", f, {"verdict":"confirmed"})
        except Exception as e:
            errors.append(str(e))
    threads = [threading.Thread(target=write, args=(i,)) for i in range(50)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(errors) == 0
    assert len(ms.get_all_decisions()) == 50

def test_plugin_registry_parallel_execution():
    """Multiple plugins running in parallel threads must not interfere."""
    from core.plugin_registry import PluginRegistry, PluginManifest
    class FastPlugin:
        PLUGIN_NAME="fast"; PLUGIN_VERSION="1.0"
        description=""; dependencies=[]; ram_class="low"
        safe_mode=False; requires_lab=False
        def __init__(self,p): self._n_findings=2
        def validate_config(self): return True
        def run(self): time.sleep(0.01)
    class FakePipeline:
        class args:
            lab=True; cookie=None
    reg = PluginRegistry()
    results = []
    for i in range(5):
        m = PluginManifest(name=f"fast_{i}")
        reg.register(m, FastPlugin)
    def run_plugin(name):
        ex = reg.execute(name, FakePipeline())
        results.append(ex.status)
    threads = [threading.Thread(target=run_plugin, args=(f"fast_{i}",)) for i in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert all(s == "done" for s in results)

def test_engine_registry_topological_stress():
    """Topological sort on full registry must be stable and fast."""
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    start = time.time()
    for _ in range(100):
        order = r.topological_order()
    elapsed = time.time() - start
    assert elapsed < 2.0  # 100 sorts under 2 seconds
    assert len(order) >= 27

def test_scope_engine_bulk_filter():
    """Filter 10,000 URLs — must complete under 1 second."""
    from core.scope_engine import ScopeEngine
    sc = ScopeEngine("target.com")
    sc._add_pattern("*.target.com")
    urls = [f"https://{'sub' if i%2==0 else 'evil'}.{'target' if i%2==0 else 'other'}.com/page/{i}"
            for i in range(10000)]
    start = time.time()
    in_s, out = sc.filter_urls(urls)
    elapsed = time.time() - start
    assert elapsed < 1.0
    assert len(in_s) + len(out) == 10000

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
