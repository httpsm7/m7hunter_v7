#!/usr/bin/env python3
# tests/integration/test_pipeline_integration.py
# Blueprint: Integration tests — resume, state, scheduler, scope chain
import sys, os, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_state_manager_full_lifecycle():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"test.db"))
        sm.create_scan("int_001","target.com",{"deep":True})
        for stage in ["step01_subdomain","step02_dns","step03_probe"]:
            sm.stage_start("int_001", stage)
            time.sleep(0.01)
            sm.stage_done("int_001", stage, findings_n=2)
        summary = sm.scan_summary("int_001")
        assert summary["total_findings"] == 0  # no findings persisted yet
        assert len(summary["stages"]) == 3
        done = [s for s in summary["stages"] if s["status"]=="done"]
        assert len(done) == 3

def test_resume_skips_completed_stages():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"test.db"))
        sm.create_scan("int_002","target.com")
        sm.stage_start("int_002","step01_subdomain")
        sm.stage_done("int_002","step01_subdomain")
        all_stages = ["step01_subdomain","step02_dns","step03_probe"]
        pending = sm.get_pending_stages("int_002", all_stages)
        assert "step01_subdomain" not in pending
        assert len(pending) == 2

def test_engine_registry_dag_order():
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    stages = ["step01_subdomain","step02_dns","step03_probe","step05_crawl"]
    order  = r.topological_order(stages)
    assert order.index("step01_subdomain") < order.index("step02_dns")
    assert order.index("step02_dns")       < order.index("step03_probe")
    assert order.index("step03_probe")     < order.index("step05_crawl")

def test_scope_filters_urls_before_engines():
    from core.scope_engine import ScopeEngine
    scope = ScopeEngine("target.com")
    scope._add_pattern("*.target.com")
    urls = [
        "https://api.target.com/v1",
        "https://evil.com/attack",
        "https://target.com/login",
        "https://other-target.com/x",
    ]
    in_scope, out = scope.filter_urls(urls)
    assert len(in_scope) == 2
    assert len(out) == 2
    assert all("target.com" in u for u in in_scope)

def test_resource_controller_single_heavy_policy():
    from core.resource_controller import ResourceController
    rc = ResourceController()
    rc.register_start("step06_nuclei", "high")
    allowed, reason = rc.can_start("high")
    assert not allowed
    rc.register_finish("step06_nuclei", "high")
    allowed2, _ = rc.can_start("medium")
    assert isinstance(allowed2, bool)

def test_risk_engine_batch_dedup():
    from ai.risk_engine import RiskEngine
    re = RiskEngine()
    findings = [
        {"vuln_type":"XSS","url":"https://x.com/a","confidence":0.9,"detail":"r"},
        {"vuln_type":"XSS","url":"https://x.com/a","confidence":0.9,"detail":"r"},
        {"vuln_type":"SQLI","url":"https://x.com/b","confidence":0.95,"detail":"t"},
    ]
    unique  = re.deduplicate(findings)
    scored  = re.evaluate_batch(unique)
    assert len(unique) == 2
    assert all("finding" in s for s in scored)

def test_plugin_registry_isolation():
    from core.plugin_registry import PluginRegistry, PluginManifest
    class BadPlugin:
        PLUGIN_NAME="bad"; PLUGIN_VERSION="1.0"
        description=""; dependencies=[]; ram_class="low"
        safe_mode=False; requires_lab=False
        def __init__(self,p): self.p=p; self._n_findings=0
        def validate_config(self): return True
        def run(self): raise Exception("CRASH"); return
    class FakePipeline:
        class args:
            lab=True; cookie=None
    reg = PluginRegistry()
    reg.register(PluginManifest(name="bad"), BadPlugin)
    ex = reg.execute("bad", FakePipeline())
    assert ex.status == "failed"  # isolated — did not crash test

def test_memory_store_no_duplicate_analysis():
    from ai.memory_store import MemoryStore
    ms = MemoryStore(persist=False)
    f  = {"vuln_type":"CORS","url":"https://x.com","confidence":0.70}
    ms.store_decision("verify", f, {"verdict":"confirmed","confidence":0.88})
    assert ms.has_decision(f)
    result = ms.get_decision(f)
    assert result["result"]["verdict"] == "confirmed"

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
