#!/usr/bin/env python3
# tests/test_edrp.py — EDRP Architecture Tests
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY
import sys, os, time, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── StateManager tests ────────────────────────────────────────────────
def test_state_create_scan():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"test.db"))
        sm.create_scan("sc001","example.com",{"deep":True})
        res = sm.find_resumable_scan("example.com")
        assert res is not None
        assert res["scan_id"] == "sc001"

def test_state_stage_lifecycle():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"test.db"))
        sm.create_scan("sc002","test.com")
        sm.stage_start("sc002","step01_subdomain")
        assert not sm.is_stage_done("sc002","step01_subdomain")
        sm.stage_done("sc002","step01_subdomain", findings_n=5)
        assert sm.is_stage_done("sc002","step01_subdomain")

def test_state_resume_pending():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"test.db"))
        sm.create_scan("sc003","resume.com")
        sm.stage_start("sc003","step01_subdomain")
        sm.stage_done("sc003","step01_subdomain")
        all_stages = ["step01_subdomain","step02_dns","step03_probe"]
        pending = sm.get_pending_stages("sc003", all_stages)
        assert "step01_subdomain" not in pending
        assert "step02_dns" in pending
        assert "step03_probe" in pending

def test_state_checkpoint():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"test.db"))
        sm.create_scan("sc004","chk.com")
        sm.save_checkpoint("sc004","mykey",{"done":True,"count":42})
        val = sm.load_checkpoint("sc004","mykey")
        assert val["count"] == 42

def test_state_persist_findings():
    from core.state_manager import StateManager
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(db_path=os.path.join(d,"test.db"))
        sm.create_scan("sc005","findings.com")
        findings = [
            {"vuln_type":"XSS","url":"https://x.com/a","severity":"high","confidence":0.92,"detail":"reflected"},
            {"vuln_type":"SQLI","url":"https://x.com/b","severity":"critical","confidence":0.98,"detail":"time-based"},
        ]
        sm.persist_findings_bulk("sc005", findings)
        stored = sm.get_findings("sc005")
        assert len(stored) == 2
        assert stored[0]["vuln_type"] in ("XSS","SQLI")

# ── EngineRegistry tests ──────────────────────────────────────────────
def test_registry_all_engines():
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    assert len(r.all()) >= 27

def test_registry_topological_order():
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    order = r.topological_order(["step01_subdomain","step02_dns","step03_probe"])
    # step02 must come after step01
    assert order.index("step01_subdomain") < order.index("step02_dns")
    # step03 must come after step02
    assert order.index("step02_dns") < order.index("step03_probe")

def test_registry_dep_graph():
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    graph = r.dependency_graph()
    assert "step01_subdomain" in graph
    assert "step02_dns" in graph
    assert "step01_subdomain" in graph["step02_dns"]

def test_registry_get_by_group():
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    recon = r.get_by_group("recon")
    assert any(e.name == "step01_subdomain" for e in recon)

def test_registry_lab_filter():
    from core.engine_registry import EngineRegistry
    r = EngineRegistry()
    no_lab = r.available_engines(lab=False)
    with_lab = r.available_engines(lab=True)
    assert len(with_lab) >= len(no_lab)

# ── ResourceController tests ──────────────────────────────────────────
def test_resource_snapshot():
    from core.resource_controller import ResourceController
    rc = ResourceController()
    snap = rc._take_snapshot()
    assert snap.ram_total_mb > 0
    assert 0 <= snap.ram_pct <= 100

def test_resource_can_start_minimal():
    from core.resource_controller import ResourceController
    rc = ResourceController()
    allowed, reason = rc.can_start("minimal")
    assert isinstance(allowed, bool)
    assert isinstance(reason, str)

def test_resource_register_cycle():
    from core.resource_controller import ResourceController
    rc = ResourceController()
    rc.register_start("step01_subdomain","low")
    with rc._lock:
        assert "low" in rc._active_costs
    rc.register_finish("step01_subdomain","low")
    with rc._lock:
        assert "low" not in rc._active_costs

def test_resource_single_active_heavy_policy():
    from core.resource_controller import ResourceController
    rc = ResourceController()
    rc.register_start("step06_nuclei","high")
    allowed, reason = rc.can_start("high")
    assert not allowed
    assert "single-active" in reason.lower() or "heavy stage" in reason.lower()
    rc.register_finish("step06_nuclei","high")
    allowed2, _ = rc.can_start("high")
    # After releasing, should be allowed (assuming RAM OK)
    assert isinstance(allowed2, bool)

def test_resource_concurrency_limit():
    from core.resource_controller import ResourceController
    rc = ResourceController()
    limit = rc.get_concurrency_limit(base=10)
    assert 1 <= limit <= 10

# ── Lifecycle state test ──────────────────────────────────────────────
def test_base_step_lifecycle_states():
    from core.base_step import LifecycleState
    states = [s.value for s in LifecycleState]
    for expected in ["idle","warming","running","cooling","sleeping","done","failed"]:
        assert expected in states

# ── AI Gate tests ─────────────────────────────────────────────────────
def test_ai_gate_skip_high_confidence():
    from ai.pipeline_controller import AIGate
    gate = AIGate()
    finding = {"vuln_type":"XSS","url":"https://x.com","confidence":0.97,"detail":"confirmed"}
    activate, reason = gate.should_activate(finding)
    assert not activate
    assert "already confirmed" in reason

def test_ai_gate_skip_low_confidence():
    from ai.pipeline_controller import AIGate
    gate = AIGate()
    finding = {"vuln_type":"XSS","url":"https://x.com","confidence":0.30,"detail":"noise"}
    activate, reason = gate.should_activate(finding)
    assert not activate
    assert "too low" in reason

def test_ai_gate_ambiguous_range():
    from ai.pipeline_controller import AIGate
    gate = AIGate()
    finding = {"vuln_type":"CORS","url":"https://x.com","confidence":0.65,"detail":"maybe"}
    # Should activate IF AI is available (won't error if not)
    activate, reason = gate.should_activate(finding)
    if not gate.is_available:
        assert not activate
    # Just check it returns correct types
    assert isinstance(activate, bool)
    assert isinstance(reason, str)

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t(); print(f"  ✓ {t.__name__}"); passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
