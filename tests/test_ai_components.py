#!/usr/bin/env python3
# tests/test_ai_components.py — Phase 5 AI + Phase 8 Evidence Tests
import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── PromptRouter ──────────────────────────────────────────────────────
def test_router_no_ai():
    from ai.prompt_router import PromptRouter
    r = PromptRouter(ai_client=None)
    result = r.summarize({"vuln_type":"XSS","url":"https://x.com","confidence":0.9,"detail":"reflected"})
    assert result.get("error") == "AI not available"

def test_router_extract_keys():
    from ai.prompt_router import PromptRouter
    keys = PromptRouter._extract_keys("Hello {name}, your {item} is ready.")
    assert "name" in keys and "item" in keys

def test_router_parse_json_valid():
    from ai.prompt_router import PromptRouter
    result = PromptRouter._parse_json('{"verdict": "confirmed", "confidence": 0.9}')
    assert result.get("verdict") == "confirmed"

def test_router_parse_code_block():
    from ai.prompt_router import PromptRouter
    raw = "```json\n" + '{"severity": "high"}' + "\n```"
    result = PromptRouter._parse_json(raw)
    assert result.get("severity") == "high"

def test_router_parse_embedded():
    from ai.prompt_router import PromptRouter
    raw = 'The result is: {"verdict": "false_positive"} based on analysis.'
    result = PromptRouter._parse_json(raw)
    assert result.get("verdict") == "false_positive"

def test_router_parse_invalid():
    from ai.prompt_router import PromptRouter
    result = PromptRouter._parse_json("not json at all")
    assert "error" in result

def test_router_temperature_map():
    from ai.prompt_router import PromptRouter
    r = PromptRouter()
    assert r.TEMPERATURE_MAP["risk_scorer"] == 0.0
    assert r.TEMPERATURE_MAP["verifier"] == 0.0
    assert r.TEMPERATURE_MAP["report_writer"] == 0.2

# ── RiskModel ─────────────────────────────────────────────────────────
def test_risk_critical_rce():
    from ai.risk_model import RiskModel
    m = RiskModel()
    rs = m.score({"vuln_type":"RCE","url":"https://x.com","confidence":0.99,"detail":"exec"})
    assert rs.severity == "critical"
    assert rs.cvss_estimate > 8.0

def test_risk_info_low():
    from ai.risk_model import RiskModel
    m = RiskModel()
    rs = m.score({"vuln_type":"INFO_LEAK","url":"https://x.com","confidence":0.5,"detail":"version"})
    assert rs.severity in ("info","low","medium")

def test_risk_confidence_grade_a_plus():
    from ai.risk_model import RiskModel
    m = RiskModel()
    rs = m.score({"vuln_type":"SQLI","url":"https://x.com","confidence":0.97,"detail":"time-based"})
    assert rs.confidence_grade in ("A+","A")

def test_risk_confidence_grade_f():
    from ai.risk_model import RiskModel
    m = RiskModel()
    rs = m.score({"vuln_type":"XSS","url":"https://x.com","confidence":0.15,"detail":"noise"})
    assert rs.confidence_grade == "F"

def test_risk_to_dict_keys():
    from ai.risk_model import RiskModel
    m = RiskModel()
    d = m.score({"vuln_type":"SSRF","url":"https://x.com","confidence":0.85,"detail":"aws"}).to_dict()
    for key in ("severity","cvss_estimate","business_impact","exploitability_ease","recommended_action"):
        assert key in d, f"Missing key: {key}"

def test_risk_top_findings_sorted():
    from ai.risk_model import RiskModel
    m = RiskModel()
    findings = [
        {"vuln_type":"XSS","url":"https://x.com/1","confidence":0.70,"detail":"x"},
        {"vuln_type":"RCE","url":"https://x.com/2","confidence":0.99,"detail":"x"},
        {"vuln_type":"INFO_LEAK","url":"https://x.com/3","confidence":0.40,"detail":"x"},
    ]
    top = m.top_findings(findings, n=2)
    assert len(top) == 2
    assert top[0].cvss_estimate >= top[1].cvss_estimate

def test_risk_all_severities_have_messages():
    from ai.risk_model import RiskModel
    m = RiskModel()
    for sev in ["critical","high","medium","low","info"]:
        assert sev in m.BUSINESS_IMPACT
        assert sev in m.ACTIONS
        assert sev in m.EASE_MAP

# ── EvidenceStore ─────────────────────────────────────────────────────
def test_evidence_store_basic():
    from reporting.evidence_store import EvidenceStore
    with tempfile.TemporaryDirectory() as d:
        es  = EvidenceStore(d, "sc001")
        eid = es.store(
            {"vuln_type":"XSS","url":"https://x.com","severity":"high","confidence":0.92,"detail":"ref"},
            request_raw="GET / HTTP/1.1\nHost: x.com",
            response_raw="<html>reflected</html>"
        )
        assert len(eid) == 12

def test_evidence_get_meta():
    from reporting.evidence_store import EvidenceStore
    with tempfile.TemporaryDirectory() as d:
        es  = EvidenceStore(d, "sc002")
        eid = es.store(
            {"vuln_type":"SQLI","url":"https://x.com","severity":"critical","confidence":0.97,"detail":"tb"},
            request_raw="POST /login HTTP/1.1"
        )
        meta = es.get(eid)
        assert meta["vuln_type"] == "SQLI"
        assert "request" in meta["files"]

def test_evidence_reproduction_steps():
    from reporting.evidence_store import EvidenceStore
    with tempfile.TemporaryDirectory() as d:
        es  = EvidenceStore(d, "sc003")
        eid = es.store({
            "vuln_type":"LFI","url":"https://x.com/?f=../../etc/passwd",
            "severity":"high","confidence":0.95,"detail":"passwd","payload":"../../etc/passwd"
        })
        steps = es.get(eid)["reproduction"]
        assert len(steps) >= 3

def test_evidence_summary_sorted():
    from reporting.evidence_store import EvidenceStore
    with tempfile.TemporaryDirectory() as d:
        es = EvidenceStore(d, "sc004")
        for vt,conf in [("XSS",0.90),("SQLI",0.98),("INFO_LEAK",0.45)]:
            es.store({"vuln_type":vt,"url":"https://x.com","severity":"high","confidence":conf,"detail":"x"})
        table = es.summary_table()
        assert len(table) == 3
        assert table[0]["confidence"] >= table[1]["confidence"]

def test_evidence_persistence():
    from reporting.evidence_store import EvidenceStore
    with tempfile.TemporaryDirectory() as d:
        eid = EvidenceStore(d,"sc005").store({
            "vuln_type":"CORS","url":"https://x.com","severity":"medium","confidence":0.75,"detail":"wildcard"
        })
        assert EvidenceStore(d,"sc005").get(eid)["vuln_type"] == "CORS"

def test_evidence_get_request_content():
    from reporting.evidence_store import EvidenceStore
    with tempfile.TemporaryDirectory() as d:
        es  = EvidenceStore(d, "sc006")
        eid = es.store(
            {"vuln_type":"XSS","url":"https://x.com","severity":"high","confidence":0.9,"detail":"x"},
            request_raw="GET /search?q=<script> HTTP/1.1\nHost: x.com"
        )
        req = es.get_request(eid)
        assert "GET" in req and "Host" in req

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t(); print(f"  ✓ {t.__name__}"); passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
