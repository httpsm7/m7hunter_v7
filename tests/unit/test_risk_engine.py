#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from ai.risk_engine import RiskEngine

def test_mandatory_output_keys():
    re = RiskEngine()
    r  = re.evaluate({"vuln_type":"XSS","url":"https://x.com","confidence":0.90})
    for k in ("finding","confidence","severity","verification","recommendation"):
        assert k in r, f"Missing mandatory key: {k}"

def test_critical_rce():
    re = RiskEngine()
    r  = re.evaluate({"vuln_type":"RCE","url":"https://x.com","confidence":0.99,"detail":"exec"})
    assert r["severity"] == "critical"

def test_info_low_confidence():
    re = RiskEngine()
    r  = re.evaluate({"vuln_type":"INFO_LEAK","url":"https://x.com","confidence":0.30,"detail":"v"})
    assert r["severity"] in ("info","low")

def test_verification_confirmed():
    re = RiskEngine()
    r  = re.evaluate({"vuln_type":"SQLI","url":"https://x.com","confidence":0.95,"detail":"t"})
    assert r["verification"] == "double_verified"

def test_verification_potential():
    re = RiskEngine()
    r  = re.evaluate({"vuln_type":"CORS","url":"https://x.com","confidence":0.65,"detail":"c"})
    assert r["verification"] == "single_signal"

def test_deduplication():
    re = RiskEngine()
    f = [
        {"vuln_type":"XSS","url":"https://x.com/a","confidence":0.9},
        {"vuln_type":"XSS","url":"https://x.com/a","confidence":0.9},
        {"vuln_type":"SQLI","url":"https://x.com/b","confidence":0.95},
    ]
    unique = re.deduplicate(f)
    assert len(unique) == 2

def test_top_critical_sorted():
    re = RiskEngine()
    f  = [
        {"vuln_type":"INFO_LEAK","url":"https://x.com/1","confidence":0.5},
        {"vuln_type":"RCE","url":"https://x.com/2","confidence":0.99},
        {"vuln_type":"SQLI","url":"https://x.com/3","confidence":0.95},
    ]
    top = re.top_critical(f, n=2)
    assert len(top) <= 2
    if len(top) == 2:
        assert top[0]["cvss_estimate"] >= top[1]["cvss_estimate"]

def test_never_raises():
    re = RiskEngine()
    r  = re.evaluate({})  # empty finding
    assert "finding" in r  # always structured

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
