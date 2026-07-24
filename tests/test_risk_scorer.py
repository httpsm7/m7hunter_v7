#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confirm.risk_scorer import calculate_risk, get_severity

def test_lambda_critical(): assert calculate_risk("LAMBDA_RCE",0.95)["severity"]=="critical"
def test_k8s_high_or_crit(): assert calculate_risk("K8S_SECRET_LEAK",0.90)["severity"] in ("critical","high")
def test_2fa_high():        assert calculate_risk("2FA_BYPASS",0.85)["severity"] in ("critical","high")
def test_saml_critical():   assert calculate_risk("SAML_SIGNATURE_BYPASS",0.92)["severity"]=="critical"
def test_sqli_high_crit():  assert calculate_risk("SQLI",0.95)["severity"] in ("critical","high")
def test_ssrf_high_crit():  assert calculate_risk("SSRF",0.95)["severity"] in ("critical","high")
def test_unknown_ok():      r=calculate_risk("UNKNOWN_XYZ",0.8); assert "severity" in r
def test_score_range():     r=calculate_risk("XSS",0.8); assert 0<=r["risk_score"]<=100

if __name__=="__main__":
    tests=[v for k,v in globals().items() if k.startswith("test_")]
    passed=failed=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); passed+=1
        except AssertionError as e: print(f"  ✗ {t.__name__}: {e}"); failed+=1
    print(f"\n{passed} passed, {failed} failed")
