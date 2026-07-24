#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confirm.confidence import ConfidenceEngine, score_confidence

def test_ssrf(): r=score_confidence("SSRF",response="ami-id: i-12345"); assert r["score"]>=0.90
def test_xss_fp(): r=score_confidence("XSS",response="&lt;script&gt;alert(1)"); assert r["score"]<0.5
def test_sqli(): r=score_confidence("SQLI",response="SQL syntax error near"); assert r["score"]>=0.88
def test_jwt(): r=score_confidence("JWT_FORGERY",response='{"role":"admin"}'); assert r["score"]>=0.85
def test_2fa(): r=score_confidence("2FA_BYPASS",response='{"success":true}'); assert r["score"]>=0.75
def test_k8s(): r=score_confidence("K8S_SECRET_LEAK",response="kind: Secret"); assert r["score"]>=0.95
def test_oob(): r=ConfidenceEngine().score("BLIND_XSS",oob_hit=True); assert r["score"]==0.99
def test_lambda(): r=score_confidence("LAMBDA_RCE",response="uid=0(root) gid=0(root)"); assert r["score"]>=0.98
def test_lfi(): r=score_confidence("LFI",response="root:x:0:0:root:/root:/bin/bash"); assert r["score"]>=0.95
def test_ssti(): r=score_confidence("SSTI",response="Output: 49"); assert r["score"]>=0.75

if __name__=="__main__":
    tests=[v for k,v in globals().items() if k.startswith("test_")]
    passed=failed=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); passed+=1
        except AssertionError as e: print(f"  ✗ {t.__name__}: {e}"); failed+=1
    print(f"\n{passed} passed, {failed} failed")
