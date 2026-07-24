#!/usr/bin/env python3
# tests/unit/test_proxy_manager.py
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from core.proxy_manager import ProxyManager, ProxyRecord

def test_no_proxies_returns_direct():
    pm = ProxyManager()
    assert pm.get() is None

def test_add_and_get():
    pm = ProxyManager(["http://proxy1:8080", "http://proxy2:8080"])
    url = pm.get()
    assert url in ("http://proxy1:8080", "http://proxy2:8080")

def test_report_success_increases_score():
    pm = ProxyManager(["http://p1:8080"])
    pm.report_success("http://p1:8080", latency_ms=100)
    r = pm._proxies["http://p1:8080"]
    assert r.successes == 1

def test_report_failure_sets_cooldown():
    pm = ProxyManager(["http://p1:8080"])
    pm.report_failure("http://p1:8080")
    r = pm._proxies["http://p1:8080"]
    assert r.banned_until > time.time()
    assert pm.get() is None

def test_proxy_score_calculation():
    p = ProxyRecord(url="http://x:8080")
    p.successes = 8; p.failures = 2; p.latency_ms = 100
    assert 0.0 <= p.score <= 1.0

def test_rotate_all_clears_bans():
    pm = ProxyManager(["http://p1:8080"])
    pm.report_failure("http://p1:8080", hard_fail=True)
    assert pm.get() is None
    pm.rotate_all()
    assert pm.get() is not None

def test_status_dict():
    pm = ProxyManager(["http://p1:8080","http://p2:8080"])
    s = pm.status()
    assert s["total"] == 2 and s["available"] == 2

def test_geo_filter():
    pm = ProxyManager()
    pm.add_proxy("http://us:8080", geo="US")
    pm.add_proxy("http://de:8080", geo="DE")
    url = pm.get(geo="US")
    assert url == "http://us:8080"

def test_httpx_proxy_format():
    pm = ProxyManager(["http://p1:8080"])
    fmt = pm.get_httpx_proxy()
    assert fmt is not None
    assert "http://" in fmt and "https://" in fmt

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); passed += 1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
