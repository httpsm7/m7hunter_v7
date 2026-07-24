#!/usr/bin/env python3
import sys, os, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_store_and_retrieve():
    from ai.memory_store import MemoryStore
    ms = MemoryStore(scan_id="test", persist=False)
    f  = {"vuln_type":"XSS","url":"https://x.com","confidence":0.9}
    ms.store_decision("verify", f, {"verdict":"confirmed","confidence":0.92})
    assert ms.has_decision(f)

def test_cache_hit():
    from ai.memory_store import MemoryStore
    ms = MemoryStore(scan_id="test", persist=False)
    f  = {"vuln_type":"SQLI","url":"https://x.com","confidence":0.95}
    ms.store_decision("score", f, {"verdict":"confirmed"})
    result = ms.get_decision(f)
    assert result is not None
    assert result["vuln_type"] == "SQLI"

def test_session_context():
    from ai.memory_store import MemoryStore
    ms = MemoryStore(persist=False)
    ms.store_context("waf_detected", "Cloudflare")
    assert ms.get_context("waf_detected") == "Cloudflare"
    assert ms.get_context("missing_key", "default") == "default"

def test_confirmed_findings_filter():
    from ai.memory_store import MemoryStore
    ms = MemoryStore(persist=False)
    ms.store_decision("verify",{"vuln_type":"XSS","url":"a"},{"verdict":"confirmed"})
    ms.store_decision("verify",{"vuln_type":"CORS","url":"b"},{"verdict":"false_positive"})
    ms.store_decision("verify",{"vuln_type":"LFI","url":"c"},{"verdict":"needs_review"})
    confirmed = ms.get_confirmed_findings()
    fp        = ms.get_false_positives()
    assert len(confirmed) == 1
    assert len(fp) == 1

def test_clear_session():
    from ai.memory_store import MemoryStore
    ms = MemoryStore(persist=False)
    ms.store_decision("verify",{"vuln_type":"XSS","url":"x"},{"verdict":"confirmed"})
    ms.clear_session()
    assert len(ms.get_all_decisions()) == 0

def test_summary_keys():
    from ai.memory_store import MemoryStore
    ms = MemoryStore(persist=False)
    s  = ms.summary()
    for k in ("total_decisions","confirmed","false_positives","needs_review"):
        assert k in s

def test_persistence():
    from ai.memory_store import MemoryStore, MEMORY_DIR
    with tempfile.TemporaryDirectory() as _d:
        import ai.memory_store as mm
        orig = mm.MEMORY_DIR
        mm.MEMORY_DIR = __import__('pathlib').Path(_d)
        mm.MEMORY_DIR.mkdir(exist_ok=True)
        f = {"vuln_type":"SSRF","url":"https://x.com","confidence":0.88}
        ms1 = MemoryStore(scan_id="persist_test", persist=True)
        ms1.store_decision("score", f, {"verdict":"confirmed"})
        ms2 = MemoryStore(scan_id="persist_test", persist=True)
        assert ms2.has_decision(f)
        mm.MEMORY_DIR = orig

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
