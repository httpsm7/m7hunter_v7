#!/usr/bin/env python3
# tests/test_scope_browser.py
import sys, os, tempfile, pathlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_primary_in_scope():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    assert s.is_in_scope("https://example.com/path")

def test_wildcard_subdomain():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    s._add_pattern("*.example.com")
    assert s.is_in_scope("api.example.com")
    assert s.is_in_scope("staging.example.com")

def test_other_domain_out():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    assert not s.is_in_scope("evil.com")
    assert not s.is_in_scope("https://attacker.com/")

def test_exclusion_rule():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    s._add_pattern("*.example.com")
    s._add_exclusion("staging.example.com")
    assert s.is_in_scope("api.example.com")
    assert not s.is_in_scope("staging.example.com")

def test_filter_urls():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    s._add_pattern("*.example.com")
    urls = ["https://example.com/login","https://evil.com/x",
            "https://api.example.com/v1","https://other.org/page"]
    in_s, out_s = s.filter_urls(urls)
    assert len(in_s) == 2 and len(out_s) == 2

def test_filter_file():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("https://example.com/a\nhttps://evil.com/b\nhttps://example.com/c\n")
        fname = f.name
    removed = s.filter_file(fname)
    assert removed == 1
    lines = [l for l in open(fname).read().strip().split("\n") if l]
    assert len(lines) == 2
    os.unlink(fname)

def test_extract_host():
    from core.scope_engine import ScopeEngine
    assert ScopeEngine._extract_host("https://example.com/path") == "example.com"
    assert ScopeEngine._extract_host("sub.example.com:8080") == "sub.example.com"

def test_assert_raises():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    raised = False
    try:
        s.assert_in_scope("https://evil.com/attack")
    except ValueError as e:
        raised = True
        assert "OUT OF SCOPE" in str(e)
    assert raised

def test_scope_summary():
    from core.scope_engine import ScopeEngine
    s = ScopeEngine("example.com")
    s._add_pattern("*.example.com")
    s._add_exclusion("staging.example.com")
    assert "include" in s.summary() and "exclude" in s.summary()

def test_pool_status():
    from core.browser_pool import BrowserPool
    p = BrowserPool(max_size=2)
    st = p.status
    assert st["max_size"] == 2 and st["in_use"] == 0

def test_pool_ram_gate():
    from core.resource_controller import ResourceController
    from core.browser_pool import BrowserPool
    rc = ResourceController()
    p  = BrowserPool(max_size=3, resource_ctrl=rc)
    assert p._pool_limit() >= 1

def test_pool_singleton():
    from core.browser_pool import get_browser_pool
    p1 = get_browser_pool(max_size=2)
    p2 = get_browser_pool(max_size=2)
    assert p1 is p2

def test_scope_dag_unaffected():
    from core.engine_registry import EngineRegistry
    from core.scope_engine    import ScopeEngine
    r = EngineRegistry()
    s = ScopeEngine("target.com")
    order = r.topological_order(["step01_subdomain","step02_dns"])
    assert order.index("step01_subdomain") < order.index("step02_dns")

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t(); print(f"  ✓ {t.__name__}"); passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
