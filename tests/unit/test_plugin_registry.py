#!/usr/bin/env python3
# tests/unit/test_plugin_registry.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from core.plugin_registry import PluginRegistry, PluginManifest

class MockPlugin:
    PLUGIN_NAME = "mock_plugin"; PLUGIN_VERSION = "1.0"
    description = "test"; dependencies = []; ram_class = "low"
    safe_mode = False; requires_lab = False
    def __init__(self, p): self.p = p; self._n_findings = 0
    def validate_config(self): return True
    def prepare(self): pass
    def run(self): self._n_findings = 3

class CrashPlugin:
    PLUGIN_NAME = "crash_plugin"; PLUGIN_VERSION = "1.0"
    description = "crashes"; dependencies = []; ram_class = "low"
    safe_mode = False; requires_lab = False
    def __init__(self, p): self.p = p; self._n_findings = 0
    def validate_config(self): return True
    def run(self): raise RuntimeError("intentional crash")

class MockPipeline:
    class args:
        lab = True
        cookie = None

def test_register_and_list():
    reg = PluginRegistry()
    m = PluginManifest(name="test", version="1.0")
    reg.register(m, MockPlugin)
    plugins = reg.list_plugins(lab=True)
    assert any(p.name == "test" for p in plugins)

def test_plugin_isolation_crash_doesnt_propagate():
    reg = PluginRegistry()
    m = PluginManifest(name="crash_plugin", version="1.0")
    reg.register(m, CrashPlugin)
    # Must NOT raise
    ex = reg.execute("crash_plugin", MockPipeline())
    assert ex.status == "failed"
    assert "intentional crash" in ex.error

def test_successful_execution():
    reg = PluginRegistry()
    m = PluginManifest(name="mock_plugin", version="1.0")
    reg.register(m, MockPlugin)
    ex = reg.execute("mock_plugin", MockPipeline())
    assert ex.status == "done"
    assert ex.findings_n == 3

def test_lab_flag_enforcement():
    reg = PluginRegistry()
    m = PluginManifest(name="lab_plugin", version="1.0", requires_lab=True)
    reg.register(m, MockPlugin)
    class NoLabPipeline:
        class args:
            lab = False
            cookie = None
    ex = reg.execute("lab_plugin", NoLabPipeline())
    assert ex.status == "skipped"
    assert "lab" in ex.error.lower()

def test_unknown_plugin_skips():
    reg = PluginRegistry()
    ex = reg.execute("nonexistent_plugin", MockPipeline())
    assert ex.status == "skipped"

def test_summary_counts():
    reg = PluginRegistry()
    reg.register(PluginManifest(name="p1"), MockPlugin)
    reg.register(PluginManifest(name="p2"), CrashPlugin)
    reg.execute("p1", MockPipeline())
    reg.execute("p2", MockPipeline())
    s = reg.summary()
    assert s["done"] == 1 and s["failed"] == 1

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); passed += 1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
