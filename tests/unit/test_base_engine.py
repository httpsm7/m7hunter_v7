#!/usr/bin/env python3
import sys, os, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def _make_pipeline():
    class FakeLog:
        def info(self,m): pass
        def warn(self,m): pass
        def error(self,m): pass
        def success(self,m): pass
    class FakeFindings:
        def add(self,**kw): pass
    class FakePipeline:
        log = FakeLog()
        target = "test.com"
        class args:
            lab = True; cookie = None
        findings_engine = FakeFindings()
        def shell(self,cmd,**kw): return ""
    return FakePipeline()

def test_lifecycle_states():
    from core.base_engine import BaseEngine, EngineState
    states = [s.value for s in EngineState]
    for s in ["idle","warming","running","paused","flushing","sleeping","failed","done"]:
        assert s in states

def test_full_lifecycle_success():
    from core.base_engine import BaseEngine, EngineState
    class GoodEngine(BaseEngine):
        name = "good_engine"
        async def execute(self): self._n_findings = 3
    p = _make_pipeline()
    e = GoodEngine(p)
    result = asyncio.run(e.run_lifecycle())
    assert result["status"] == "done"
    assert result["findings"] == 3
    assert e._state == EngineState.DONE

def test_failed_engine_doesnt_hang():
    from core.base_engine import BaseEngine, EngineState
    class BadEngine(BaseEngine):
        name = "bad_engine"
        async def execute(self): raise ValueError("intentional")
    p = _make_pipeline()
    e = BadEngine(p)
    result = asyncio.run(e.run_lifecycle())
    assert result["status"] == "failed"
    assert "intentional" in result["error"]

def test_handle_tracking():
    from core.base_engine import BaseEngine
    class DummyEngine(BaseEngine):
        name = "dummy"
        async def execute(self): pass
    class FakeHandle:
        closed = False
        def close(self): self.closed = True
    p  = _make_pipeline()
    e  = DummyEngine(p)
    fh = FakeHandle()
    e.track(fh)
    assert len(e._handles) == 1
    e._close_handles()
    assert fh.closed
    assert len(e._handles) == 0

def test_add_finding():
    from core.base_engine import BaseEngine
    class DummyEngine(BaseEngine):
        name="dummy"
        async def execute(self): pass
    p = _make_pipeline()
    e = DummyEngine(p)
    e.add_finding("XSS","https://x.com","reflected",0.9,"high")
    assert e._n_findings == 1

def test_metadata():
    from core.base_engine import BaseEngine
    class MetaEngine(BaseEngine):
        name="meta"; version="2.0"
        description="test"; dependencies=["step01"]
        resource_cost="low"; stage_group="recon"
        async def execute(self): pass
    m = MetaEngine.get_metadata()
    assert m["name"] == "meta"
    assert m["version"] == "2.0"
    assert "step01" in m["dependencies"]

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
