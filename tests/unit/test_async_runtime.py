#!/usr/bin/env python3
import sys, os, asyncio, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def test_runtime_starts():
    from core.async_runtime import AsyncRuntime
    rt = AsyncRuntime()
    rt.start()
    assert rt.is_running
    rt.shutdown(wait=True)

def test_submit_and_wait():
    from core.async_runtime import AsyncRuntime
    rt = AsyncRuntime(); rt.start()
    async def work(): return 42
    result = rt.submit_and_wait(work(), timeout=5)
    assert result == 42
    rt.shutdown(wait=True)

def test_timeout_cancels():
    from core.async_runtime import AsyncRuntime
    rt = AsyncRuntime(); rt.start()
    async def slow(): await asyncio.sleep(100)
    result = rt.submit_and_wait(slow(), timeout=1)
    assert result is None
    rt.shutdown(wait=True)

def test_cancel_task():
    from core.async_runtime import AsyncRuntime
    rt = AsyncRuntime(); rt.start()
    async def slow(): await asyncio.sleep(100)
    rt.submit(slow(), name="test_task")
    time.sleep(0.1)
    cancelled = rt.cancel_task("test_task")
    assert cancelled
    rt.shutdown(wait=True)

def test_cancel_all():
    from core.async_runtime import AsyncRuntime
    rt = AsyncRuntime(); rt.start()
    async def slow(): await asyncio.sleep(100)
    for i in range(5):
        rt.submit(slow(), name=f"task_{i}")
    time.sleep(0.1)
    rt.cancel_all()
    rt.shutdown(wait=True)

def test_status_dict():
    from core.async_runtime import AsyncRuntime
    rt = AsyncRuntime(); rt.start()
    s = rt.status()
    assert "running" in s and "active_tasks" in s
    rt.shutdown(wait=True)

def test_singleton():
    from core.async_runtime import get_runtime
    r1 = get_runtime(); r2 = get_runtime()
    assert r1 is r2

if __name__ == "__main__":
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    p=f=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); p+=1
        except Exception as e: print(f"  ✗ {t.__name__}: {e}"); f+=1
    print(f"\n{p} passed, {f} failed")
