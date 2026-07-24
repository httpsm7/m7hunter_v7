#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.error_handler import ErrorHandler, safe_run, get_handler

def test_capture_no_crash():
    h=ErrorHandler(); h.capture("test", ValueError("boom"), "ctx")
    assert len(h.get_errors())==1

def test_safe_run_returns_default():
    result=safe_run(lambda: 1/0, module="test", default="fallback")
    assert result=="fallback"

def test_safe_run_success():
    result=safe_run(lambda: 42, module="test")
    assert result==42

def test_summary_empty():
    h=ErrorHandler(); assert "No errors" in h.summary()

def test_summary_with_errors():
    h=ErrorHandler()
    for _ in range(3): h.capture("modA", RuntimeError("x"), "ctx")
    h.capture("modB", ValueError("y"), "ctx")
    assert "4 errors" in h.summary()

if __name__=="__main__":
    tests=[v for k,v in globals().items() if k.startswith("test_")]
    passed=failed=0
    for t in tests:
        try: t(); print(f"  ✓ {t.__name__}"); passed+=1
        except AssertionError as e: print(f"  ✗ {t.__name__}: {e}"); failed+=1
    print(f"\n{passed} passed, {failed} failed")
