#!/usr/bin/env python3
# core/error_handler.py — Centralized Structured Error Handler
# Blueprint Fix: Replaces ALL silent except:pass blocks
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import sys, traceback, threading, logging, json
from datetime import datetime

_handler_instance = None
def get_handler():
    global _handler_instance
    if _handler_instance is None:
        _handler_instance = ErrorHandler()
    return _handler_instance

class ErrorHandler:
    def __init__(self, log=None, sentry_dsn=None):
        self.log     = log
        self._errors = []
        self._lock   = threading.Lock()
        self._sentry = None
        sys.excepthook = self._global_hook
        if sentry_dsn:
            try:
                import sentry_sdk; sentry_sdk.init(dsn=sentry_dsn, traces_sample_rate=0.1)
                self._sentry = sentry_sdk
            except ImportError: pass

    def _global_hook(self, exc_type, exc_val, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_val, exc_tb); return
        tb = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
        self._record("UNHANDLED", str(exc_val), tb, "global")
        if self.log: self.log.error(f"[UNHANDLED] {exc_val}\n{tb}")

    def capture(self, module, exc, context="", reraise=False):
        tb = traceback.format_exc()
        self._record(module, str(exc), tb, context)
        if self.log:
            self.log.error(f"[{module}] {type(exc).__name__}: {exc}" + (f" | {context}" if context else ""))
        if self._sentry:
            try:
                with self._sentry.push_scope() as scope:
                    scope.set_tag("module", module); scope.set_extra("context", context)
                    self._sentry.capture_exception(exc)
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("error_handler", _e)
        if reraise: raise exc

    def _record(self, module, msg, tb, context):
        with self._lock:
            self._errors.append({"ts": datetime.now().isoformat(), "module": module,
                                  "message": msg, "context": context, "traceback": tb})

    def get_errors(self):
        with self._lock: return list(self._errors)

    def summary(self):
        n = len(self._errors)
        if not n: return "No errors."
        mods = {}
        for e in self._errors: mods[e["module"]] = mods.get(e["module"],0)+1
        top = sorted(mods.items(), key=lambda x:-x[1])[:5]
        return f"{n} errors | " + ", ".join(f"{m}:{c}" for m,c in top)

def safe_run(fn, module="unknown", context="", default=None, reraise=False):
    try: return fn()
    except Exception as e:
        get_handler().capture(module, e, context=context, reraise=reraise)
        return default
