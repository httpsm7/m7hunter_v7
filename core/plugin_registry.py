#!/usr/bin/env python3
# core/plugin_registry.py — Isolated Plugin Registry
# Blueprint 5.7: Plugin failures MUST NOT crash scheduler, corrupt DB, or leak sessions
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import importlib, inspect, time, traceback
from dataclasses import dataclass, field
from typing import Optional
from core.error_handler import get_handler

@dataclass
class PluginManifest:
    name          : str
    version       : str        = "1.0"
    author        : str        = "unknown"
    description   : str        = ""
    dependencies  : list       = field(default_factory=list)
    resource_cost : str        = "medium"   # low/medium/high/critical
    safe_mode     : bool       = False      # skip if target is sensitive
    requires_lab  : bool       = False
    module_path   : str        = ""
    class_name    : str        = ""
    enabled       : bool       = True

@dataclass
class PluginExecution:
    plugin_name : str
    started_at  : float = 0.0
    finished_at : float = 0.0
    status      : str   = "idle"   # idle/running/done/failed/skipped
    error       : str   = ""
    findings_n  : int   = 0


class PluginRegistry:
    """
    Blueprint 5.7: Isolated plugin execution.
    
    Rules:
    - Plugin failures MUST NOT crash the scheduler
    - Plugin failures MUST NOT corrupt state DB
    - Plugin failures MUST NOT leak browser sessions
    - Plugin failures MUST NOT leak asyncio tasks
    
    Every plugin runs in try/except isolation.
    Manifest must define: name, version, dependencies, resource_cost, safe_mode
    """

    def __init__(self, state_manager=None, resource_ctrl=None, log=None):
        self.state  = state_manager
        self.rctrl  = resource_ctrl
        self.log    = log
        self._manifests   : dict[str, PluginManifest]  = {}
        self._executions  : dict[str, PluginExecution] = {}
        self._classes     : dict[str, type]            = {}

    # ── Registration ──────────────────────────────────────────────────
    def register(self, manifest: PluginManifest, cls: type = None):
        self._manifests[manifest.name] = manifest
        if cls:
            self._classes[manifest.name] = cls
        if self.log:
            self.log.info(f"[PluginRegistry] Registered: {manifest.name} v{manifest.version}")

    def auto_discover(self, plugin_dir: str = "plugins"):
        """Scan plugins/ directory and auto-register all valid plugins."""
        import os, glob
        pattern = f"{plugin_dir}/**/*.py"
        for path in glob.glob(pattern, recursive=True):
            if "__pycache__" in path or "__init__" in path:
                continue
            try:
                self._load_plugin_file(path)
            except Exception as e:
                get_handler().capture("plugin_registry", e, f"discover:{path}")

    def _load_plugin_file(self, path: str):
        import importlib.util, os
        mod_name = path.replace("/","_").replace("\\","_").replace(".py","")
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if not spec:
            return
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for name, cls in inspect.getmembers(mod, inspect.isclass):
            if hasattr(cls, "PLUGIN_NAME") and hasattr(cls, "PLUGIN_VERSION"):
                manifest = PluginManifest(
                    name         = cls.PLUGIN_NAME,
                    version      = cls.PLUGIN_VERSION,
                    author       = getattr(cls, "PLUGIN_AUTHOR", "unknown"),
                    description  = getattr(cls, "description", ""),
                    dependencies = getattr(cls, "dependencies", []),
                    resource_cost= getattr(cls, "ram_class", "medium"),
                    safe_mode    = getattr(cls, "safe_mode", False),
                    requires_lab = getattr(cls, "requires_lab", False),
                    module_path  = path,
                    class_name   = name,
                )
                self.register(manifest, cls)

    # ── Execution ─────────────────────────────────────────────────────
    def execute(self, plugin_name: str, pipeline,
                scan_id: str = "") -> PluginExecution:
        """
        Execute a plugin in full isolation.
        Blueprint: plugin failure MUST NOT propagate to scheduler.
        """
        manifest = self._manifests.get(plugin_name)
        ex = PluginExecution(plugin_name=plugin_name, started_at=time.time())
        self._executions[plugin_name] = ex

        if not manifest or not manifest.enabled:
            ex.status = "skipped"
            ex.error  = "not registered or disabled"
            return ex

        if manifest.requires_lab and not getattr(pipeline.args, "lab", False):
            ex.status = "skipped"
            ex.error  = "requires --lab flag"
            if self.log:
                self.log.info(f"[PluginRegistry] Skipped {plugin_name}: requires --lab")
            return ex

        if self.rctrl:
            allowed, reason = self.rctrl.can_start(manifest.resource_cost)
            if not allowed:
                ex.status = "skipped"
                ex.error  = f"resource gate: {reason}"
                return ex

        # ── Isolated execution ────────────────────────────────────────
        try:
            ex.status = "running"
            cls = self._get_class(manifest)
            if not cls:
                raise ImportError(f"Cannot load class for {plugin_name}")

            instance = cls(pipeline)
            if hasattr(instance, "validate_config") and not instance.validate_config():
                ex.status = "skipped"
                ex.error  = "validate_config failed"
                return ex

            if hasattr(instance, "prepare"):
                instance.prepare()

            instance.run()
            ex.findings_n  = getattr(instance, "_n_findings", 0)
            ex.status      = "done"
            ex.finished_at = time.time()

            if self.state and scan_id:
                self.state.stage_done(scan_id, plugin_name, findings_n=ex.findings_n)

            if self.log:
                elapsed = round(ex.finished_at - ex.started_at, 1)
                self.log.info(
                    f"[PluginRegistry] ✓ {plugin_name} "
                    f"({elapsed}s | {ex.findings_n} findings)"
                )

        except Exception as e:
            # ISOLATION: capture error, never re-raise to scheduler
            ex.status      = "failed"
            ex.error       = str(e)
            ex.finished_at = time.time()
            tb = traceback.format_exc()
            get_handler().capture("plugin_registry", e, f"execute:{plugin_name}")
            if self.log:
                self.log.error(f"[PluginRegistry] ✗ {plugin_name}: {e}")
            if self.state and scan_id:
                self.state.stage_done(scan_id, plugin_name, error=str(e))

        finally:
            # Ensure handles are released even on crash
            try:
                if "instance" in dir() and hasattr(instance, "_release_handles"):
                    instance._release_handles()
            except Exception:
                pass

        return ex

    def _get_class(self, manifest: PluginManifest) -> Optional[type]:
        if manifest.name in self._classes:
            return self._classes[manifest.name]
        if manifest.module_path and manifest.class_name:
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    manifest.name, manifest.module_path
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return getattr(mod, manifest.class_name, None)
            except Exception as e:
                get_handler().capture("plugin_registry", e, f"load_class:{manifest.name}")
        return None

    # ── Query API ─────────────────────────────────────────────────────
    def list_plugins(self, lab: bool = False) -> list[PluginManifest]:
        return [
            m for m in self._manifests.values()
            if m.enabled and (not m.requires_lab or lab)
        ]

    def get_execution(self, name: str) -> Optional[PluginExecution]:
        return self._executions.get(name)

    def summary(self) -> dict:
        execs = list(self._executions.values())
        return {
            "registered": len(self._manifests),
            "executed"  : len(execs),
            "done"      : sum(1 for e in execs if e.status == "done"),
            "failed"    : sum(1 for e in execs if e.status == "failed"),
            "skipped"   : sum(1 for e in execs if e.status == "skipped"),
            "findings"  : sum(e.findings_n for e in execs),
        }
