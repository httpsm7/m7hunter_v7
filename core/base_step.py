#!/usr/bin/env python3
# core/base_step.py — Abstract BaseStep with Full Lifecycle States
# Blueprint: idle→warming→running→cooling→sleeping + resource release hooks
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

from abc import ABC, abstractmethod
from enum import Enum
import time

class LifecycleState(Enum):
    IDLE     = "idle"
    WARMING  = "warming"
    RUNNING  = "running"
    COOLING  = "cooling"
    SLEEPING = "sleeping"
    DONE     = "done"
    FAILED   = "failed"

class BaseStep(ABC):
    """
    Blueprint: Every module moves through:
      idle → warming → running → cooling → sleeping → done

    After a stage finishes it MUST:
      - flush findings
      - release browser/session handles
      - close file/network handles
      - save checkpoint
      - return to idle
    """

    name        : str  = "unnamed"
    description : str  = ""
    dependencies: list = []
    requires_lab: bool = False
    ram_class   : str  = "medium"   # critical/high/medium/low/minimal
    stage_group : str  = "vuln"

    def __init__(self, pipeline):
        self.p            = pipeline
        self.log          = pipeline.log
        self.args         = pipeline.args
        self.target       = pipeline.target
        self._state       = LifecycleState.IDLE
        self._start_time  = None
        self._n_findings  = 0
        # Handles to release on cooling
        self._browser     = None
        self._page        = None
        self._context     = None
        self._client      = None
        self._open_files  = []

    # ── Lifecycle hooks (override as needed) ──────────────────────────
    def validate_config(self) -> bool:
        if self.requires_lab and not getattr(self.args, "lab", False):
            self.log.warn(f"[{self.name}] Requires --lab flag. Skipping.")
            return False
        return True

    def prepare(self):
        """Warming phase — setup resources, validate tools."""
        self._state = LifecycleState.WARMING

    @abstractmethod
    def run(self):
        """Running phase — main scan logic."""
        pass

    def cool_down(self):
        """
        Cooling phase — release all handles, flush buffers.
        Called automatically by execute() after run().
        Override to add module-specific cleanup.
        """
        self._state = LifecycleState.COOLING
        self._release_handles()

    def sleep(self):
        """Sleeping phase — brief pause before marking done."""
        self._state = LifecycleState.SLEEPING
        time.sleep(0.2)

    # ── Orchestrated execute (used when not under Scheduler) ──────────
    def execute(self):
        from core.error_handler import get_handler
        self._start_time = time.time()

        if not self.validate_config():
            self._state = LifecycleState.DONE
            return

        # WARMING
        try:
            self.prepare()
        except Exception as e:
            get_handler().capture(self.name, e, "prepare()")

        # RUNNING
        self._state = LifecycleState.RUNNING
        result = None
        try:
            result = self.run()
        except Exception as e:
            get_handler().capture(self.name, e, "run()")
            self._state = LifecycleState.FAILED

        # COOLING
        try:
            self.cool_down()
        except Exception as e:
            get_handler().capture(self.name, e, "cool_down()")

        # SLEEPING
        try:
            self.sleep()
        except Exception as e:
            get_handler().capture(self.name, e, "sleep()")

        # DONE
        self._state = LifecycleState.DONE
        elapsed = round(time.time() - self._start_time, 1)
        self.log.info(
            f"[{self.name}] {self._state.value} | "
            f"{elapsed}s | findings:{self._n_findings}"
        )
        return result

    # ── Handle release (cooling) ──────────────────────────────────────
    def _release_handles(self):
        """Blueprint: release browser/session/file/network handles."""
        from core.error_handler import get_handler

        # Browser handles
        for attr in ("_page", "_context", "_browser"):
            try:
                obj = getattr(self, attr, None)
                if obj is not None:
                    if hasattr(obj, "close"):
                        obj.close()
                    setattr(self, attr, None)
            except Exception as e:
                get_handler().capture(self.name, e, f"release:{attr}")

        # Async HTTP client
        if self._client is not None:
            try:
                import asyncio
                if hasattr(self._client, "aclose"):
                    loop = asyncio.new_event_loop()
                    loop.run_until_complete(self._client.aclose())
                    loop.close()
            except Exception as e:
                get_handler().capture(self.name, e, "release:_client")
            finally:
                self._client = None

        # Open file handles
        for fh in self._open_files:
            try:
                if not fh.closed:
                    fh.close()
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("base_step", _e)
        self._open_files.clear()

    # ── Convenience methods ───────────────────────────────────────────
    def add_finding(self, vuln_type, url, evidence,
                    confidence, severity):
        self._n_findings += 1
        try:
            self.p.findings_engine.add(
                vuln_type=vuln_type, url=url,
                detail=evidence, confidence=confidence,
                severity=severity, stage=self.name
            )
        except Exception as e:
            from core.error_handler import get_handler
            get_handler().capture(self.name, e, f"add_finding:{vuln_type}")

    def shell(self, cmd, timeout=300, label=None, append_file=None):
        try:
            return self.p.shell(
                cmd, timeout=timeout,
                label=label or self.name,
                append_file=append_file
            )
        except Exception as e:
            from core.error_handler import get_handler
            get_handler().capture(self.name, e, f"shell:{cmd[:60]}")
            return ""

    def register_file_handle(self, fh):
        """Track open file handles for cleanup in cool_down."""
        self._open_files.append(fh)
        return fh

    @property
    def lifecycle_state(self) -> str:
        return self._state.value

class BasePlugin(BaseStep):
    PLUGIN_NAME   : str = "unnamed_plugin"
    PLUGIN_VERSION: str = "1.0"
    PLUGIN_AUTHOR : str = "Sharlix"

    @classmethod
    def get_metadata(cls) -> dict:
        return {
            "name"   : cls.PLUGIN_NAME,
            "version": cls.PLUGIN_VERSION,
            "author" : cls.PLUGIN_AUTHOR,
            "desc"   : cls.description,
            "lab"    : cls.requires_lab,
        }
