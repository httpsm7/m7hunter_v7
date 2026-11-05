#!/usr/bin/env python3
# core/ceo_engine.py — M7Hunter V7 CEO Rule Engine
# Controls pipeline: confirm_threshold, auto-chain, severity gates, kill switch
# MilkyWay Intelligence | Author: Sharlix

import threading
import time
from typing import Callable, Optional

# ── Default CEO Rules ────────────────────────────────────────────────
DEFAULT_RULES = {
    # Require double-verification before adding to final report
    "double_verify"          : True,
    "double_verify_delay_ms" : 1500,

    # Confidence threshold per severity
    "min_confidence_critical": 0.85,
    "min_confidence_high"    : 0.75,
    "min_confidence_medium"  : 0.60,
    "min_confidence_low"     : 0.50,

    # Auto-chain: if IDOR found → auto-trigger ATO module
    "auto_chain_idor_to_ato" : True,
    "auto_chain_ssrf_to_cloud": True,
    "auto_chain_xss_to_cookie": True,

    # Severity gate: only report medium+ in HTML; low goes to JSON only
    "html_min_severity"      : "medium",

    # Dedup: deduplicate by URL pattern (replace IDs with {N})
    "dedup_by_pattern"       : True,

    # Step control
    "skip_on_waf_detected"   : False,
    "max_findings_per_type"  : 50,

    # Stealth delays (ms)
    "stealth_min_delay_ms"   : 3000,
    "stealth_max_delay_ms"   : 8000,
    "normal_min_delay_ms"    : 300,
    "normal_max_delay_ms"    : 1500,
}

# ── Live control commands ─────────────────────────────────────────────
class PipelineState:
    RUNNING  = "running"
    PAUSED   = "paused"
    STOPPING = "stopping"
    STOPPED  = "stopped"


class CEOEngine:
    """
    V7 CEO Rule Engine.

    Controls:
    - Live pause/resume/stop
    - Double-verification of findings before report
    - Auto-chain suggestions (IDOR→ATO, SSRF→Cloud)
    - Severity gating
    - Per-type finding limits
    - Kill switch
    """

    def __init__(self, rules: dict = None, log=None):
        self.rules          = dict(DEFAULT_RULES)
        if rules:
            self.rules.update(rules)
        self.log            = log
        self._state         = PipelineState.RUNNING
        self._state_lock    = threading.Lock()
        self._pause_event   = threading.Event()
        self._pause_event.set()   # not paused initially
        self._findings_count: dict = {}  # type→count
        self._checkpoint_path: Optional[str] = None
        self._on_stop_callbacks: list = []
        self._waf_detected  = False

    # ── State control (live) ─────────────────────────────────────────

    def pause(self):
        """Pause the pipeline. Steps will wait at next checkpoint."""
        with self._state_lock:
            if self._state == PipelineState.RUNNING:
                self._state = PipelineState.PAUSED
                self._pause_event.clear()
                if self.log: self.log.warn("[CEO] Pipeline PAUSED — use resume() to continue")

    def resume(self):
        """Resume a paused pipeline."""
        with self._state_lock:
            if self._state == PipelineState.PAUSED:
                self._state = PipelineState.RUNNING
                self._pause_event.set()
                if self.log: self.log.success("[CEO] Pipeline RESUMED")

    def stop(self):
        """Graceful stop — saves state, finishes current step."""
        with self._state_lock:
            self._state = PipelineState.STOPPING
            self._pause_event.set()   # unblock any waiting steps
        if self.log: self.log.warn("[CEO] Pipeline STOPPING — finishing current step...")
        for cb in self._on_stop_callbacks:
            try: cb()
            except Exception: pass

    def kill(self):
        """Immediate kill switch — no cleanup."""
        with self._state_lock:
            self._state = PipelineState.STOPPED
            self._pause_event.set()
        if self.log: self.log.warn("[CEO] KILL SWITCH ACTIVATED — pipeline terminated")
        import os, signal
        os.kill(os.getpid(), signal.SIGTERM)

    def on_stop(self, callback: Callable):
        """Register callback for graceful stop."""
        self._on_stop_callbacks.append(callback)

    # ── Step gate ────────────────────────────────────────────────────

    def step_gate(self) -> bool:
        """
        Call at the start of each step. Handles pause/stop.
        Returns False if pipeline should stop.
        """
        self._pause_event.wait()  # blocks if paused
        with self._state_lock:
            if self._state in (PipelineState.STOPPING, PipelineState.STOPPED):
                return False
        return True

    def is_running(self) -> bool:
        with self._state_lock:
            return self._state == PipelineState.RUNNING

    def get_state(self) -> str:
        with self._state_lock:
            return self._state

    # ── Finding validation ───────────────────────────────────────────

    def validate_finding(self, vuln_type: str, confidence: float,
                          severity: str) -> tuple:
        """
        Validate a potential finding against CEO rules.
        Returns (allow: bool, reason: str)
        """
        # Per-type limit
        count = self._findings_count.get(vuln_type, 0)
        if count >= self.rules["max_findings_per_type"]:
            return False, f"Per-type limit reached ({count}/{self.rules['max_findings_per_type']})"

        # Confidence gate
        min_conf_key = f"min_confidence_{severity}"
        min_conf     = self.rules.get(min_conf_key, 0.50)
        if confidence < min_conf:
            return False, f"Confidence {confidence:.2f} < required {min_conf:.2f} for {severity}"

        # WAF detection gate
        if self._waf_detected and self.rules.get("skip_on_waf_detected"):
            return False, "WAF detected — skipping (CEO rule: skip_on_waf_detected)"

        return True, "ok"

    def accept_finding(self, vuln_type: str):
        """Increment accepted finding counter."""
        self._findings_count[vuln_type] = self._findings_count.get(vuln_type, 0) + 1

    # ── Double verification ──────────────────────────────────────────

    def should_double_verify(self) -> bool:
        return self.rules.get("double_verify", True)

    def double_verify_delay(self) -> float:
        return self.rules.get("double_verify_delay_ms", 1500) / 1000.0

    # ── Auto-chain ───────────────────────────────────────────────────

    def get_auto_chains(self, vuln_type: str) -> list:
        """Return list of modules to auto-trigger based on finding."""
        chains = []
        vt = vuln_type.upper()
        if "IDOR" in vt and self.rules.get("auto_chain_idor_to_ato"):
            chains.append(("ATO", "idor_ato_chain"))
        if "SSRF" in vt and "AWS" in vt and self.rules.get("auto_chain_ssrf_to_cloud"):
            chains.append(("CLOUD_CREDS", "ssrf_cloud_chain"))
        if "XSS" in vt and self.rules.get("auto_chain_xss_to_cookie"):
            chains.append(("SESSION_HIJACK", "xss_cookie_chain"))
        return chains

    # ── WAF detection ────────────────────────────────────────────────

    def set_waf_detected(self, waf_name: str):
        self._waf_detected = True
        if self.log:
            self.log.warn(f"[CEO] WAF detected: {waf_name}")

    # ── HTML severity gate ───────────────────────────────────────────

    def should_include_in_html(self, severity: str) -> bool:
        ORDER     = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        min_sev   = self.rules.get("html_min_severity","medium")
        return ORDER.get(severity,4) <= ORDER.get(min_sev,2)

    # ── Stealth delay ────────────────────────────────────────────────

    def get_delay(self, stealth: bool = False) -> float:
        import random
        if stealth:
            mn = self.rules["stealth_min_delay_ms"] / 1000
            mx = self.rules["stealth_max_delay_ms"] / 1000
        else:
            mn = self.rules["normal_min_delay_ms"] / 1000
            mx = self.rules["normal_max_delay_ms"] / 1000
        return random.uniform(mn, mx)

    # ── URL dedup ────────────────────────────────────────────────────

    def normalize_url_pattern(self, url: str) -> str:
        """Replace numeric IDs with {N} for pattern dedup."""
        import re
        if not self.rules.get("dedup_by_pattern"):
            return url
        url = re.sub(r'(=)\d+', r'\1{N}', url)
        url = re.sub(r'/\d+(/|$)', r'/{N}\1', url)
        return url

    # ── Status report ────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "state"          : self.get_state(),
            "waf_detected"   : self._waf_detected,
            "findings_count" : dict(self._findings_count),
            "rules_active"   : {k: v for k, v in self.rules.items()
                                 if isinstance(v, bool) and v},
        }
