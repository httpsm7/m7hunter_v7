#!/usr/bin/env python3
# ai/agent_manager.py — AI Agent Role Coordinator
# Blueprint 5.5: Coordinates all AI roles — gated, structured, predictable
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import time, threading, json
from core.error_handler import get_handler

ACTIVATION_TRIGGERS = {
    "high_confidence_finding" : 0.85,
    "ambiguous_finding"       : (0.50, 0.84),
    "verification_needed"     : True,
    "exploit_correlation"     : True,
}

class AgentManager:
    """
    Blueprint 5.5: Central AI coordinator.

    AI MUST NOT:
    - analyze everything
    - run continuously
    - generate uncontrolled free-text
    - consume RAM constantly

    AI ACTIVATES ONLY when:
    - High-confidence finding needs correlation
    - Ambiguous finding needs verification
    - Business logic anomaly detected
    - Explicit verification requested

    All outputs are structured JSON — never free-text.
    """

    def __init__(self, resource_ctrl=None, state_manager=None, log=None):
        self.rctrl  = resource_ctrl
        self.state  = state_manager
        self.log    = log
        self._lock  = threading.Lock()
        self._ai    = None
        self._router = None
        self._risk_engine = None
        self._memory = None
        self._ready  = False
        self._call_count   = 0
        self._token_budget = 10000  # max tokens per scan session
        self._tokens_used  = 0
        self._init()

    def _init(self):
        try:
            from ai.prompt_router import PromptRouter
            from ai.risk_engine   import RiskEngine
            from ai.memory_store  import MemoryStore
            try:
                from integrations.ollama_ai import OllamaAI
                self._ai = OllamaAI(log=self.log)
            except Exception:
                pass
            self._router      = PromptRouter(ai_client=self._ai, log=self.log)
            self._risk_engine = RiskEngine(router=self._router)
            self._memory      = MemoryStore()
            self._ready       = self._ai is not None
        except Exception as e:
            get_handler().capture("agent_manager", e, "_init")
            self._ready = False

    # ── Gate check ────────────────────────────────────────────────────
    def _gate(self, reason: str = "") -> tuple[bool, str]:
        if not self._ready:
            return False, "AI not available"
        if self.rctrl and not self.rctrl.ai_allowed():
            return False, "RAM gate blocked"
        if self._tokens_used >= self._token_budget:
            return False, f"token budget exhausted ({self._token_budget})"
        return True, "ok"

    def should_activate(self, finding: dict) -> tuple[bool, str]:
        conf = finding.get("confidence", 0.0)
        lo, hi = ACTIVATION_TRIGGERS["ambiguous_finding"]
        if lo <= conf <= hi:
            return self._gate("ambiguous")
        if conf >= ACTIVATION_TRIGGERS["high_confidence_finding"]:
            if finding.get("needs_correlation"):
                return self._gate("high_confidence_correlation")
        return False, f"confidence {conf:.2f} outside activation range"

    # ── AI Role Dispatch ──────────────────────────────────────────────
    def verify_finding(self, finding: dict) -> dict:
        ok, reason = self._gate("verify")
        if not ok:
            return {"skipped": True, "reason": reason}
        try:
            result = self._router.verify(finding)
            self._track_call(result)
            # Store in memory
            if self._memory:
                self._memory.store_decision("verify", finding, result)
            return result
        except Exception as e:
            get_handler().capture("agent_manager", e, "verify_finding")
            return {"error": str(e)}

    def score_finding(self, finding: dict) -> dict:
        ok, reason = self._gate("score")
        if not ok:
            return {"skipped": True, "reason": reason}
        try:
            result = self._risk_engine.evaluate(finding)
            self._track_call(result)
            return result
        except Exception as e:
            get_handler().capture("agent_manager", e, "score_finding")
            return {"error": str(e)}

    def correlate_findings(self, findings: list) -> dict:
        """Connect related findings — IDOR→ATO, SSRF→CloudCreds, etc."""
        ok, reason = self._gate("correlate")
        if not ok:
            return {"skipped": True, "reason": reason, "chains": []}
        try:
            chains = self._find_chains(findings)
            if chains and self._router:
                summary = self._router.route("prioritizer", {
                    "findings_json": json.dumps(findings[:8], indent=2)
                })
                return {"chains": chains, "priority": summary}
            return {"chains": chains}
        except Exception as e:
            get_handler().capture("agent_manager", e, "correlate_findings")
            return {"chains": [], "error": str(e)}

    def write_report_section(self, finding: dict) -> dict:
        ok, reason = self._gate("report")
        if not ok:
            return {"skipped": True, "reason": reason}
        try:
            return self._router.write_report(finding)
        except Exception as e:
            get_handler().capture("agent_manager", e, "write_report_section")
            return {"error": str(e)}

    def batch_triage(self, findings: list, max_items: int = 15) -> list:
        """
        Triage a batch of findings. Cap at max_items for RAM control.
        Only processes ambiguous-range findings.
        """
        ok, reason = self._gate("triage")
        if not ok:
            if self.log:
                self.log.info(f"[AgentMgr] Triage skipped: {reason}")
            return []

        targets = [
            f for f in findings
            if 0.50 <= f.get("confidence", 0) <= 0.84
        ][:max_items]

        if not targets:
            return []

        if self.log:
            self.log.info(f"[AgentMgr] Triaging {len(targets)} ambiguous findings")

        results = []
        for f in targets:
            result = self.verify_finding(f)
            result["_finding"] = f
            results.append(result)
            time.sleep(0.3)  # avoid hammering Ollama

        confirmed = sum(1 for r in results if r.get("verdict") == "confirmed")
        fp_count  = sum(1 for r in results if r.get("verdict") == "false_positive")
        if self.log:
            self.log.info(
                f"[AgentMgr] Triage done: {confirmed} confirmed, "
                f"{fp_count} FP, {len(results)-confirmed-fp_count} needs_review"
            )
        return results

    # ── Chain detection ───────────────────────────────────────────────
    CHAIN_MAP = {
        ("IDOR","XSS")         : "IDOR→Stored XSS → Account Takeover",
        ("SSRF","CLOUD_EXPOSURE"): "SSRF→Cloud Credentials Leak",
        ("SQLI","LFI")         : "SQLi→File Read → RCE potential",
        ("JWT_FORGERY","IDOR") : "JWT Forgery→IDOR → Privilege Escalation",
        ("CORS_MISCONFIG","XSS"): "CORS→XSS → Cross-Origin Data Theft",
    }

    def _find_chains(self, findings: list) -> list:
        found_types = {f.get("vuln_type","").upper() for f in findings}
        chains = []
        for (t1, t2), description in self.CHAIN_MAP.items():
            if t1 in found_types and t2 in found_types:
                chains.append({
                    "type1": t1, "type2": t2,
                    "chain": description,
                    "severity": "critical"
                })
        return chains

    def _track_call(self, result: dict):
        with self._lock:
            self._call_count += 1
            if isinstance(result, dict) and not result.get("skipped"):
                self._tokens_used += 256  # estimate

    @property
    def status(self) -> dict:
        return {
            "ready"       : self._ready,
            "call_count"  : self._call_count,
            "tokens_used" : self._tokens_used,
            "token_budget": self._token_budget,
            "budget_pct"  : round(self._tokens_used / self._token_budget * 100, 1),
        }
