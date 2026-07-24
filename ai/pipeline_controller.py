#!/usr/bin/env python3
# ai/pipeline_controller.py — AI-Gated Pipeline Controller
# Blueprint: LLM activates ONLY when confidence is ambiguous or finding needs verification
# Not on every event — only suspicious/ambiguous findings
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import time, threading
from core.error_handler import get_handler

# AI activates only in these confidence ranges
AI_GATE_MIN = 0.50   # below this → too low, discard
AI_GATE_MAX = 0.84   # above this → already confirmed, skip AI
AI_MAX_BATCH = 20    # max findings to send AI per run
AI_RAM_THRESHOLD = 75  # % RAM — pause AI above this

ANALYSIS_PROMPT = """You are a security analyst reviewing a bug bounty finding.
Evaluate whether this finding is a TRUE POSITIVE or FALSE POSITIVE.

Finding:
  Type       : {vuln_type}
  URL        : {url}
  Evidence   : {detail}
  Tool       : {tool}
  Confidence : {confidence}

Respond ONLY with valid JSON:
{{
  "verdict"     : "confirmed" | "false_positive" | "needs_review",
  "confidence"  : 0.0-1.0,
  "explanation" : "one sentence reason",
  "recommended_severity": "critical|high|medium|low|info"
}}"""

class AIGate:
    """
    Blueprint: AI Gate — LLM must not run on every event.
    Activates only when:
    - Confidence is in ambiguous range (0.50–0.84)
    - Finding needs verification
    - Result is ambiguous
    - User wants deeper analysis
    - RAM is below threshold
    """

    def __init__(self, resource_ctrl=None, log=None):
        self.rctrl  = resource_ctrl
        self.log    = log
        self._lock  = threading.Lock()
        self._cache : dict[str, dict] = {}   # url+type → result
        self._ai    = None
        self._ready = False
        self._init_ai()

    def _init_ai(self):
        try:
            from integrations.ollama_ai import OllamaAI
            self._ai    = OllamaAI(log=self.log)
            self._ready = True
        except ImportError:
            self._ready = False
        except Exception as e:
            get_handler().capture("ai_gate", e, "_init_ai")
            self._ready = False

    def should_activate(self, finding: dict) -> tuple[bool, str]:
        """Blueprint gate check — should AI review this finding?"""
        if not self._ready:
            return False, "AI not available"

        if self.rctrl and not self.rctrl.ai_allowed():
            return False, f"RAM above {AI_RAM_THRESHOLD}%"

        conf = finding.get("confidence", 0.0)
        if conf < AI_GATE_MIN:
            return False, f"confidence {conf:.2f} too low"
        if conf > AI_GATE_MAX:
            return False, f"confidence {conf:.2f} already confirmed"

        # Check cache
        cache_key = f"{finding.get('url','')}:{finding.get('vuln_type','')}"
        if cache_key in self._cache:
            return False, "cached result exists"

        return True, "in ambiguous range"

    def review_finding(self, finding: dict) -> dict:
        """
        Send a single finding to LLM for verification.
        Returns AI verdict dict.
        """
        activate, reason = self.should_activate(finding)
        if not activate:
            return {"skipped": True, "reason": reason}

        cache_key = f"{finding.get('url','')}:{finding.get('vuln_type','')}"

        try:
            prompt = ANALYSIS_PROMPT.format(
                vuln_type  = finding.get("vuln_type", ""),
                url        = finding.get("url", ""),
                detail     = finding.get("detail", "")[:300],
                tool       = finding.get("tool", ""),
                confidence = finding.get("confidence", 0),
            )
            response = self._ai.query(prompt, max_tokens=256)
            result   = self._parse_response(response)
            with self._lock:
                self._cache[cache_key] = result
            return result
        except Exception as e:
            get_handler().capture("ai_gate", e, "review_finding")
            return {"error": str(e)}

    def review_batch(self, findings: list) -> list:
        """
        Review a batch of ambiguous findings.
        Blueprint: cap at AI_MAX_BATCH to control RAM.
        """
        ambiguous = [
            f for f in findings
            if AI_GATE_MIN <= f.get("confidence", 0) <= AI_GATE_MAX
        ][:AI_MAX_BATCH]

        if not ambiguous:
            if self.log:
                self.log.info("[AIGate] No ambiguous findings to review")
            return []

        if self.log:
            self.log.info(f"[AIGate] Reviewing {len(ambiguous)} ambiguous findings")

        results = []
        for f in ambiguous:
            result = self.review_finding(f)
            result["original_finding"] = f
            results.append(result)
            time.sleep(0.5)   # avoid hammering Ollama

        confirmed = sum(1 for r in results if r.get("verdict") == "confirmed")
        fp        = sum(1 for r in results if r.get("verdict") == "false_positive")
        if self.log:
            self.log.info(f"[AIGate] Results: {confirmed} confirmed, {fp} FP, {len(results)-confirmed-fp} needs review")

        return results

    def plan_next_steps(self, findings: list, completed_stages: list) -> list:
        """
        Blueprint: Agentic AI planner — recommend next scanning steps
        based on what's been found so far.
        Only activates when explicitly requested (not automatic).
        """
        if not self._ready or not findings:
            return []

        if self.rctrl and not self.rctrl.ai_allowed():
            return []

        try:
            summary = self._summarise_findings(findings)
            prompt  = f"""You are a security research assistant helping plan bug bounty testing.

Completed stages: {', '.join(completed_stages)}

Finding summary:
{summary}

Suggest up to 5 additional testing actions that would be most valuable.
Respond ONLY with valid JSON array:
[{{"action": "...", "reason": "...", "priority": 1-5}}]"""

            response = self._ai.query(prompt, max_tokens=512)
            return self._parse_list_response(response)
        except Exception as e:
            get_handler().capture("ai_gate", e, "plan_next_steps")
            return []

    def _summarise_findings(self, findings: list) -> str:
        by_sev = {}
        for f in findings:
            s = f.get("severity","info")
            by_sev[s] = by_sev.get(s,0) + 1
        types = list({f.get("vuln_type","") for f in findings})[:10]
        return (f"Severity breakdown: {by_sev}\n"
                f"Vuln types found: {', '.join(types)}")

    def _parse_response(self, text: str) -> dict:
        import json, re
        try:
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("pipeline_controller", _e)
        return {"verdict": "needs_review", "confidence": 0.5,
                "explanation": text[:200] if text else "parse_error"}

    def _parse_list_response(self, text: str) -> list:
        import json, re
        try:
            m = re.search(r'\[.*\]', text, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("pipeline_controller", _e)
        return []

    @property
    def is_available(self) -> bool:
        return self._ready


class PipelineController:
    """
    Blueprint: AI-driven step ordering and skip logic.
    Wraps AIGate and provides pipeline-level AI decisions.
    """

    def __init__(self, pipeline):
        self.p      = pipeline
        self.log    = pipeline.log
        self.gate   = AIGate(
            resource_ctrl = getattr(pipeline, "rctrl", None),
            log           = pipeline.log
        )

    def review_all_findings(self) -> dict:
        """Post-scan: review all ambiguous findings through AI gate."""
        try:
            findings = self.p.findings_engine.get_all()
            results  = self.gate.review_batch(findings)
            return {
                "reviewed"  : len(results),
                "confirmed" : sum(1 for r in results if r.get("verdict")=="confirmed"),
                "false_pos" : sum(1 for r in results if r.get("verdict")=="false_positive"),
                "details"   : results,
            }
        except Exception as e:
            get_handler().capture("pipeline_controller", e, "review_all_findings")
            return {}

    def suggest_next_steps(self) -> list:
        """Get AI recommendations for next testing actions."""
        try:
            findings        = self.p.findings_engine.get_all()
            completed       = list(getattr(self.p, "_completed_stages", []))
            return self.gate.plan_next_steps(findings, completed)
        except Exception as e:
            get_handler().capture("pipeline_controller", e, "suggest_next_steps")
            return []

    def should_skip_stage(self, stage_name: str) -> tuple[bool, str]:
        """
        AI-assisted skip logic:
        If previous results suggest stage is irrelevant, skip it.
        Conservative — only skips safe_to_skip=True stages.
        """
        from core.engine_registry import get_registry
        spec = get_registry().get(stage_name)
        if not spec or not spec.safe_to_skip:
            return False, "required"
        # For now: skip screenshot if no live hosts
        if stage_name == "step14_screenshot":
            import os
            resolved = getattr(self.p, "files", {}).get("resolved","")
            if resolved and os.path.isfile(resolved):
                from core.utils import count_lines
                try:
                    n = count_lines(resolved)
                    if n == 0:
                        return True, "no live hosts found"
                except Exception as _e:
                    from core.error_handler import get_handler
                    get_handler().capture("pipeline_controller", _e)
        return False, "proceed"
