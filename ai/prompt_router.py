#!/usr/bin/env python3
# ai/prompt_router.py — Role-Based Prompt Router
# Blueprint Phase 5: AI as structured agent with specific roles
# Roles: summarizer, risk_scorer, verifier, payload_helper, report_writer, prioritizer
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import json, re
from core.error_handler import get_handler

# ── Prompt templates per role ─────────────────────────────────────────
PROMPTS = {

"summarizer": """You are a security finding summarizer.
Summarize this finding in 2 sentences max. Be technical and precise.

Finding:
  Type: {vuln_type}
  URL: {url}
  Evidence: {detail}
  Confidence: {confidence}

Respond ONLY with JSON:
{{"summary": "...", "one_liner": "..."}}""",

"risk_scorer": """You are a security risk analyst.
Score this finding objectively.

Finding:
  Type: {vuln_type}
  URL: {url}
  Evidence: {detail}
  Confidence: {confidence}

Respond ONLY with JSON:
{{"severity": "critical|high|medium|low|info",
  "cvss_estimate": 0.0,
  "exploitability": "easy|medium|hard",
  "business_impact": "...",
  "confidence_adjusted": 0.0}}""",

"verifier": """You are a security verification analyst.
Determine if this is a true positive or false positive.

Finding:
  Type: {vuln_type}
  URL: {url}
  Evidence: {detail}
  Response snippet: {response}
  Payload used: {payload}

Respond ONLY with JSON:
{{"verdict": "confirmed|false_positive|needs_review",
  "confidence": 0.0,
  "reason": "...",
  "recommended_action": "..."}}""",

"report_writer": """You are a professional security report writer.
Write a clear, concise finding description for a bug bounty report.

Finding:
  Type: {vuln_type}
  URL: {url}
  Evidence: {detail}
  Severity: {severity}
  Confidence: {confidence}

Respond ONLY with JSON:
{{"title": "...",
  "description": "...",
  "impact": "...",
  "reproduction": "...",
  "recommendation": "..."}}""",

"prioritizer": """You are a bug bounty prioritization advisor.
Given these findings, rank the top 3 by exploitation value.

Findings: {findings_json}

Respond ONLY with JSON array:
[{{"rank": 1, "vuln_type": "...", "url": "...", "reason": "..."}}]""",

}

class PromptRouter:
    """
    Blueprint Phase 5: Role-based AI prompt routing.
    Each role gets a specific structured prompt and expected JSON schema.
    Low temperature. Structured output only. No free-form text.
    """

    TEMPERATURE_MAP = {
        "summarizer"   : 0.1,
        "risk_scorer"  : 0.0,
        "verifier"     : 0.0,
        "report_writer": 0.2,
        "prioritizer"  : 0.1,
    }

    def __init__(self, ai_client=None, log=None):
        self._ai  = ai_client
        self.log  = log
        self._ready = ai_client is not None

    def route(self, role: str, context: dict) -> dict:
        """
        Route a finding to the correct AI role.
        Returns structured JSON dict always — never raw text.
        """
        if not self._ready:
            return {"error": "AI not available", "role": role}

        template = PROMPTS.get(role)
        if not template:
            return {"error": f"Unknown role: {role}"}

        try:
            prompt = template.format(**{
                k: context.get(k, "") for k in self._extract_keys(template)
            })
            temp   = self.TEMPERATURE_MAP.get(role, 0.1)
            raw    = self._ai.query(prompt, temperature=temp, max_tokens=512)
            result = self._parse_json(raw)
            result["_role"]    = role
            result["_success"] = "error" not in result
            return result
        except Exception as e:
            get_handler().capture("prompt_router", e, f"route:{role}")
            return {"error": str(e), "role": role, "_success": False}

    def summarize(self, finding: dict) -> dict:
        return self.route("summarizer", finding)

    def score_risk(self, finding: dict) -> dict:
        return self.route("risk_scorer", finding)

    def verify(self, finding: dict) -> dict:
        return self.route("verifier", finding)

    def write_report(self, finding: dict) -> dict:
        return self.route("report_writer", finding)

    def prioritize(self, findings: list) -> list:
        ctx = {"findings_json": json.dumps(findings[:10], indent=2)}
        result = self.route("prioritizer", ctx)
        return result if isinstance(result, list) else result.get("data", [])

    @staticmethod
    def _extract_keys(template: str) -> list:
        return re.findall(r'\{(\w+)\}', template)

    @staticmethod
    def _parse_json(text: str) -> dict | list:
        if not text:
            return {"error": "empty_response"}
        try:
            # Try direct parse
            clean = text.strip()
            if clean.startswith("```"):
                clean = re.sub(r"```\w*\n?", "", clean).strip()
            return json.loads(clean)
        except Exception:
            pass
        # Try to extract JSON block
        m = re.search(r'[\[{].*[\]}]', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
        return {"error": "parse_failed", "raw": text[:200]}
