#!/usr/bin/env python3
# ai/risk_model.py — Structured Risk Scoring Model
# Blueprint Phase 5: Confidence-based reasoning, structured JSON output
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import json
from dataclasses import dataclass, asdict
from confirm.risk_scorer import EXPLOITABILITY, IMPACT
from core.error_handler import get_handler

@dataclass
class RiskScore:
    vuln_type          : str
    url                : str
    severity           : str
    cvss_estimate      : float
    exploitability_score: float
    impact_score       : float
    confidence         : float
    confidence_grade   : str   # A/B/C/D/F
    business_impact    : str
    exploitability_ease: str   # easy/medium/hard
    recommended_action : str
    ai_verified        : bool  = False
    ai_verdict         : str   = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class RiskModel:
    """
    Blueprint Phase 5: Structured, predictable risk scoring.
    Combines static scoring with AI-assisted analysis.
    Low-temperature prompts. Structured JSON output always.
    """

    CONF_GRADES = [
        (0.95, "A+"), (0.90, "A"), (0.80, "B"),
        (0.70, "C"),  (0.55, "D"), (0.00, "F"),
    ]

    BUSINESS_IMPACT = {
        "critical": "Full system compromise, data breach, complete loss of confidentiality/integrity",
        "high"    : "Significant data exposure, privilege escalation, account takeover",
        "medium"  : "Partial data exposure, limited privilege escalation, session hijacking",
        "low"     : "Information disclosure, minor security bypass",
        "info"    : "Minimal direct impact, aids further reconnaissance",
    }

    EASE_MAP = {
        "critical": "easy",   "high"  : "easy",
        "medium"  : "medium", "low"   : "hard",
        "info"    : "hard",
    }

    ACTIONS = {
        "critical": "Immediate remediation required — escalate to security team now",
        "high"    : "Remediate within 7 days — prioritize in next sprint",
        "medium"  : "Remediate within 30 days — include in security backlog",
        "low"     : "Remediate within 90 days — track in issue tracker",
        "info"    : "Consider fixing in next maintenance cycle",
    }

    def __init__(self, prompt_router=None):
        self.router = prompt_router

    def score(self, finding: dict) -> RiskScore:
        vuln_type  = finding.get("vuln_type", "UNKNOWN")
        url        = finding.get("url", "")
        confidence = float(finding.get("confidence", 0.5))

        vt_upper = vuln_type.upper()
        ex_score = EXPLOITABILITY.get(vt_upper, 5.0)
        im_score = IMPACT.get(vt_upper, 5.0)
        raw_cvss = (ex_score * im_score * confidence) / 10

        severity = self._severity_from_cvss(raw_cvss)
        conf_grade = self._confidence_grade(confidence)

        # AI enhancement if router available
        ai_verified = False
        ai_verdict  = ""
        if self.router and confidence >= 0.50:
            try:
                ai_result = self.router.score_risk(finding)
                if ai_result.get("_success"):
                    ai_verified = True
                    ai_verdict  = ai_result.get("verdict", "")
                    # Blend AI severity if provided
                    ai_sev = ai_result.get("severity", "")
                    if ai_sev and ai_sev in self.BUSINESS_IMPACT:
                        severity = ai_sev
                    ai_conf = ai_result.get("confidence_adjusted", 0)
                    if ai_conf > 0:
                        confidence = (confidence + ai_conf) / 2
            except Exception as e:
                get_handler().capture("risk_model", e, "ai_score")

        return RiskScore(
            vuln_type           = vuln_type,
            url                 = url,
            severity            = severity,
            cvss_estimate       = round(raw_cvss, 2),
            exploitability_score= ex_score,
            impact_score        = im_score,
            confidence          = round(confidence, 3),
            confidence_grade    = conf_grade,
            business_impact     = self.BUSINESS_IMPACT.get(severity, "Unknown impact"),
            exploitability_ease = self.EASE_MAP.get(severity, "medium"),
            recommended_action  = self.ACTIONS.get(severity, "Review and remediate"),
            ai_verified         = ai_verified,
            ai_verdict          = ai_verdict,
        )

    def score_batch(self, findings: list) -> list[RiskScore]:
        return [self.score(f) for f in findings]

    def top_findings(self, findings: list, n: int = 10) -> list[RiskScore]:
        scored = self.score_batch(findings)
        return sorted(scored, key=lambda s: s.cvss_estimate, reverse=True)[:n]

    @staticmethod
    def _severity_from_cvss(score: float) -> str:
        if score >= 8.0: return "critical"
        if score >= 6.0: return "high"
        if score >= 4.0: return "medium"
        if score >= 2.0: return "low"
        return "info"

    def _confidence_grade(self, conf: float) -> str:
        for threshold, grade in self.CONF_GRADES:
            if conf >= threshold:
                return grade
        return "F"
