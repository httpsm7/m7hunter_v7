#!/usr/bin/env python3
# ai/risk_engine.py — Structured Risk Analysis Engine
# Blueprint 5.5: Predictable JSON output, no free-text parsing
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import json
from confirm.risk_scorer import EXPLOITABILITY, IMPACT
from core.error_handler  import get_handler

SEVERITY_THRESHOLDS = {"critical": 8.0, "high": 6.0, "medium": 4.0, "low": 2.0}

MANDATORY_OUTPUT = {
    "finding"        : "",
    "confidence"     : 0.0,
    "severity"       : "info",
    "verification"   : "unverified",
    "recommendation" : "",
}

class RiskEngine:
    """
    Blueprint 5.5 — Required output format:
    {
      "finding": "",
      "confidence": 0.0,
      "severity": "",
      "verification": "",
      "recommendation": ""
    }
    Free-text parsing MUST NOT be used.
    """

    RECOMMENDATIONS = {
        "critical": "Immediate remediation — escalate now, stop production if exploitable",
        "high"    : "Remediate within 7 days — include in current sprint",
        "medium"  : "Remediate within 30 days — add to security backlog",
        "low"     : "Remediate within 90 days — track in issue tracker",
        "info"    : "Consider fixing in next maintenance cycle",
    }

    VERIFICATION_MAP = {
        "confirmed"    : "double_verified",
        "potential"    : "single_signal",
        "noise"        : "unverified",
    }

    def __init__(self, router=None):
        self._router = router

    def evaluate(self, finding: dict) -> dict:
        """
        Evaluate a finding and return mandatory JSON output.
        Never raises — always returns structured dict.
        """
        try:
            vuln_type  = finding.get("vuln_type", "UNKNOWN").upper()
            confidence = float(finding.get("confidence", 0.5))
            url        = finding.get("url", "")
            detail     = finding.get("detail", "")

            # CVSS-style score
            ex_score   = EXPLOITABILITY.get(vuln_type, 5.0)
            im_score   = IMPACT.get(vuln_type, 5.0)
            cvss       = round((ex_score * im_score * confidence) / 10, 2)
            severity   = self._severity(cvss)

            # Confidence verdict
            verdict    = self._confidence_verdict(confidence)
            verification = self.VERIFICATION_MAP.get(verdict, "unverified")

            # AI enhancement if router available
            ai_result  = {}
            if self._router and 0.50 <= confidence <= 0.84:
                try:
                    ai_result = self._router.score_risk(finding)
                    if ai_result.get("_success") and ai_result.get("severity"):
                        severity = ai_result["severity"]
                    if ai_result.get("confidence_adjusted", 0) > 0:
                        confidence = (confidence + ai_result["confidence_adjusted"]) / 2
                except Exception as e:
                    get_handler().capture("risk_engine", e, "ai_enhance")

            result = {
                **MANDATORY_OUTPUT,
                "finding"       : f"{vuln_type} at {url[:80]}",
                "confidence"    : round(confidence, 3),
                "severity"      : severity,
                "verification"  : verification,
                "recommendation": self.RECOMMENDATIONS.get(severity, "Review required"),
                "cvss_estimate" : cvss,
                "exploit_score" : ex_score,
                "impact_score"  : im_score,
                "detail"        : detail[:200],
                "vuln_type"     : vuln_type,
                "url"           : url,
                "ai_enhanced"   : bool(ai_result.get("_success")),
            }
            return result

        except Exception as e:
            get_handler().capture("risk_engine", e, "evaluate")
            return {
                **MANDATORY_OUTPUT,
                "error": str(e),
                "finding": finding.get("vuln_type","?") + " at " + finding.get("url","?")[:60],
            }

    def evaluate_batch(self, findings: list) -> list:
        return [self.evaluate(f) for f in findings]

    def top_critical(self, findings: list, n: int = 5) -> list:
        scored = self.evaluate_batch(findings)
        critical = [s for s in scored if s["severity"] in ("critical","high")]
        return sorted(critical, key=lambda s: s["cvss_estimate"], reverse=True)[:n]

    def deduplicate(self, findings: list) -> list:
        """Remove duplicate findings by URL+type combination."""
        seen   = set()
        unique = []
        for f in findings:
            key = f"{f.get('vuln_type','')}:{f.get('url','')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _severity(cvss: float) -> str:
        for name, threshold in SEVERITY_THRESHOLDS.items():
            if cvss >= threshold:
                return name
        return "info"

    @staticmethod
    def _confidence_verdict(confidence: float) -> str:
        if confidence >= 0.85: return "confirmed"
        if confidence >= 0.50: return "potential"
        return "noise"
