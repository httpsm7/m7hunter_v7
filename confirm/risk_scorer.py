#!/usr/bin/env python3
# confirm/risk_scorer.py — CVSS-like Risk Scorer
# MilkyWay Intelligence | Author: Sharlix

EXPLOITABILITY = {
    "SQLI":9.5,"CMDI":9.5,"SSTI":9.5,"SSRF":8.6,"XXE":8.0,"LFI":8.0,
    "XSS":8.2,"IDOR":7.8,"TAKEOVER":8.5,"JWT":7.5,"CORS":6.8,
    "REDIRECT":6.1,"SMUGGLING":8.0,"GRAPHQL":7.0,"HOST_HEADER":7.0,
    "CSRF":6.5,"RACE":7.0,"NOSQL":8.5,"PROTO":6.5,"WS":6.0,
    "DEFAULT":5.0,
}

IMPACT = {
    "SQLI":9.8,"CMDI":9.8,"SSTI":9.8,"SSRF":8.6,"XXE":7.5,"LFI":7.5,
    "XSS":8.2,"IDOR":8.1,"TAKEOVER":9.1,"JWT":7.4,"CORS":7.1,
    "REDIRECT":6.1,"SMUGGLING":8.0,"CSRF":7.0,"RACE":7.5,
    "NOSQL":9.0,"DEFAULT":5.0,
}

SEV_WEIGHTS = {
    "critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2
}

TOOL_AUTO_TRUST = {
    "sqlmap": 0.95, "dalfox": 0.90, "nuclei": 0.80,
    "subzy":  0.90, "interactsh": 0.85,
}


class RiskScorer:
    def score(self, finding: dict) -> dict:
        vt       = (finding.get("type") or finding.get("vuln_type","DEFAULT"))
        vt_key   = vt.split("_")[0].upper()
        sev      = finding.get("severity","medium").lower()
        conf     = finding.get("confidence", 0.5)
        stat     = finding.get("status","potential")
        tool     = finding.get("tool","")

        exploit  = EXPLOITABILITY.get(vt_key, EXPLOITABILITY["DEFAULT"])
        impact   = IMPACT.get(vt_key, IMPACT["DEFAULT"])
        sw       = SEV_WEIGHTS.get(sev, 0.6)
        auto_trust = TOOL_AUTO_TRUST.get(tool, 0.60)
        mult     = 1.0 if stat == "confirmed" else 0.7

        total = (
            exploit     * sw * 0.30 +
            impact      * sw * 0.35 +
            conf * 10   * 0.20 +
            auto_trust  * 10 * 0.15
        ) * mult

        total = round(min(total, 10.0), 2)
        band  = (
            "Critical" if total >= 9.0 else
            "High"     if total >= 7.0 else
            "Medium"   if total >= 4.0 else
            "Low"
        )
        return {"total": total, "band": band}
