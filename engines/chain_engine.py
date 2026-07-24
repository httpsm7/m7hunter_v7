#!/usr/bin/env python3
# engines/chain_engine.py — Attack Chain Suggestion Engine v6
# Analyzes findings and suggests realistic attack chains
# MilkyWay Intelligence | Author: Sharlix

CHAIN_RULES = [
    # Rule: (trigger_vulns, suggested_chain, impact, severity_boost)
    {
        "triggers"   : {"IDOR", "IDOR_CONFIRMED"},
        "needs"      : {"password_reset", "email_change", "account_update"},
        "chain"      : "IDOR → Change victim email → Trigger password reset → Account Takeover",
        "impact"     : "Full account takeover",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"IDOR"},
        "needs"      : {"XSS"},
        "chain"      : "IDOR + Stored XSS → Inject payload into victim account → Session hijack",
        "impact"     : "Session hijack via victim's account",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"SSRF", "SSRF_AWS", "SSRF_GCP"},
        "needs"      : set(),
        "chain"      : "SSRF → Cloud Metadata → IAM Credentials → AWS/GCP Console Access",
        "impact"     : "Cloud infrastructure compromise",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"OPEN_REDIRECT"},
        "needs"      : {"oauth"},
        "chain"      : "Open Redirect → OAuth redirect_uri bypass → Access token theft",
        "impact"     : "OAuth account takeover",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"OPEN_REDIRECT", "CRLF_INJECTION"},
        "needs"      : set(),
        "chain"      : "Open Redirect + CRLF → Cache Poisoning → Mass phishing via trusted domain",
        "impact"     : "Mass credential phishing using target's domain",
        "severity"   : "high",
    },
    {
        "triggers"   : {"CORS_MISCONFIG"},
        "needs"      : set(),
        "chain"      : "CORS misconfiguration → Read authenticated API responses from evil.com",
        "impact"     : "Cross-origin data theft from victim sessions",
        "severity"   : "high",
    },
    {
        "triggers"   : {"LFI", "LFI_UNIX_PASSWD"},
        "needs"      : set(),
        "chain"      : "LFI → /proc/self/environ → Log poisoning via User-Agent → RCE",
        "impact"     : "Remote code execution via LFI chain",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"NOSQL_INJECTION"},
        "needs"      : set(),
        "chain"      : "NoSQL Auth Bypass → Admin access → Full data exfiltration",
        "impact"     : "Authentication bypass and database dump",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"XSS"},
        "needs"      : {"csrf"},
        "chain"      : "XSS + CSRF bypass → Force victim to perform sensitive actions",
        "impact"     : "Forced account actions (transfer, delete, change settings)",
        "severity"   : "high",
    },
    {
        "triggers"   : {"HTTP_SMUGGLING_CLTE", "HTTP_SMUGGLING_TECL"},
        "needs"      : set(),
        "chain"      : "Request Smuggling → Poison front-end cache → Steal victim requests/cookies",
        "impact"     : "Session hijack of other users via smuggled requests",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"SUBDOMAIN_TAKEOVER"},
        "needs"      : set(),
        "chain"      : "Subdomain Takeover → Host malicious content under trusted domain → Phishing",
        "impact"     : "Phishing / malware distribution under target's brand",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"GITHUB_EXPOSURE"},
        "needs"      : set(),
        "chain"      : "GitHub Leak → Credentials/API keys → Direct system access",
        "impact"     : "Direct authentication with exposed credentials",
        "severity"   : "critical",
    },
    {
        "triggers"   : {"JWT_ALG_NONE_BYPASS", "JWT_WEAK_SECRET"},
        "needs"      : set(),
        "chain"      : "JWT Bypass → Forge admin token → Privilege escalation → Account takeover",
        "impact"     : "Admin access via forged JWT",
        "severity"   : "critical",
    },
]


class ChainEngine:
    """
    Analyzes a set of findings and suggests attack chains.
    High-value for bug bounty reports — shows escalation potential.
    """

    def analyze(self, findings: list) -> list:
        """
        Given a list of findings, suggest attack chains.
        Returns list of chain suggestions sorted by impact.
        """
        vuln_types = {f.get("vuln_type","").upper() for f in findings}
        urls       = {f.get("url","") for f in findings}
        url_content = " ".join(urls).lower()

        suggestions = []

        for rule in CHAIN_RULES:
            # Check if any trigger vulnerability is present
            if not any(t in vuln_types for t in rule["triggers"]):
                continue

            # Check if "needs" context exists in URLs (loose check)
            needs_ok = not rule["needs"] or any(
                n in url_content for n in rule.get("needs",set())
            )

            # If needs not satisfied, still suggest but mark as "potential chain"
            confidence = "confirmed" if needs_ok else "potential"

            # Find the triggering finding(s)
            trigger_findings = [
                f for f in findings
                if f.get("vuln_type","").upper() in rule["triggers"]
            ]

            suggestions.append({
                "chain"           : rule["chain"],
                "impact"          : rule["impact"],
                "severity"        : rule["severity"],
                "confidence"      : confidence,
                "trigger_vulns"   : [f.get("vuln_type","") for f in trigger_findings[:2]],
                "trigger_urls"    : [f.get("url","") for f in trigger_findings[:2]],
                "needs_additional": list(rule.get("needs",set())),
            })

        # Sort: confirmed first, then by severity
        sev_order = {"critical":0,"high":1,"medium":2}
        conf_order = {"confirmed":0,"potential":1}
        suggestions.sort(key=lambda x: (
            conf_order.get(x["confidence"],1),
            sev_order.get(x["severity"],2)
        ))

        return suggestions

    def format_for_report(self, findings: list) -> str:
        """Format chain suggestions as markdown text."""
        chains = self.analyze(findings)
        if not chains:
            return ""

        lines = ["## ⛓️ Attack Chain Analysis\n"]
        for i, chain in enumerate(chains[:6], 1):
            conf_icon = "✅" if chain["confidence"] == "confirmed" else "⚠️"
            lines.append(f"### Chain {i}: {chain['severity'].upper()} {conf_icon}")
            lines.append(f"**Path:** {chain['chain']}")
            lines.append(f"**Impact:** {chain['impact']}")
            if chain["trigger_urls"]:
                lines.append(f"**Starting point:** `{chain['trigger_urls'][0][:80]}`")
            if chain["needs_additional"]:
                lines.append(f"**Needs:** Find {', '.join(chain['needs_additional'])} endpoint")
            lines.append("")

        return "\n".join(lines)
