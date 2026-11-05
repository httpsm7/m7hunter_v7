#!/usr/bin/env python3
# ai/autonomous_brain.py — M7Hunter Autonomous AI Decision Engine
# AI-Cycle 4: Strategic scan decisions based on recon + findings
# Decides module priority, chains attacks, adapts strategy
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, sys, re, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List, Optional, Tuple

# ── Tech stack → high-value modules ──────────────────────────────────────────
TECH_MODULE_MAP = {
    "wordpress":  ["wpscan","xss","sqli","lfi","file_upload","content"],
    "react":      ["xss_advanced","dom_xss","cors","ssrf","idor"],
    "angular":    ["xss_advanced","cors","ssti","idor"],
    "django":     ["ssti","sqli","csrf","session_fixation","idor"],
    "rails":      ["ssti","sqli","csrf","session_fixation"],
    "laravel":    ["sqli","lfi","file_upload","ssti"],
    "spring":     ["ssti","xxe","actuator","smuggling"],
    "graphql":    ["graphql","idor","nosql","sqli"],
    "nodejs":     ["nosql","proto_pollution","ssti","xss_advanced"],
    "php":        ["sqli","lfi","file_upload","xxe","ssti"],
    "java":       ["xxe","ssti","deserialization","smuggling"],
    "python":     ["ssti","deserialization","ssrf","idor"],
    "aws":        ["ssrf","s3_enum","iam_roles","recon_deep"],
    "gcp":        ["ssrf","recon_deep"],
    "azure":      ["ssrf","recon_deep"],
    "mysql":      ["sqli","nosql"],
    "mongodb":    ["nosql","idor"],
    "redis":      ["ssrf","rce"],
    "elasticsearch":["ssrf","exposed_service"],
}

# ── Finding → chain attack map ────────────────────────────────────────────────
FINDING_CHAINS = {
    # XSS confirmed → try session hijack, stored XSS, CSRF
    "XSS":          ["csrf","session_fixation","xss_advanced"],
    # SQLi confirmed → try data extraction, auth bypass, IDOR
    "SQLI":         ["idor","hashcrack","business_logic"],
    # SSRF confirmed → try cloud metadata, internal port scan, RCE
    "SSRF":         ["recon_deep","cve_exploit"],
    # LFI confirmed → try log poisoning, RCE chain
    "LFI":          ["cve_exploit"],
    # SSTI confirmed → skip to direct RCE attempt
    "SSTI":         ["cve_exploit"],
    # Subdomain takeover → phishing + stored XSS setup
    "SUBDOMAIN_TAKEOVER": ["xss","clickjacking"],
    # IDOR confirmed → try mass assignment, privilege escalation
    "IDOR":         ["business_logic","session_fixation"],
    # S3 public → check for backup files, credentials
    "S3_PUBLIC":    ["content","github"],
    # Hash found → try crack
    "HASH_EXPOSED": ["hashcrack"],
    # Default creds → try privilege escalation
    "DEFAULT_CREDENTIALS": ["idor","business_logic","api_security"],
    # Open redirect → chain to OAuth token theft
    "OPEN_REDIRECT": ["oauth","ssrf"],
    # JWT issue → try privilege escalation
    "JWT_ALG_NONE": ["idor","business_logic"],
}

# ── Recon signals → attack priority ──────────────────────────────────────────
RECON_SIGNALS = {
    "has_login":        ["sqli","xss","csrf","2fa_bypass","session_fixation"],
    "has_api":          ["idor","api_security","graphql","nosql","sqli"],
    "has_upload":       ["file_upload","xss_advanced"],
    "has_admin":        ["sqli","idor","business_logic","api_security"],
    "has_payment":      ["business_logic","idor","sqli"],
    "has_oauth":        ["oauth","cors","xss"],
    "has_graphql":      ["graphql","idor","nosql"],
    "has_websocket":    ["ws","sop_bypass"],
    "has_s3":           ["recon_deep","content"],
    "has_jwt":          ["jwt"],
}

# ── Severity-based priority multipliers ──────────────────────────────────────
PRIORITY_BASE = {
    "critical": 100,
    "high":      70,
    "medium":    40,
    "low":       10,
    "info":       1,
}


class AutonomousBrain:
    """
    M7Hunter Autonomous AI Decision Engine.
    AI-Cycle 4:
    1. Analyze recon data → decide which modules to prioritize
    2. Chain attacks from confirmed findings
    3. Adapt scan strategy based on tech stack
    4. Generate attack narrative for reporting
    5. Score attack surface intelligently
    """

    def __init__(self, ollama_ai=None, trainer=None,
                 payload_gen=None, log=None):
        self.ollama      = ollama_ai
        self.trainer     = trainer
        self.payload_gen = payload_gen
        self.log         = log
        self._decisions  = []
        self._chains     = []

    # ── Decision 1: Prioritize modules from recon ─────────────────────────────
    def prioritize_modules(self, recon_data: dict,
                            all_modules: List[str]) -> List[str]:
        """
        Analyze recon data and return ordered module list.
        High-priority modules run first.
        """
        scores: Dict[str, int] = {m: 50 for m in all_modules}  # base score

        # Score from tech stack
        tech = recon_data.get("tech_stack", {})
        frameworks = tech.get("frameworks", [])
        db         = tech.get("db", "")
        waf        = tech.get("waf", "")

        for fw in frameworks:
            for module in TECH_MODULE_MAP.get(fw.lower(), []):
                if module in scores:
                    scores[module] += 30
                    self._log_decision(
                        f"Tech '{fw}' → boost {module} (+30)")

        if db:
            for module in TECH_MODULE_MAP.get(db.lower(), []):
                if module in scores:
                    scores[module] += 25

        # Score from URL/content signals
        signals = recon_data.get("signals", {})
        for signal, modules in RECON_SIGNALS.items():
            if signals.get(signal):
                for m in modules:
                    if m in scores:
                        scores[m] += 20
                        self._log_decision(
                            f"Signal '{signal}' → boost {m} (+20)")

        # WAF detected → boost WAF-bypass modules
        if waf:
            for m in ["xss_advanced","xss","waf_bypass_test"]:
                if m in scores:
                    scores[m] += 15

        # Always run fast recon first
        for m in ["subdomain","dns","probe","ports","crawl","nuclei"]:
            if m in scores:
                scores[m] = 999

        # Sort by score
        ordered = sorted(all_modules,
                         key=lambda m: scores.get(m, 0), reverse=True)
        return ordered

    # ── Decision 2: Chain attacks from findings ───────────────────────────────
    def get_chains(self, findings: list) -> List[Tuple[str, str, str]]:
        """
        Return chain steps to run based on confirmed findings.
        Returns: [(module_to_run, reason, priority)]
        """
        chains   = []
        seen_mods= set()

        for finding in findings:
            if finding.get("status") not in ("confirmed","critical"):
                continue
            vt = finding.get("vuln_type","").upper().split("_")[0]
            chain_mods = FINDING_CHAINS.get(vt, [])

            for module in chain_mods:
                if module not in seen_mods:
                    seen_mods.add(module)
                    reason = (f"{vt} confirmed at {finding.get('url','')[:50]} "
                              f"→ chain {module}")
                    prio   = ("critical" if vt in ("RCE","SQLI","SSTI","SSRF")
                              else "high")
                    chains.append((module, reason, prio))
                    self._chains.append({"trigger": vt, "chain": module,
                                          "reason": reason})
                    self._log_decision(f"Chain: {vt} → {module}")

        return chains

    # ── Decision 3: Adapt payload strategy ───────────────────────────────────
    def adapt_payloads(self, vuln_type: str, failed_payloads: List[str],
                        tech_stack: dict) -> List[str]:
        """
        When payloads fail, adapt strategy.
        Switch context, try WAF bypasses, use AI generation.
        """
        if not self.payload_gen:
            return []

        waf = tech_stack.get("waf","")
        csp = tech_stack.get("csp","")
        fws = tech_stack.get("frameworks",[])

        if vuln_type.upper() == "XSS":
            # If html context failed → try attr/js
            ctx = "waf_bypass" if waf else "attr"
            return self.payload_gen.generate_xss_payloads(
                fws, waf, csp, ctx)
        elif vuln_type.upper() == "SSRF":
            cloud = tech_stack.get("cloud","generic")
            return self.payload_gen.generate_ssrf_payloads(
                cloud, failed_payloads, "url")
        return []

    # ── Decision 4: Scan strategy ─────────────────────────────────────────────
    def decide_scan_depth(self, findings_so_far: list,
                           elapsed_minutes: float) -> dict:
        """
        Decide whether to deepen, pivot, or conclude scan.
        """
        critical_count = sum(
            1 for f in findings_so_far
            if f.get("severity") in ("critical","high")
        )
        total = len(findings_so_far)

        decision = {
            "action":    "continue",
            "reason":    "",
            "next_focus": [],
        }

        # Many critical finds → go deeper on this target
        if critical_count >= 3:
            decision["action"]     = "deepen"
            decision["reason"]     = (f"{critical_count} critical findings — "
                                       f"deepen exploitation chains")
            decision["next_focus"] = ["cve_exploit","business_logic","idor"]

        # No finds after 30min → pivot strategy
        elif total == 0 and elapsed_minutes > 30:
            decision["action"]     = "pivot"
            decision["reason"]     = "No findings after 30min — pivoting strategy"
            decision["next_focus"] = ["content","github","recon_deep",
                                       "api_security"]

        # Good finds, time running out → focus on high-value
        elif elapsed_minutes > 90 and total > 0:
            decision["action"]     = "focus"
            decision["reason"]     = "90min elapsed — focusing on confirmed findings"
            decision["next_focus"] = ["cve_exploit","hashcrack"]

        self._log_decision(f"Scan depth: {decision['action']} — {decision['reason']}")
        return decision

    # ── Decision 5: Attack narrative ──────────────────────────────────────────
    def generate_narrative(self, findings: list, target: str) -> str:
        """Generate attack chain narrative for executive report."""
        if not findings:
            return f"No significant vulnerabilities found on {target}."

        sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        sorted_f  = sorted(findings,
                           key=lambda x: sev_order.get(x.get("severity","info"),4))

        narrative = [f"Security assessment of {target} identified the following attack vectors:\n"]

        # Attack path 1: The worst finding
        if sorted_f:
            worst = sorted_f[0]
            narrative.append(
                f"1. CRITICAL RISK: {worst.get('vuln_type','')} vulnerability "
                f"at {worst.get('url','')[:60]} — {worst.get('detail','')[:80]}")

        # Look for chains
        vuln_types = [f.get("vuln_type","").upper() for f in sorted_f]
        if "XSS" in vuln_types and "IDOR" in vuln_types:
            narrative.append(
                "2. ATTACK CHAIN: XSS + IDOR combination enables "
                "complete account takeover without user interaction")
        if "SQLI" in vuln_types:
            narrative.append(
                "3. DATA BREACH RISK: SQL injection enables full "
                "database exfiltration including user credentials")
        if "SSRF" in vuln_types:
            narrative.append(
                "4. CLOUD PIVOT: SSRF enables access to cloud metadata, "
                "potentially compromising entire cloud infrastructure")

        # Use Ollama for richer narrative if available
        if self.ollama and self.ollama.is_available() and len(findings) > 0:
            try:
                prompt = (
                    f"Write a 2-sentence executive summary of these "
                    f"security findings for {target}: "
                    f"{json.dumps([{k:v for k,v in f.items() if k in ('vuln_type','severity','url')} for f in sorted_f[:5]])}"
                    f". Be concise and businesslike. No technical jargon."
                )
                ollama_narrative = self.ollama._query_ollama(prompt)
                if ollama_narrative and len(ollama_narrative) > 20:
                    narrative.append(f"\nExecutive Summary: {ollama_narrative.strip()}")
            except Exception:
                pass

        return "\n".join(narrative)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _log_decision(self, msg: str):
        entry = {"time": time.strftime("%H:%M:%S"), "decision": msg}
        self._decisions.append(entry)
        if self.log:
            self.log.info(f"  [Brain] {msg}")

    def get_decision_log(self) -> list:
        return self._decisions

    def get_chain_log(self) -> list:
        return self._chains

    def get_summary(self) -> str:
        return (f"AI Brain: {len(self._decisions)} decisions | "
                f"{len(self._chains)} chains triggered")


if __name__ == "__main__":
    brain = AutonomousBrain()

    # Test module prioritization
    recon = {
        "tech_stack": {
            "frameworks": ["react","django"],
            "db":          "postgresql",
            "waf":         "cloudflare",
        },
        "signals": {
            "has_api":     True,
            "has_login":   True,
            "has_payment": True,
        }
    }
    modules = ["xss","sqli","nosql","graphql","idor","business_logic",
               "api_security","ssti","jwt","nuclei","takeover"]
    ordered = brain.prioritize_modules(recon, modules)
    print("Module priority order:")
    for m in ordered[:6]:
        print(f"  → {m}")

    # Test chain decisions
    findings = [
        {"vuln_type":"XSS","status":"confirmed","severity":"high",
         "url":"https://target.com/search"},
        {"vuln_type":"IDOR","status":"confirmed","severity":"critical",
         "url":"https://target.com/api/user/1337"},
    ]
    chains = brain.get_chains(findings)
    print(f"\nChains triggered ({len(chains)}):")
    for module, reason, prio in chains:
        print(f"  [{prio}] → {module}: {reason[:50]}")

    # Test narrative
    narrative = brain.generate_narrative(findings, "target.com")
    print(f"\nNarrative:\n{narrative}")
    print(f"\n{brain.get_summary()}")
