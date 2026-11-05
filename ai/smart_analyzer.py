#!/usr/bin/env python3
# ai/smart_analyzer.py — Smart Per-Vulnerability Analyzer
# AI-Cycle 2: specialized analysis per vuln type + confidence calibration
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, time
from typing import Optional

# ── Per-vulnerability specialized system prompts ──────────────────────────────
VULN_PROMPTS = {
    "XSS": """You are an expert XSS analyst trained on 665 XSS payloads.
Confirm XSS ONLY if: payload reflected UNENCODED in HTML/JS/attr context.
REJECT if: &lt; encoding present, payload in comment, response is JSON, CSP blocks inline.
Context types: HTML body, attribute value, JS string, URL, CSS — each has different rules.
Blind XSS: confirmed only if OOB callback received.""",

    "SQLI": """You are an expert SQL injection analyst.
Confirm SQLi if: DB error message present, time delay measured (>4.5s for SLEEP(5)),
boolean condition changes response length significantly (>100 bytes diff).
DB types: MySQL (syntax error), MSSQL (Unclosed quotation), Oracle (ORA-), PostgreSQL (pg_query).
Union-based: confirmed if extra column data appears in response.""",

    "SSRF": """You are an expert SSRF analyst trained on cloud environments.
Confirm SSRF ONLY if: cloud metadata returned (ami-id/AccessKeyId/computeMetadata),
internal service data returned (Redis version, Elasticsearch cluster info),
or OOB DNS/HTTP callback received.
REJECT if: connection refused, timeout, generic error, WAF block.""",

    "SSTI": """You are an expert SSTI analyst for 8 template engines.
Confirm SSTI if: math expression evaluated (7*7=49, {{7*7}} returns 49),
or 7777777 appears (multiplication result), or RCE output (uid=).
Engines: Jinja2={{7*'7'}}→7777777, FreeMarker=${7*7}→49, Twig={{'7'*7}}→7777777.
REJECT if: expression returned literally without evaluation.""",

    "IDOR": """You are an expert IDOR/BOLA analyst.
Confirm IDOR if: different user's personal data returned (email, phone, private data),
or admin data accessible to regular user, or multi-session confirms data crossing.
REJECT if: same data returned for all IDs, 403/404 on other IDs.""",

    "JWT": """You are an expert JWT security analyst.
Confirm if: alg:none token accepted (200 response), weak secret cracked,
RS256→HS256 confusion accepted, expired token still valid.
Check: response code change from 401 to 200, user data returned with forged token.""",

    "LFI": """You are an expert LFI analyst.
Confirm if: /etc/passwd content (root:x:0:0), Windows files (win.ini, boot.ini),
PHP source code exposed, log file content returned.
Log poisoning confirmed: PHP code executed in log, id command output.""",

    "GRAPHQL": """You are an expert GraphQL security analyst.
Confirm if: introspection returns full schema, IDOR returns other user data,
mutations execute without auth, alias batching bypasses rate limits.
Field suggestions: server reveals valid field names in error.""",

    "NOSQL": """You are an expert NoSQL injection analyst.
Confirm auth bypass if: 200 returned with user data for $ne/$gt/$regex operator.
Blind: time delay >4.5s with $where sleep confirms injection.
REJECT if: operator syntax error, query format error, 400 status.""",

    "DEFAULT": """You are an expert security analyst.
Analyze the response carefully. Confirm only with strong evidence.
Consider: response status change, data leakage, error messages, timing.""",
}

# ── Confidence calibration weights by evidence type ───────────────────────────
EVIDENCE_WEIGHTS = {
    "status_200_from_401": +0.20,   # auth bypass
    "db_error_present":    +0.40,   # SQLi
    "payload_unencoded":   +0.35,   # XSS
    "cloud_metadata":      +0.50,   # SSRF critical
    "math_evaluated":      +0.40,   # SSTI
    "time_delay_5s":       +0.40,   # blind SQLi/NoSQL
    "personal_data":       +0.30,   # IDOR
    "file_content":        +0.40,   # LFI
    "rce_output":          +0.50,   # RCE
    "waf_encoded":         -0.30,   # FP
    "generic_error":       -0.15,   # FP
    "timeout_error":       -0.20,   # FP
    "connection_refused":  -0.25,   # FP
}

# ── Quick pattern checks ──────────────────────────────────────────────────────
QUICK_CONFIRM = {
    "XSS":    [r'<svg[^>]*onload\s*=', r'onerror\s*=\s*alert', r'<script>alert'],
    "SQLI":   [r'sql syntax.*mariadb', r'ora-\d+', r'pg_query\(\)',
               r'mssql.*driver', r'sqlstate\['],
    "SSRF":   [r'ami-id', r'accesskeyid', r'computemetadata',
               r'redis_version', r'"id":\s*"\d+"'],
    "SSTI":   [r'\b49\b', r'7777777', r'uid=\d+\('],
    "LFI":    [r'root:x:0:0', r'daemon:x:\d+', r'begin rsa private'],
    "NOSQL":  [r'"role"\s*:\s*"admin"', r'"isAdmin"\s*:\s*true'],
    "JWT":    [r'"id"\s*:\s*\d+', r'"email"\s*:', r'"role"\s*:'],
}

QUICK_FP = {
    "XSS":    [r'&lt;svg', r'&amp;lt;', r'%3csvg', r'\\u003c',
               r'content-security-policy.*script-src.*none'],
    "SQLI":   [r'please enter a valid', r'invalid input format'],
    "SSRF":   [r'connection refused', r'no route to host',
               r'network unreachable', r'connection timed out'],
    "SSTI":   [r'\{\{7\*7\}\}', r'\$\{7\*7\}'],  # literal not evaluated
    "LFI":    [r'file not found', r'no such file', r'permission denied'],
}


class SmartAnalyzer:
    """
    Smart per-vulnerability analyzer.
    AI-Cycle 2:
    - Uses specialized prompts per vuln type
    - Quick pattern check before Ollama (saves API calls)
    - Confidence calibration from evidence
    - Integrates with AITrainer for learned patterns
    """

    def __init__(self, ollama_ai=None, trainer=None, log=None):
        self.ollama  = ollama_ai
        self.trainer = trainer
        self.log     = log
        self._stats  = {"analyzed": 0, "quick_confirmed": 0,
                        "quick_fp": 0, "ollama_used": 0}

    def analyze(self, vuln_type: str, url: str, response: str,
                 payload: str = "", baseline_len: int = 0,
                 status: int = 200, elapsed: float = 0.0) -> dict:
        """
        Full smart analysis pipeline:
        1. Quick pattern check (instant, no API call)
        2. Evidence scoring
        3. Trainer confidence adjustment
        4. Ollama deep analysis (if still uncertain)
        """
        self._stats["analyzed"] += 1
        vt = vuln_type.upper().split("_")[0]

        # ── Step 1: Quick pattern check ───────────────────────────────────────
        quick = self._quick_check(vt, response, status, elapsed)
        if quick["verdict"] in ("confirmed","false_positive"):
            self._stats[f"quick_{quick['verdict'].replace('false_positive','fp')}"] += 1
            return quick

        # ── Step 2: Evidence scoring ──────────────────────────────────────────
        base_conf = self._score_evidence(vt, response, status, payload,
                                          baseline_len, elapsed)

        # ── Step 3: Trainer pattern adjustment ───────────────────────────────
        if self.trainer:
            adjustment = self.trainer.get_confidence_adjustment(vt, response)
            base_conf  = max(0.0, min(1.0, base_conf + adjustment))

        # ── Step 4: Ollama deep analysis (if uncertain 0.3-0.75) ─────────────
        if self.ollama and self.ollama.is_available() and 0.30 < base_conf < 0.75:
            self._stats["ollama_used"] += 1
            ollama_result = self._ollama_analyze(vt, url, response, payload,
                                                   baseline_len, status)
            if ollama_result:
                # Blend Ollama confidence with evidence scoring
                blend = (base_conf * 0.4) + (ollama_result["confidence"] * 0.6)
                return {
                    "verdict":    ollama_result["verdict"],
                    "confidence": round(blend, 3),
                    "reason":     f"Ollama+Evidence: {ollama_result['reason']}",
                    "severity":   ollama_result.get("severity","medium"),
                    "method":     "ollama_blend",
                }

        # ── Step 5: Verdict from evidence score alone ─────────────────────────
        if base_conf >= 0.75:
            verdict = "confirmed"
        elif base_conf <= 0.25:
            verdict = "false_positive"
        else:
            verdict = "potential"

        return {
            "verdict":    verdict,
            "confidence": round(base_conf, 3),
            "reason":     f"Evidence score ({vt})",
            "severity":   self._get_severity(vt, verdict),
            "method":     "evidence_scoring",
        }

    # ── Quick pattern check ───────────────────────────────────────────────────
    def _quick_check(self, vt: str, response: str,
                      status: int, elapsed: float) -> dict:
        body_lower = response.lower()

        # Check FP patterns first
        for pat in QUICK_FP.get(vt,[]):
            if re.search(pat, body_lower, re.I):
                return {"verdict":"false_positive","confidence":0.88,
                        "reason":f"Quick FP: pattern '{pat}' matched",
                        "severity":"info","method":"quick_fp"}

        # Check confirmed patterns
        for pat in QUICK_CONFIRM.get(vt,[]):
            if re.search(pat, body_lower, re.I):
                return {"verdict":"confirmed","confidence":0.92,
                        "reason":f"Quick confirm: pattern matched",
                        "severity":self._get_severity(vt,"confirmed"),
                        "method":"quick_confirm"}

        # Timing-based for blind SQLi/NoSQL
        if elapsed >= 4.5 and vt in ("SQLI","NOSQL","BLIND"):
            return {"verdict":"confirmed","confidence":0.87,
                    "reason":f"Time delay: {elapsed:.1f}s (expected 5s)",
                    "severity":"critical","method":"timing"}

        return {"verdict":"potential","confidence":0.50,
                "reason":"No quick match","severity":"medium","method":"pending"}

    # ── Evidence scoring ──────────────────────────────────────────────────────
    def _score_evidence(self, vt: str, response: str, status: int,
                         payload: str, baseline_len: int, elapsed: float) -> float:
        score = 0.40  # base neutral
        body  = response.lower()
        resp_len = len(response)

        # Status change (auth bypass indicator)
        if status == 200 and "401" in str(baseline_len):
            score += EVIDENCE_WEIGHTS["status_200_from_401"]

        # Length difference (content change)
        if baseline_len > 0:
            diff_ratio = abs(resp_len - baseline_len) / max(baseline_len, 1)
            if diff_ratio > 0.5:
                score += 0.10
            elif diff_ratio < 0.02:
                score -= 0.05  # barely changed = likely FP

        # Payload reflection (for XSS)
        if vt == "XSS" and payload.lower() in body:
            if not any(e in body for e in ["&lt;","&gt;","\\u003c","%3c"]):
                score += 0.30  # unencoded reflection

        # Error messages (SQLi)
        if vt == "SQLI":
            db_errors = ["syntax error","ora-","pg_query","sqlstate","mssql"]
            if any(e in body for e in db_errors):
                score += EVIDENCE_WEIGHTS["db_error_present"]

        # Cloud metadata (SSRF)
        if vt == "SSRF":
            cloud = ["ami-id","accesskeyid","computemetadata","service-accounts"]
            if any(c in body for c in cloud):
                score += EVIDENCE_WEIGHTS["cloud_metadata"]

        # FP indicators
        if any(e in body for e in ["&lt;","&amp;lt;","\\u003c"]):
            score += EVIDENCE_WEIGHTS["waf_encoded"]
        if any(e in body for e in ["not found","404","does not exist"]):
            score += EVIDENCE_WEIGHTS["generic_error"]
        if status == 403:
            score -= 0.15
        if status == 429:
            score -= 0.20  # rate limited = FP

        return max(0.0, min(1.0, score))

    # ── Ollama analysis with specialized prompt ───────────────────────────────
    def _ollama_analyze(self, vt: str, url: str, response: str,
                         payload: str, baseline_len: int,
                         status: int) -> Optional[dict]:
        if not self.ollama: return None

        # Get specialized system prompt
        system = VULN_PROMPTS.get(vt, VULN_PROMPTS["DEFAULT"])

        # Add book knowledge context
        if self.trainer:
            ctx    = self.trainer.build_ollama_context(vt)
            system = system + "\n\n" + ctx

        try:
            result = self.ollama.analyze_response(
                vt, url, response, payload, baseline_len, status)
            return result
        except Exception:
            return None

    # ── Severity lookup ───────────────────────────────────────────────────────
    def _get_severity(self, vt: str, verdict: str) -> str:
        if verdict == "false_positive":
            return "info"
        SMAP = {
            "XSS":"high","SQLI":"critical","SSRF":"critical",
            "SSTI":"critical","RCE":"critical","IDOR":"high",
            "LFI":"high","JWT":"critical","XXE":"high","NOSQL":"critical",
        }
        return SMAP.get(vt, "medium")

    def get_stats(self) -> dict:
        return self._stats


if __name__ == "__main__":
    sa = SmartAnalyzer()

    # Test XSS confirmed
    r1 = sa.analyze("XSS",
        "https://example.com/search?q=test",
        "<html><body><svg/onload=alert(1)></body></html>",
        payload="<svg/onload=alert(1)>")
    print(f"XSS confirmed test:  {r1}")

    # Test XSS FP (encoded)
    r2 = sa.analyze("XSS",
        "https://example.com/search?q=test",
        "<html>&lt;svg/onload=alert(1)&gt;</html>",
        payload="<svg/onload=alert(1)>")
    print(f"XSS FP test:         {r2}")

    # Test SSRF confirmed
    r3 = sa.analyze("SSRF",
        "https://example.com/proxy",
        '{"ami-id":"ami-12345678","instance-id":"i-12345"}',
        payload="http://169.254.169.254/latest/meta-data/")
    print(f"SSRF confirmed test: {r3}")

    print(f"\nStats: {sa.get_stats()}")
