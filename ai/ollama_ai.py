#!/usr/bin/env python3
# ai/ollama_ai.py — Ollama AI Integration for M7Hunter
# Connects to local Ollama instance for intelligent vuln analysis & FP reduction
# Books: Bug Bounty Bootcamp (methodology), Bug Hunter Methodology (analysis)
# MilkyWay Intelligence | Author: Sharlix + M7AI

import json
import urllib.request
import urllib.error
import os
import re

OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("M7_OLLAMA_MODEL", "llama3")

# ── Training prompts derived from the 6 security books ────────────────────────
SYSTEM_PROMPT = """You are M7Hunter's security analysis AI, trained on:
- Bug Bounty Bootcamp by Vickie Li
- Bug Hunter's Methodology by Jason Haddix  
- CEH (Certified Ethical Hacker) guide
- Penetration Testing with Kali Linux (PWK)
- Coding for Penetration Testers
- XSS Payload methodology

Your job: Analyze HTTP responses and determine if a vulnerability finding is:
- CONFIRMED: Clear evidence of exploitation (payload executed, data leaked, etc.)
- POTENTIAL: Signs of vulnerability but needs more verification
- FALSE_POSITIVE: Not a real vulnerability (WAF block, encoded output, normal error)

Rules from Bug Bounty Bootcamp:
- XSS is CONFIRMED only if payload reflects UNENCODED in response
- SSRF is CONFIRMED only if metadata endpoints return actual cloud credentials
- SQLi is CONFIRMED only if database errors OR time delay is measurable
- IDOR is CONFIRMED only if you get data belonging to another user
- Always check if response is encoded (&lt; instead of <) = FALSE_POSITIVE for XSS

Always respond ONLY with valid JSON, no preamble, no explanation outside JSON:
{"verdict": "confirmed|potential|false_positive", "confidence": 0.0-1.0, "reason": "brief reason", "severity": "critical|high|medium|low"}"""

ANALYSIS_PROMPT_TEMPLATE = """Analyze this security finding:

Vulnerability Type: {vuln_type}
URL: {url}
Payload Used: {payload}
Response Status: {status}
Response Body (first 1500 chars): {response}
Baseline Length: {baseline_len}
Actual Length: {response_len}

Key indicators to check:
- For XSS: Is payload reflected UNENCODED? Is there &lt; encoding?
- For SQLi: Any DB error messages? Timing anomaly?
- For SSRF: Any internal IP, AWS metadata, GCP metadata in response?
- For LFI: Any /etc/passwd content? Windows path content?
- For SSTI: Is 7*7=49 returned? Is 7777777 in output?

Respond with JSON only."""


class OllamaAI:
    """
    Ollama AI integration for M7Hunter.
    Falls back to OfflineAI if Ollama is not available.
    """

    def __init__(self, log=None, model: str = None):
        self.log      = log
        self.model    = model or DEFAULT_MODEL
        self.base_url = OLLAMA_BASE
        self.available = self._check_available()
        self._stats   = {"analyzed": 0, "confirmed": 0, "fp_caught": 0, "errors": 0}

        if self.available and self.log:
            self.log.success(f"Ollama AI ready: {self.model} @ {self.base_url}")
        elif self.log:
            self.log.warn(f"Ollama not available at {self.base_url} — AI analysis disabled")

    def _check_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        try:
            req  = urllib.request.Request(
                f"{self.base_url}/api/tags",
                headers={"Content-Type": "application/json"}
            )
            resp = urllib.request.urlopen(req, timeout=3)
            data = json.loads(resp.read())
            models = [m["name"].split(":")[0] for m in data.get("models", [])]
            return self.model.split(":")[0] in models
        except Exception:
            return False

    def analyze_response(self, vuln_type: str, url: str, response: str,
                          payload: str = "", baseline_len: int = 0,
                          status: int = 200) -> dict:
        """Analyze a finding using Ollama."""
        self._stats["analyzed"] += 1

        if not self.available:
            return self._offline_fallback(vuln_type, response, payload)

        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            vuln_type    = vuln_type,
            url          = url[:200],
            payload      = payload[:200],
            status       = status,
            response     = response[:1500],
            baseline_len = baseline_len,
            response_len = len(response),
        )

        try:
            result = self._query_ollama(prompt)
            parsed = self._parse_result(result)

            if parsed["verdict"] == "confirmed":
                self._stats["confirmed"] += 1
            elif parsed["verdict"] == "false_positive":
                self._stats["fp_caught"] += 1

            return parsed

        except Exception as e:
            self._stats["errors"] += 1
            if self.log:
                self.log.warn(f"Ollama error: {e}")
            return self._offline_fallback(vuln_type, response, payload)

    def _query_ollama(self, prompt: str) -> str:
        """Send prompt to Ollama and return raw text response."""
        body = json.dumps({
            "model":  self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": 0.1,   # Low temp = more deterministic
                "top_p": 0.9,
                "num_predict": 200,   # Short responses only
            }
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        return data.get("response", "")

    def _parse_result(self, raw: str) -> dict:
        """Parse Ollama JSON response safely."""
        # Extract JSON from response
        raw = raw.strip()
        # Sometimes Ollama wraps in ```json ... ```
        json_match = re.search(r'\{[^}]+\}', raw, re.DOTALL)
        if json_match:
            try:
                result = json.loads(json_match.group())
                return {
                    "verdict":    result.get("verdict", "potential"),
                    "confidence": float(result.get("confidence", 0.5)),
                    "reason":     result.get("reason", ""),
                    "severity":   result.get("severity", "medium"),
                }
            except Exception:
                pass

        # Fallback: keyword scan
        lower = raw.lower()
        if "confirmed" in lower:
            return {"verdict": "confirmed", "confidence": 0.85, "reason": "Ollama: confirmed", "severity": "high"}
        elif "false_positive" in lower or "false positive" in lower:
            return {"verdict": "false_positive", "confidence": 0.80, "reason": "Ollama: FP", "severity": "info"}
        else:
            return {"verdict": "potential", "confidence": 0.50, "reason": "Ollama: uncertain", "severity": "medium"}

    def _offline_fallback(self, vuln_type: str, response: str, payload: str) -> dict:
        """Pattern-based fallback when Ollama is unavailable (from Book patterns)."""
        resp_lower = response.lower() if response else ""
        vtype = vuln_type.upper().split("_")[0]

        # FP patterns from Bug Bounty Bootcamp
        FP = {
            "XSS":  ["&lt;script", "&lt;svg", "\\u003c", "content-security-policy: default-src"],
            "SSRF": ["connection refused", "no route to host", "network unreachable"],
            "LFI":  ["file not found", "no such file", "permission denied"],
            "SQLI": ["please enter a valid", "invalid input"],
        }
        for pat in FP.get(vtype, []):
            if pat in resp_lower:
                return {"verdict": "false_positive", "confidence": 0.85,
                        "reason": f"FP pattern: {pat}", "severity": "info"}

        # Confirmed patterns from Bug Bounty Bootcamp chapters
        CONFIRMED = {
            "XSS":  ["<script>alert", "<svg/onload", "onerror=alert"],
            "SSRF": ["ami-id", "instance-id", "accesskeyid", "computemetadata"],
            "LFI":  ["root:x:0:0", "daemon:", "begin rsa private key"],
            "SQLI": ["sql syntax", "ora-", "postgresql.*error", "sqlstate"],
            "SSTI": ["7777777", "49", "uid=0(root)"],
        }
        for pat in CONFIRMED.get(vtype, []):
            if re.search(pat, resp_lower, re.I):
                return {"verdict": "confirmed", "confidence": 0.92,
                        "reason": f"Confirmed pattern: {pat}", "severity": "high"}

        return {"verdict": "potential", "confidence": 0.50,
                "reason": "No definitive indicators", "severity": "medium"}

    def train_from_finding(self, finding: dict, outcome: str):
        """
        Train Ollama from confirmed/denied findings.
        outcome: 'true_positive' | 'false_positive'
        This saves to learned patterns file for future sessions.
        """
        if not self.available:
            return

        learned_file = os.path.expanduser("~/.m7hunter/ollama_trained.jsonl")
        os.makedirs(os.path.dirname(learned_file), exist_ok=True)

        record = {
            "vuln_type": finding.get("vuln_type", ""),
            "payload":   finding.get("payload", ""),
            "outcome":   outcome,
            "detail":    finding.get("detail", "")[:200],
        }
        with open(learned_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    def get_status(self) -> str:
        return (
            f"Ollama AI ({self.model}) | "
            f"available:{self.available} | "
            f"analyzed:{self._stats['analyzed']} | "
            f"confirmed:{self._stats['confirmed']} | "
            f"fp_caught:{self._stats['fp_caught']}"
        )

    def is_available(self) -> bool:
        return self.available


if __name__ == "__main__":
    ai = OllamaAI()
    print(ai.get_status())

    # Test offline fallback
    result = ai._offline_fallback(
        "XSS",
        "<html><body><svg/onload=alert(1)> hello</body></html>",
        "<svg/onload=alert(1)>"
    )
    print("Test XSS confirmed:", result)

    result2 = ai._offline_fallback(
        "XSS",
        "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>",
        "<script>alert(1)</script>"
    )
    print("Test XSS FP (encoded):", result2)
