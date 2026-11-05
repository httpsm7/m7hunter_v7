#!/usr/bin/env python3
# ai/offline_ai.py — Offline AI (pattern matching + heuristics)
# MilkyWay Intelligence | Author: Sharlix

import os, re, json

LEARNED_FILE = os.path.expanduser("~/.m7hunter/learned_patterns.json")

FALSE_POSITIVE_PATTERNS = {
    "SSRF" : ["connection refused", "invalid url", "connection timed out", "no route to host"],
    "XSS"  : ["&lt;script&gt;", "&amp;lt;", "\\u003c", "content-security-policy"],
    "LFI"  : ["file not found", "no such file", "permission denied", "access denied"],
    "SQLI" : ["please enter a valid", "invalid input", "bad request"],
}

CONFIRMED_PATTERNS = {
    "SSRF_AWS"     : ["ami-id", "instance-id", "local-ipv4", "security-credentials", "AccessKeyId"],
    "SSRF_GCP"     : ["computeMetadata", "instance/zone", "service-accounts"],
    "XSS_REFLECT"  : ["<script>alert", "<svg/onload", "onerror=alert", "javascript:alert"],
    "LFI_UNIX"     : ["root:x:0:0", "daemon:", "bin/bash", "bin/sh", "/etc/passwd"],
    "SQLI_ERROR"   : ["mysql error", "ORA-", "PostgreSQL", "mssql", "SQLSTATE"],
    "NOSQL_BYPASS" : ['"role":"admin"', '"isAdmin":true', "logged in as"],
    "SSTI_CALC"    : ["7777777", "49", "uid=0(root)"],
}

SEVERITY_MAP = {
    "SSRF_AWS": "critical", "SSRF_GCP": "critical",
    "LFI_UNIX": "critical",  "SQLI_ERROR": "critical",
    "NOSQL_BYPASS": "critical", "SSTI_CALC": "critical",
    "XSS_REFLECT": "high",
}


class OfflineAI:
    def __init__(self, log=None):
        self.log     = log
        self.learned = self._load_learned()
        self._stats  = {"analyzed": 0, "confirmed": 0, "fp_caught": 0}

    def _load_learned(self) -> dict:
        if os.path.isfile(LEARNED_FILE):
            try:
                with open(LEARNED_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"fp_signatures": [], "total_analyzed": 0}

    def analyze_response(self, vuln_type: str, url: str, response: str,
                          payload: str = "", baseline_len: int = 0) -> dict:
        self._stats["analyzed"] += 1
        resp_lower = response.lower() if response else ""
        result = {
            "verdict": "potential", "confidence": 0.5,
            "reason": [], "is_false_positive": False, "severity": "medium",
        }
        vtype_key = vuln_type.upper().split("_")[0]

        # FP filter
        for pat in FALSE_POSITIVE_PATTERNS.get(vtype_key, []):
            if re.search(pat, resp_lower):
                result["verdict"] = "false_positive"
                result["is_false_positive"] = True
                result["confidence"] = 0.9
                result["reason"].append(f"FP: {pat}")
                self._stats["fp_caught"] += 1
                return result

        # Confirmed check
        for pat_name, patterns in CONFIRMED_PATTERNS.items():
            if not pat_name.startswith(vtype_key):
                continue
            for pat in patterns:
                if re.search(re.escape(pat), resp_lower, re.IGNORECASE):
                    result["verdict"]    = "confirmed"
                    result["confidence"] = 0.95
                    result["severity"]   = SEVERITY_MAP.get(pat_name, "high")
                    result["reason"].append(f"Confirmed: {pat_name}")
                    self._stats["confirmed"] += 1
                    return result

        # Content diff
        if baseline_len > 0 and response:
            diff = abs(len(response) - baseline_len)
            if diff > 500:
                result["confidence"] += 0.30
                result["reason"].append(f"Large response diff: {diff}b")
            elif diff > 100:
                result["confidence"] += 0.15
            elif diff < 10:
                result["confidence"] -= 0.20

        # Error signals
        for sig in ["exception", "stacktrace", "fatal error", "syntax error"]:
            if sig in resp_lower:
                result["confidence"] += 0.20
                result["reason"].append(f"Error: {sig}")
                break

        # Payload reflection (XSS/SSTI)
        if payload and vtype_key in ("XSS", "SSTI"):
            if payload.lower() in resp_lower and "&lt;" not in resp_lower:
                result["confidence"] += 0.35
                result["reason"].append("Unencoded reflection")

        # Final verdict
        if result["confidence"] >= 0.80:
            result["verdict"] = "confirmed"
        elif result["confidence"] < 0.40:
            result["verdict"] = "false_positive"
            result["is_false_positive"] = True

        return result

    def is_available(self) -> bool:
        return True

    def get_status(self) -> str:
        return (f"Offline AI | analyzed:{self._stats['analyzed']} "
                f"| fp_caught:{self._stats['fp_caught']} "
                f"| confirmed:{self._stats['confirmed']}")
