#!/usr/bin/env python3
# confirm/confidence.py — Multi-Signal Confidence Scoring Engine
# MilkyWay Intelligence | Author: Sharlix

import re

CONFIRMED_INDICATORS = {
    "SSRF" : [
        (r"ami-id",             0.95),
        (r"instance-id",        0.95),
        (r"local-ipv4",         0.95),
        (r"AccessKeyId",        0.95),
        (r"computeMetadata",    0.90),
        (r"169\.254\.169\.254", 0.70),
    ],
    "XSS"  : [
        (r"<script[^>]*>alert", 0.95),
        (r"<svg[^>]*(onload|onerror)=", 0.90),
        (r"<img[^>]*onerror=",  0.90),
    ],
    "LFI"  : [
        (r"root:x?:\d+:\d+:",  0.99),
        (r"daemon:[^:]+:\d+:", 0.95),
        (r"\[boot loader\]",   0.99),
        (r"BEGIN RSA PRIVATE KEY", 0.99),
    ],
    "SQLI" : [
        (r"SQL syntax.*MySQL", 0.95),
        (r"ORA-\d{4,5}:",      0.95),
        (r"PostgreSQL.*ERROR", 0.90),
        (r"SQLSTATE\[",        0.85),
    ],
    "SSTI" : [
        (r"\b49\b",            0.80),
        (r"\b7777777\b",       0.95),
        (r"uid=\d+\(",         0.99),
    ],
    "NOSQL": [
        (r'"role"\s*:\s*"admin"', 0.90),
        (r'"isAdmin"\s*:\s*true', 0.90),
        (r"logged in",            0.75),
    ],
}

FP_PATTERNS = {
    "SSRF" : [r"connection refused", r"no route to host", r"network unreachable"],
    "XSS"  : [r"&lt;script", r"&lt;svg",  r"\\u003c"],
    "LFI"  : [r"file not found", r"no such file", r"permission denied"],
    "SQLI" : [r"please enter a valid", r"invalid input"],
}


class ConfidenceEngine:
    THRESHOLDS = {"confirmed": 0.85, "potential": 0.50}

    def __init__(self, offline_ai=None, threshold: float = 0.8):
        self.offline_ai = offline_ai
        self.threshold  = threshold

    def score(self, vuln_type: str, url: str = "", detail: str = "",
              response: str = "", payload: str = "", ai_analysis: dict = None,
              tool: str = "", baseline_len: int = 0, response_time: float = 0.0,
              oob_hit: bool = False) -> dict:

        signals    = []
        score      = 0.0
        resp_lower = response.lower() if response else ""
        vtype      = vuln_type.split("_")[0].upper()

        # 1. OOB callback — strongest signal
        if oob_hit:
            score = 0.99
            signals.append({"type": "oob_callback", "weight": 0.99})
            return self._result(score, signals, vuln_type)

        # 2. Confirmed indicator patterns
        for pattern, weight in CONFIRMED_INDICATORS.get(vtype, []):
            if re.search(pattern, response, re.IGNORECASE):
                score = max(score, weight)
                signals.append({"type": "confirmed_pattern",
                                  "pattern": pattern[:40], "weight": weight})
                if weight >= 0.95:
                    return self._result(min(score, 1.0), signals, vuln_type)

        # 3. FP filter
        for pattern in FP_PATTERNS.get(vtype, []):
            if re.search(pattern, resp_lower):
                return {"score": max(0.1, score - 0.5),
                         "status": "false_positive", "signals": signals}

        # 4. Content length diff
        if baseline_len > 0 and response:
            diff = abs(len(response) - baseline_len)
            if diff > 500:
                score += 0.30
                signals.append({"type": "len_diff_large", "diff": diff, "weight": 0.30})
            elif diff > 100:
                score += 0.15
            elif diff < 10:
                score -= 0.15

        # 5. Payload reflection (unencoded)
        if payload and vtype in ("XSS", "SSTI", "IDOR"):
            if payload.lower() in resp_lower:
                if "&lt;" in resp_lower:
                    score -= 0.20
                    signals.append({"type": "encoded_reflection", "weight": -0.20})
                else:
                    score += 0.35
                    signals.append({"type": "unencoded_reflection", "weight": 0.35})

        # 6. Error signals
        for sig, w in [("exception", 0.15), ("stacktrace", 0.15),
                        ("fatal error", 0.15), ("internal server error", 0.10)]:
            if sig in resp_lower:
                score += w
                signals.append({"type": "error_signal", "signal": sig, "weight": w})
                break

        # 7. Time-based (SQLi / SSRF blind)
        if response_time > 5.0 and vtype in ("SQLI", "SSRF", "CMDI"):
            score += 0.40
            signals.append({"type": "timing_delay",
                              "seconds": response_time, "weight": 0.40})

        # 8. Tool-specific auto-score
        tool_trust = {
            "sqlmap": 0.95, "dalfox": 0.90, "nuclei": 0.80,
            "subzy": 0.90,  "interactsh": 0.85,
        }
        if tool in tool_trust:
            tool_w = tool_trust[tool]
            score  = max(score, tool_w * 0.6)
            signals.append({"type": "tool_trust", "tool": tool, "weight": tool_w})

        # 9. AI analysis
        if ai_analysis:
            if ai_analysis.get("verdict") == "confirmed":
                score += 0.20
            elif ai_analysis.get("verdict") == "false_positive":
                score -= 0.30

        if score <= 0.0:
            score = 0.30

        return self._result(min(score, 1.0), signals, vuln_type)

    def _result(self, score: float, signals: list, vuln_type: str) -> dict:
        if score >= max(self.THRESHOLDS["confirmed"], self.threshold):
            status = "confirmed"
        elif score >= self.THRESHOLDS["potential"]:
            status = "potential"
        else:
            status = "false_positive"
        return {
            "score"     : round(score, 3),
            "status"    : status,
            "signals"   : signals,
            "vuln_type" : vuln_type,
        }
