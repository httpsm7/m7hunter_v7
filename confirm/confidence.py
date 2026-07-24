#!/usr/bin/env python3
# confirm/confidence.py — Multi-Signal Confidence Scoring Engine V7
# Blueprint Fix: 8 → 26 vuln types, FP patterns, OOB signal, timing signal
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import re

CONFIRMED_INDICATORS = {
    "SSRF"             : [(r"ami-id",0.95),(r"instance-id",0.95),(r"local-ipv4",0.95),
                          (r"AccessKeyId",0.95),(r"computeMetadata",0.90),(r"169\.254\.169\.254",0.70)],
    "XSS"              : [(r"<script[^>]*>alert",0.95),(r"<svg[^>]*(onload|onerror)=",0.90),
                          (r"<img[^>]*onerror=",0.90)],
    "DOM_XSS"          : [(r"document\.write\s*\(",0.80),(r"innerHTML\s*=",0.85),
                          (r"eval\s*\(",0.82),(r"location\.hash",0.70)],
    "BLIND_XSS"        : [],
    "STORED_XSS"       : [(r"<script[^>]*>alert",0.97),(r"<img[^>]*onerror=",0.93),(r"m7x\s+id=.m7_",0.99)],
    "SVG_XSS"          : [(r"<svg.*onload=",0.90),(r"<script>alert",0.95)],
    "LFI"              : [(r"root:x?:\d+:\d+:",0.99),(r"daemon:[^:]+:\d+:",0.95),
                          (r"\[boot loader\]",0.99),(r"BEGIN RSA PRIVATE KEY",0.99)],
    "SQLI"             : [(r"SQL syntax",0.92),(r"SQL syntax.*MySQL",0.95),(r"ORA-\d{4,5}:",0.95),
                          (r"PostgreSQL.*ERROR",0.90),(r"SQLSTATE\[",0.85),
                          (r"Unclosed quotation mark",0.92),(r"unterminated quoted string",0.90)],
    "SQLI_TIME_BASED"  : [],
    "SQLI_UNION_BASED" : [(r"[0-9]+\.[0-9]+\.[0-9]+",0.85),(r"information_schema",0.90)],
    "SQLI_ERROR_BASED" : [(r"SQL syntax",0.92),(r"ORA-\d{4}",0.90),(r"unterminated quoted",0.88)],
    "SQLI_OOB"         : [],
    "SSTI"             : [(r"\b49\b",0.80),(r"\b7777777\b",0.95),(r"uid=\d+\(",0.99)],
    "NOSQL"            : [(r'"role"\s*:\s*"admin"',0.90),(r'"isAdmin"\s*:\s*true',0.90),(r"logged in",0.75)],
    "HTTP_SMUGGLING"   : [(r"GPOST\s*/",0.95),(r"Invalid request line",0.75),(r"HTTP/1\.1 400",0.70)],
    "HTTP2_SMUGGLING"  : [(r"GPOST\s*/",0.95),(r"switching protocols",0.75)],
    "JWT_FORGERY"      : [(r'"role"\s*:\s*"admin"',0.90),(r'"is_admin"\s*:\s*true',0.90),
                          (r'"admin"\s*:\s*1',0.82)],
    "GRAPHQL_INJECTION": [(r'"\"errors\":\s*\[',0.75),(r'"__schema"',0.95)],
    "GRAPHQL_BATCHING" : [(r'"\"data\":\s*\[',0.80)],
    "2FA_BYPASS"       : [(r'"success"\s*:\s*true',0.80),(r'"authenticated"\s*:\s*true',0.85),
                          (r"Set-Cookie.*session=",0.85)],
    "SAML_BYPASS"      : [(r"<saml:NameID",0.90),(r"SAMLResponse",0.70),(r"authenticated.*true",0.82)],
    "LAMBDA_RCE"       : [(r"uid=\d+\(",0.99),(r"root:x:\d+:",0.99),(r"x-amzn-RequestId",0.65)],
    "K8S_SECRET_LEAK"  : [(r"kind:\s*Secret",0.99),(r'"\"apiVersion\":\s*\"v1\"',0.80),
                          (r"KUBERNETES_SERVICE_HOST",0.95),(r"serviceAccountToken",0.99)],
    "DYNAMODB_INJECTION": [(r'"\"Items\":\s*\[',0.80),(r'"\"isAdmin\":',0.85)],
    "S3_PRESIGNED_ABUSE": [(r"ListBucketResult",0.95),(r"<Contents>",0.95)],
    "OPEN_S3_BUCKET"   : [(r"ListBucketResult",0.99),(r"<Contents>",0.95)],
    "CORS_MISCONFIG"   : [(r"Access-Control-Allow-Origin:\s*https?://evil",0.95)],
    "DNS_ZONE_TRANSFER": [(r"AXFR",0.99),(r"\sIN\s+SOA\s",0.99)],
}

FP_PATTERNS = {
    "XSS"         : [r"&lt;script",r"&lt;svg",r"\\u003c"],
    "DOM_XSS"     : [r"DOMPurify",r"sanitize",r"\\u003c"],
    "LFI"         : [r"file not found",r"no such file",r"permission denied"],
    "SQLI"        : [r"please enter a valid",r"invalid input"],
    "SSRF"        : [r"connection refused",r"no route to host"],
    "JWT_FORGERY" : [r"invalid token",r"token expired",r"signature.*invalid"],
    "2FA_BYPASS"  : [r"invalid code",r"code expired",r"try again"],
    "SAML_BYPASS" : [r"invalid signature",r"assertion.*expired"],
    "LAMBDA_RCE"  : [r"Function timed out"],
    "K8S_SECRET_LEAK": [r"Forbidden",r"401 Unauthorized"],
}

class ConfidenceEngine:
    THRESHOLDS = {"confirmed":0.85,"potential":0.50}

    def __init__(self, offline_ai=None, threshold=0.8):
        self.offline_ai = offline_ai
        self.threshold  = threshold

    def score(self, vuln_type, url="", detail="", response="",
              payload="", ai_analysis=None, tool="",
              baseline_len=0, response_time=0.0, oob_hit=False) -> dict:
        signals = []; score = 0.0
        full = vuln_type.upper()
        prefix = full.split("_")[0]

        if oob_hit:
            return self._result(0.99, [{"type":"oob_callback","weight":0.99}], vuln_type)

        for vt in [full, prefix]:
            for pat, weight in CONFIRMED_INDICATORS.get(vt, []):
                if re.search(pat, response, re.IGNORECASE):
                    score = max(score, weight)
                    signals.append({"type":"pattern","pattern":pat,"weight":weight})
                    break

        for pat in FP_PATTERNS.get(full, FP_PATTERNS.get(prefix, [])):
            if re.search(pat, response, re.IGNORECASE):
                score *= 0.3
                signals.append({"type":"fp_caught","pattern":pat})
                break

        if response_time >= 4.5 and "sqli" in vuln_type.lower():
            s = 0.95 if response_time >= 9 else 0.88
            score = max(score, s)
            signals.append({"type":"timing","delay_s":round(response_time,1)})

        if baseline_len and response and prefix in ("XSS","SSTI","SQLI"):
            diff = abs(len(response) - baseline_len)
            if diff > 200:
                score = min(score + 0.08, 0.75)
                signals.append({"type":"len_diff","diff":diff})

        if ai_analysis and ai_analysis.get("confidence"):
            ai_s = float(ai_analysis["confidence"])
            score = max(score, (score + ai_s)/2)
            signals.append({"type":"ai","weight":ai_s})

        return self._result(score, signals, vuln_type)

    def _result(self, score, signals, vuln_type):
        return {"score":round(score,3),
                "verdict":"confirmed" if score>=self.THRESHOLDS["confirmed"] else
                          "potential" if score>=self.THRESHOLDS["potential"] else "noise",
                "signals":signals,"vuln_type":vuln_type,"pass":score>=self.threshold}

def score_confidence(vuln_type, response="", **kw):
    return ConfidenceEngine().score(vuln_type, response=response, **kw)
