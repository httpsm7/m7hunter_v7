#!/usr/bin/env python3
# engines/double_verify.py — V7 Double Verification Engine (Expanded)
# Blueprint Fix: Coverage 8 → 27+ vuln types, structured error capture
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import re, time, random
from core.error_handler import get_handler

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
]

CONFIRM_PATTERNS = {
    "SSRF"            : [r"ami-id",r"instance-id",r"local-ipv4",r"AccessKeyId"],
    "LFI"             : [r"root:x?:\d+:\d+:",r"/bin/bash",r"\[boot loader\]"],
    "XSS"             : [r"<script[^>]*>alert",r"<svg[^>]*(onload|onerror)=",r"<img[^>]*onerror="],
    "DOM_XSS"         : [r"document\.write\s*\(",r"innerHTML\s*=",r"eval\s*\("],
    "STORED_XSS"      : [r"<script[^>]*>alert",r"<img[^>]*onerror=",r"m7x\s+id=.m7_"],
    "SQLI"            : [r"SQL syntax",r"ORA-\d{4}",r"PostgreSQL.*ERROR",r"SQLSTATE"],
    "SQLI_UNION_BASED": [r"[0-9]+\.[0-9]+\.[0-9]+",r"information_schema"],
    "SQLI_ERROR_BASED": [r"SQL syntax",r"ORA-\d{4}",r"unterminated quoted"],
    "NOSQL"           : [r'"role"\s*:\s*"admin"', r'"isAdmin"\s*:\s*true', r"logged in", r'"is_admin"\s*:\s*true'],
    "SSTI"            : [r"\b49\b",r"\b7777777\b",r"uid=\d+\("],
    "OPEN_S3_BUCKET"  : [r"ListBucketResult",r"<Contents>"],
    "CORS_MISCONFIG"  : [r"Access-Control-Allow-Origin:\s*https?://evil"],
    "HTTP_SMUGGLING"  : [r"GPOST\s*/",r"Invalid request line"],
    "HTTP2_SMUGGLING" : [r"GPOST\s*/",r"switching protocols"],
    "JWT_FORGERY"     : [r'"role"\s*:\s*"admin"', r'"is_admin"\s*:\s*true', r'"isAdmin"\s*:\s*true'],
    "GRAPHQL_INJECTION": [r'"errors"\s*:\s*\[', r'"__schema"', r"introspection"],
    "2FA_BYPASS"      : [r'"success"\s*:\s*true', r'"authenticated"\s*:\s*true', r"Set-Cookie.*session="],
    "SAML_BYPASS"     : [r"<saml:NameID",r"authenticated.*true"],
    "LAMBDA_RCE"      : [r"uid=\d+\(",r"root:x:\d+:"],
    "K8S_SECRET_LEAK" : [r"kind:\s*Secret",r"serviceAccountToken"],
    "DYNAMODB_INJECTION": [r'"\"Items\":\s*\[',r'"\"isAdmin\":'],
    "CNAME_TAKEOVER"  : [r"There is no app configured",r"herokucdn\.com"],
}

EXTERNAL_VERIFY = {"BLIND_XSS","SQLI_OOB","SQLI_TIME_BASED"}

FP_PATTERNS = {
    "XSS"         : [r"&lt;script",r"&lt;svg",r"\\u003c"],
    "LFI"         : [r"file not found",r"no such file"],
    "SQLI"        : [r"please enter a valid",r"invalid input"],
    "SSRF"        : [r"invalid url", r"url must start with http"],
    "JWT_FORGERY" : [r"invalid token",r"token expired"],
    "2FA_BYPASS"  : [r"invalid code",r"code expired"],
    "SAML_BYPASS" : [r"invalid signature",r"assertion.*expired"],
}

class DoubleVerify:
    def __init__(self, ceo_engine=None, log=None):
        self.ceo   = ceo_engine
        self.log   = log
        self.delay = (ceo_engine.double_verify_delay() if ceo_engine else 1.5)

    def verify(self, vuln_type, url, payload="", original_response="",
               method="GET", post_body=None, headers=None) -> dict:
        vtype = vuln_type.upper()
        if vtype in EXTERNAL_VERIFY:
            return {"confirmed":True,"confidence_boost":0.10,
                    "reason":"external_signal","second_response":""}
        time.sleep(self.delay)
        ua = random.choice(UAS)
        h  = dict(headers or {})
        h["User-Agent"] = ua
        h["X-Request-ID"] = f"m7dv-{int(time.time())}"
        second = ""
        try:
            from core.http_client import sync_post, sync_get
            r = sync_post(url,data=post_body,headers=h,timeout=15) if (method.upper()=="POST" and post_body) else sync_get(url,headers=h,timeout=15)
            second = r.get("body","") if r else ""
        except Exception as e:
            get_handler().capture("double_verify", e, f"verify:{vtype}")
            return {"confirmed":False,"confidence_boost":0.0,"reason":"network_error","second_response":""}

        patterns = CONFIRM_PATTERNS.get(vtype) or CONFIRM_PATTERNS.get(vtype.split("_")[0])
        if not patterns:
            sim = self._sim(original_response, second)
            if sim > 0.80:
                return {"confirmed":True,"confidence_boost":0.05,
                        "reason":f"response_similar:{sim:.2f}","second_response":second}
            return {"confirmed":False,"confidence_boost":0.0,
                    "reason":"no_pattern","second_response":second}

        fp_list = FP_PATTERNS.get(vtype, FP_PATTERNS.get(vtype.split("_")[0],[]))
        for fp in fp_list:
            if re.search(fp, second, re.IGNORECASE):
                return {"confirmed":False,"confidence_boost":-0.20,
                        "reason":f"fp:{fp}","second_response":second}

        for pat in patterns:
            if re.search(pat, second, re.IGNORECASE):
                return {"confirmed":True,"confidence_boost":0.10,
                        "reason":f"pattern:{pat}","second_response":second}

        return {"confirmed":False,"confidence_boost":-0.10,
                "reason":"pattern_not_found","second_response":second}

    def _sim(self, a, b):
        if not a or not b: return 0.0
        sa=set(a.lower().split()); sb=set(b.lower().split())
        if not sa or not sb: return 0.0
        return len(sa&sb)/len(sa|sb)
