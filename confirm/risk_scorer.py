#!/usr/bin/env python3
# confirm/risk_scorer.py — CVSS-like Risk Scoring V7
# Blueprint Fix: 25 new vuln types added
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

EXPLOITABILITY = {
    "XSS":7.5,"SQLI":9.0,"SSRF":8.5,"LFI":7.0,"SSTI":9.5,"RCE":10.0,
    "IDOR":7.0,"CORS":6.0,"XXE":7.5,"CSRF":6.5,"OPEN_REDIRECT":5.0,
    "NOSQL":8.0,"JWT_WEAK":7.5,"GRAPHQL":7.0,"RACE_CONDITION":6.5,
    "SMUGGLING":8.0,"TAKEOVER":8.5,"CLOUD_EXPOSURE":7.5,"INFO_LEAK":4.0,
    "2FA_BYPASS":8.5,"2FA_RATE_LIMIT_BYPASS":7.0,"2FA_STEP_SKIP":8.8,
    "SAML_BYPASS":8.8,"SAML_SIGNATURE_BYPASS":9.2,
    "LAMBDA_RCE":9.5,"K8S_SECRET_LEAK":9.0,"DYNAMODB_INJECTION":8.0,
    "S3_PRESIGNED_ABUSE":7.5,"HTTP2_SMUGGLING":8.2,
    "GRAPHQL_BATCHING":6.5,"DOM_XSS":8.0,"BLIND_XSS":8.5,"STORED_XSS":8.8,
    "SVG_XSS":8.0,"SQLI_TIME_BASED":8.5,"SQLI_UNION_BASED":9.0,
    "SQLI_ERROR_BASED":8.8,"SQLI_OOB":9.5,
    "DNS_ZONE_TRANSFER":8.0,"CNAME_TAKEOVER_CHAIN":8.5,
}

IMPACT = {
    "XSS":7.0,"SQLI":9.5,"SSRF":9.0,"LFI":7.5,"SSTI":9.5,"RCE":10.0,
    "IDOR":8.0,"CORS":7.0,"XXE":8.0,"CSRF":7.0,"OPEN_REDIRECT":5.5,
    "NOSQL":8.5,"JWT_WEAK":8.5,"GRAPHQL":7.5,"RACE_CONDITION":7.5,
    "SMUGGLING":9.0,"TAKEOVER":9.5,"CLOUD_EXPOSURE":8.5,"INFO_LEAK":4.5,
    "2FA_BYPASS":9.0,"2FA_RATE_LIMIT_BYPASS":7.5,"2FA_STEP_SKIP":9.2,
    "SAML_BYPASS":9.5,"SAML_SIGNATURE_BYPASS":9.8,
    "LAMBDA_RCE":9.8,"K8S_SECRET_LEAK":9.5,"DYNAMODB_INJECTION":8.5,
    "S3_PRESIGNED_ABUSE":8.0,"HTTP2_SMUGGLING":8.5,
    "GRAPHQL_BATCHING":7.0,"DOM_XSS":8.0,"BLIND_XSS":8.5,"STORED_XSS":9.0,
    "SVG_XSS":8.0,"SQLI_TIME_BASED":8.5,"SQLI_UNION_BASED":9.2,
    "SQLI_ERROR_BASED":8.8,"SQLI_OOB":9.5,
    "DNS_ZONE_TRANSFER":8.0,"CNAME_TAKEOVER_CHAIN":9.0,
}

def calculate_risk(vuln_type, confidence=0.8) -> dict:
    vt = vuln_type.upper()
    ex = EXPLOITABILITY.get(vt, 5.0); im = IMPACT.get(vt, 5.0)
    score = round((ex * im * confidence) / 10, 2)
    sev = ("critical" if score>=8.0 else "high" if score>=6.0 else
           "medium" if score>=4.0 else "low" if score>=2.0 else "info")
    return {"vuln_type":vuln_type,"risk_score":score,"severity":sev,
            "exploitability":ex,"impact":im,"confidence":confidence}

def get_severity(vuln_type, confidence=0.8) -> str:
    return calculate_risk(vuln_type, confidence)["severity"]
