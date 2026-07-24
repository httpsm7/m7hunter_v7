#!/usr/bin/env python3
# engines/param_intel.py — Parameter Intelligence Engine v6
# Auto-classifies URL/body parameters by risk level
# Reduces noise, increases accuracy, prioritizes fuzzing
# MilkyWay Intelligence | Author: Sharlix

import re
import urllib.parse
from collections import defaultdict

# ── Parameter risk classification ────────────────────────────────────

PARAM_RISK = {
    # CRITICAL — direct object reference / auth context
    "critical": {
        "idor"        : {"id","user_id","uid","account_id","accountid","profile_id",
                         "order_id","invoice_id","record_id","object_id","resource_id",
                         "userId","accountId","orderId","profileId","pid","cid","eid",
                         "tid","rid","bid","vid","sid","doc_id","file_id","item_id"},
        "auth_bypass" : {"token","access_token","auth_token","session","session_id",
                         "api_key","apikey","key","secret","password","passwd","pwd",
                         "credential","jwt","bearer","authorization"},
        "ssrf"        : {"url","uri","link","src","source","dest","destination",
                         "redirect","return","next","goto","target","callback",
                         "fetch","load","proxy","webhook","endpoint","host","domain"},
        "path_traversal": {"file","path","page","include","load","template","doc",
                            "read","content","filename","dir","lang","module","view",
                            "layout","skin","theme","conf","data","source","ref"},
    },
    # HIGH — injection / execution risk
    "high": {
        "sqli"        : {"query","search","q","filter","where","sort","order",
                         "category","cat","tag","type","status","name","title"},
        "ssti"        : {"template","theme","view","layout","render","format",
                         "output","page","content","body","message"},
        "xss"         : {"msg","message","text","comment","description","note",
                         "value","input","data","info","content","body","html"},
        "redirect"    : {"to","from","back","continue","forward","location",
                         "returnurl","returnto","referer","r","u"},
    },
    # MEDIUM — info leak / lower impact
    "medium": {
        "debug"       : {"debug","verbose","test","mode","dev","trace","log","output"},
        "info_leak"   : {"format","type","version","v","api_version","callback",
                         "jsonp","lang","locale","timezone","tz"},
    },
}

# Flatten for quick lookup
_CRITICAL_PARAMS = set()
_HIGH_PARAMS     = set()
_MEDIUM_PARAMS   = set()
for subcats in PARAM_RISK["critical"].values():
    _CRITICAL_PARAMS.update(subcats)
for subcats in PARAM_RISK["high"].values():
    _HIGH_PARAMS.update(subcats)
for subcats in PARAM_RISK["medium"].values():
    _MEDIUM_PARAMS.update(subcats)

# Attack type per param
_PARAM_ATTACK_TYPE = {}
for attack_type, params in PARAM_RISK["critical"].items():
    for p in params: _PARAM_ATTACK_TYPE[p] = attack_type
for attack_type, params in PARAM_RISK["high"].items():
    for p in params: _PARAM_ATTACK_TYPE.setdefault(p, attack_type)


class ParamIntel:
    """
    Parameter Intelligence Engine.
    
    Classifies URL parameters by attack priority.
    Used to order fuzzing — critical params first.
    """

    def classify(self, param_name: str) -> dict:
        """
        Classify a single parameter.
        Returns: {risk, attack_type, fuzz_priority}
        """
        p = param_name.lower().strip()

        if p in _CRITICAL_PARAMS:
            return {
                "risk"        : "critical",
                "attack_type" : _PARAM_ATTACK_TYPE.get(p, "idor"),
                "fuzz_priority": 1,
            }
        elif p in _HIGH_PARAMS:
            return {
                "risk"        : "high",
                "attack_type" : _PARAM_ATTACK_TYPE.get(p, "sqli"),
                "fuzz_priority": 2,
            }
        elif p in _MEDIUM_PARAMS:
            return {
                "risk"        : "medium",
                "attack_type" : _PARAM_ATTACK_TYPE.get(p, "info_leak"),
                "fuzz_priority": 3,
            }
        else:
            return {
                "risk"        : "low",
                "attack_type" : "generic",
                "fuzz_priority": 4,
            }

    def analyze_url(self, url: str) -> dict:
        """
        Analyze all parameters in a URL.
        Returns sorted list of params with risk classifications.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return {"url": url, "params": [], "highest_risk": "none"}

        params = []
        for param_name, values in qs.items():
            classification = self.classify(param_name)
            params.append({
                "name"   : param_name,
                "value"  : values[0] if values else "",
                **classification,
            })

        # Sort by priority
        params.sort(key=lambda p: p["fuzz_priority"])

        highest = params[0]["risk"] if params else "none"

        return {
            "url"         : url,
            "params"      : params,
            "highest_risk": highest,
            "attack_types": list({p["attack_type"] for p in params if p["risk"] in ("critical","high")}),
        }

    def prioritize_urls(self, urls: list) -> list:
        """
        Sort a list of URLs by parameter risk — highest first.
        Used to focus testing on most vulnerable params first.
        """
        scored = []
        for url in urls:
            analysis = self.analyze_url(url)
            score = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
            scored.append((score.get(analysis["highest_risk"], 0), url, analysis))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [(url, analysis) for _, url, analysis in scored]

    def extract_high_risk(self, urls: list, min_risk: str = "high") -> dict:
        """
        From a list of URLs, extract those with high-risk parameters.
        Returns bucketed by attack type.
        """
        threshold = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_score = threshold.get(min_risk, 3)

        buckets = defaultdict(list)

        for url in urls:
            analysis = self.analyze_url(url)
            for param in analysis["params"]:
                param_score = threshold.get(param["risk"], 1)
                if param_score >= min_score:
                    attack_type = param["attack_type"]
                    buckets[attack_type].append({
                        "url"  : url,
                        "param": param["name"],
                        "risk" : param["risk"],
                    })

        return dict(buckets)

    def get_fuzz_targets(self, url: str) -> list:
        """
        Get ordered list of (param_name, attack_type) to fuzz for a URL.
        """
        analysis = self.analyze_url(url)
        return [
            (p["name"], p["attack_type"])
            for p in analysis["params"]
            if p["risk"] in ("critical", "high")
        ]


# ── JSON body param analysis ──────────────────────────────────────────

def classify_json_body(body: dict, path: str = "") -> list:
    """
    Recursively classify keys in a JSON request body.
    Returns list of risky keys with paths.
    """
    intel = ParamIntel()
    results = []

    for key, value in body.items():
        full_path = f"{path}.{key}" if path else key
        c = intel.classify(key)
        if c["risk"] in ("critical", "high"):
            results.append({
                "path"       : full_path,
                "key"        : key,
                "value"      : str(value)[:50],
                "risk"       : c["risk"],
                "attack_type": c["attack_type"],
            })
        if isinstance(value, dict):
            results.extend(classify_json_body(value, full_path))

    return sorted(results, key=lambda x: {"critical": 0, "high": 1}.get(x["risk"], 2))
