import os
#!/usr/bin/env python3
# modules/step13_takeover.py — Subdomain Takeover (subzy + manual)
# MilkyWay Intelligence | Author: Sharlix

import re
from core.utils import safe_read, count_lines
from core.http_client import sync_get

# Fingerprints: service → (cname_pattern, body_pattern, takeover_msg)
TAKEOVER_FINGERPRINTS = [
    ("github",     r"github\.io",        "There isn't a GitHub Pages site here",   "GitHub Pages"),
    ("heroku",     r"heroku",            "No such app",                             "Heroku"),
    ("shopify",    r"myshopify\.com",    "Sorry, this shop is currently unavailable","Shopify"),
    ("fastly",     r"fastly",            "Fastly error: unknown domain",            "Fastly"),
    ("pantheon",   r"pantheonsite\.io",  "The gods are wise",                       "Pantheon"),
    ("readme",     r"readme\.io",        "Project doesnt exist",                    "Readme.io"),
    ("surge",      r"surge\.sh",         "project not found",                       "Surge.sh"),
    ("bitbucket",  r"bitbucket\.io",     "Repository not found",                    "Bitbucket"),
    ("zendesk",    r"zendesk\.com",      "Help Center Closed",                      "Zendesk"),
    ("wordpress",  r"wordpress\.com",    "Do you want to register",                 "WordPress.com"),
    ("s3",         r"s3\.amazonaws\.com","NoSuchBucket",                            "AWS S3"),
    ("azure",      r"azurewebsites\.net","404 Web Site not found",                  "Azure"),
    ("ghost",      r"ghost\.io",         "404",                                     "Ghost"),
    ("helpjuice",  r"helpjuice\.com",    "We could not find what you're looking for","HelpJuice"),
    ("hubspot",    r"hubspot\.net",      "Domain not found",                        "HubSpot"),
    ("tumblr",     r"tumblr\.com",       "There's nothing here",                    "Tumblr"),
    ("unbounce",   r"unbounce\.com",     "The requested URL was not found",         "Unbounce"),
    ("pingdom",    r"pingdom\.com",      "This public report page has not been shared","Pingdom"),
    ("campaignmonitor",r"createsend\.com","Double-check the URL",                   "CampaignMonitor"),
    ("netlify",    r"netlify",           "Not Found",                               "Netlify"),
]


class Step13Takeover:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["takeover_results"]
        subs  = p.files.get("subdomains", "")
        dns   = p.files.get("dns_records", "")
        found = 0

        subdomains = safe_read(subs)
        if not subdomains:
            p.log.warn("Takeover: no subdomains"); return

        p.log.info(f"Takeover check: {len(subdomains)} subdomains")

        # Method 1: subzy (fast)
        p.shell(
            f"subzy run --targets {subs} --concurrency 20 --hide-fails 2>/dev/null",
            label="subzy", tool_name="subzy",
            append_file=out, timeout=p.tmgr.get("subzy")
        )

        # Method 2: Manual fingerprint check
        for sub in subdomains[:50]:
            sub = sub.strip()
            if not sub:
                continue
            for host in [f"https://{sub}", f"http://{sub}"]:
                resp = sync_get(host, timeout=6, follow_redirects=True)
                if not resp or resp.get("status", 0) == 0:
                    continue
                body = resp.get("body", "")
                hdrs = str(resp.get("headers", {})).lower()

                for svc, cname_re, body_sig, svc_name in TAKEOVER_FINGERPRINTS:
                    # Check body signature
                    if re.search(re.escape(body_sig), body, re.IGNORECASE):
                        detail = (f"Subdomain takeover via {svc_name}: "
                                  f"'{body_sig}' in response — "
                                  f"register the account/repo to claim")
                        with open(out, "a") as f:
                            f.write(f"TAKEOVER_{svc.upper()}: {host} | {detail}\n")
                        p.add_finding("critical", "SUBDOMAIN_TAKEOVER", host,
                                      detail, "takeover-engine")
                        found += 1
                        break

                # Check CNAME from DNS records
                if dns and os.path.isfile(dns):
                    dns_data = open(dns).read()
                    for svc, cname_re, _, svc_name in TAKEOVER_FINGERPRINTS:
                        if (re.search(sub, dns_data) and
                                re.search(cname_re, dns_data, re.IGNORECASE)):
                            # Already found via body check above
                            pass
                break  # Only test HTTPS, then HTTP

        # Parse subzy output
        self._parse_subzy(out)

        p.log.success(f"Takeover: {found} vulnerable subdomains")

    def _parse_subzy(self, out: str):
        import os
        if not os.path.isfile(out):
            return
        with open(out) as f:
            for line in f:
                line = line.strip()
                if "VULNERABLE" in line.upper() or "[TAKEOVER]" in line.upper():
                    urls = re.findall(r'https?://\S+', line)
                    if urls:
                        self.p.add_finding("critical", "SUBDOMAIN_TAKEOVER",
                                           urls[0], line[:100], "subzy")

