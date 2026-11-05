#!/usr/bin/env python3
# modules/step13_takeover.py — Subdomain Takeover V7 (UPGRADED)
# Expanded to 50+ fingerprints, added DNS-based detection, NS takeover
# Source: Bug Hunter's Methodology (Jason Haddix) — full takeover checklist
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, socket
from core.utils import safe_read, count_lines
from core.http_client import sync_get

# ── 50+ Service Fingerprints (Bug Hunter Methodology) ─────────────────────────
# Format: (service_key, cname_regex, body_signature, service_name, registerable)
TAKEOVER_FINGERPRINTS = [
    # Cloud hosting
    ("github",      r"github\.io",           "There isn't a GitHub Pages site here",       "GitHub Pages",      True),
    ("heroku",      r"heroku",               "No such app",                                 "Heroku",            True),
    ("netlify",     r"netlify\.(app|com)",   "Not Found",                                   "Netlify",           True),
    ("vercel",      r"vercel\.app",          "The deployment could not be found",           "Vercel",            True),
    ("render",      r"render\.com",          "Page not found",                              "Render",            True),
    ("surge",       r"surge\.sh",            "project not found",                           "Surge.sh",          True),
    # E-commerce
    ("shopify",     r"myshopify\.com",       "Sorry, this shop is currently unavailable",   "Shopify",           True),
    ("bigcartel",   r"bigcartel\.com",       "Oops! We couldn&#8217;t find that page",      "BigCartel",         True),
    ("squarespace", r"squarespace\.com",     "No Such Account",                             "Squarespace",       True),
    # CMS / Blog
    ("wordpress",   r"wordpress\.com",       "Do you want to register",                     "WordPress.com",     True),
    ("ghost",       r"ghost\.io",            "404",                                         "Ghost",             True),
    ("tumblr",      r"tumblr\.com",          "There's nothing here",                        "Tumblr",            True),
    ("medium",      r"medium\.com",          "Publication not found",                       "Medium",            True),
    ("webflow",     r"webflow\.io",          "The page you are looking for doesn't exist",  "Webflow",           True),
    # CDN/Static
    ("fastly",      r"fastly",              "Fastly error: unknown domain",                 "Fastly",            False),
    ("cloudfront",  r"cloudfront\.net",     "ERROR: The request could not be satisfied",   "CloudFront",        False),
    ("azurefd",     r"azurefd\.net",        "Troubleshooting information",                 "Azure Front Door",  False),
    # Cloud Storage
    ("s3",          r"s3\.amazonaws\.com",  "NoSuchBucket",                                "AWS S3",            True),
    ("gcs",         r"storage\.googleapis", "NoSuchBucket|The specified bucket",          "Google Cloud Storage",True),
    ("azure_blob",  r"blob\.core\.windows", "BlobNotFound|ContainerNotFound",             "Azure Blob",        True),
    # Cloud Apps
    ("azure",       r"azurewebsites\.net",  "404 Web Site not found",                      "Azure Web Apps",    True),
    ("azureclassic",r"cloudapp\.net",       "404 - Web app",                               "Azure Classic",     True),
    ("elastic",     r"elasticbeanstalk",    "There is no application",                     "AWS Elastic Beanstalk",True),
    # Support / Docs
    ("zendesk",     r"zendesk\.com",        "Help Center Closed",                          "Zendesk",           True),
    ("helpjuice",   r"helpjuice\.com",      "We could not find what you're looking for",   "HelpJuice",         True),
    ("helpscout",   r"helpscoutdocs\.com",  "No settings were found",                      "HelpScout",         True),
    ("readme",      r"readme\.io",          "Project doesnt exist",                        "Readme.io",         True),
    ("gitbook",     r"gitbook\.io",         "if you need to know more",                    "GitBook",           True),
    # Marketing
    ("hubspot",     r"hubspot\.net",        "Domain not found",                            "HubSpot",           True),
    ("mailchimp",   r"list-manage\.com",    "Oops! That page doesn't exist",               "Mailchimp",         True),
    ("campaignmonitor",r"createsend\.com",  "Double-check the URL",                        "CampaignMonitor",   True),
    ("activecampaign",r"activehosted\.com", "The requested URL was not found",             "ActiveCampaign",    True),
    # Analytics / Feedback
    ("canny",       r"canny\.io",           "Company Not Found",                           "Canny",             True),
    ("statuspage",  r"statuspage\.io",      "You are being redirected",                    "Statuspage.io",     True),
    ("pingdom",     r"pingdom\.com",        "This public report page has not been shared", "Pingdom",           True),
    ("uptime",      r"uptime\.com",         "No Site For Domain",                          "Uptime.com",        True),
    # CI/CD
    ("jenkins",     r"jenkins\.io",         "Error 404",                                   "Jenkins",           False),
    ("teamcity",    r"teamcity",            "TeamCity",                                    "TeamCity",          False),
    # Other
    ("pantheon",    r"pantheonsite\.io",    "The gods are wise",                           "Pantheon",          True),
    ("bitbucket",   r"bitbucket\.io",       "Repository not found",                        "Bitbucket",         True),
    ("unbounce",    r"unbounce\.com",       "The requested URL was not found",             "Unbounce",          True),
    ("feedpress",   r"feedpress\.me",       "The feed has not been found",                 "FeedPress",         True),
    ("smartjobboard",r"smartjobboard\.com", "This job board website is either",            "SmartJobBoard",     True),
    ("kinsta",      r"kinsta\.cloud",       "No Site For Domain",                          "Kinsta",            True),
    ("launchrock",  r"launchrock\.com",     "It looks like you may have taken",            "Launchrock",        True),
    ("strikingly",  r"strikingly\.com",     "PAGE NOT FOUND",                              "Strikingly",        True),
    ("cargo",       r"cargocollective\.com","404 Not Found",                               "Cargo",             True),
    ("intercom",    r"custom\.intercom\.help","Uh oh. That page doesn't exist",            "Intercom",          True),
    ("tave",        r"clientaccess\.tave",  "Error 404",                                   "Tave",              True),
]

# ── NXDOMAIN-based takeover (DNS not resolving) ───────────────────────────────
# If CNAME points to service that no longer exists → NXDOMAIN → takeover
NXDOMAIN_SERVICES = {
    "github.io", "heroku.com", "netlify.app", "surge.sh",
    "myshopify.com", "s3.amazonaws.com", "azurewebsites.net",
}

# ── NS-based takeover (dangling nameserver) ───────────────────────────────────
# If NS record points to expired/unregistered nameserver → can register it
NS_TAKEOVER_PATTERNS = [
    r"SERVFAIL",
    r"NXDOMAIN",
]


class Step13Takeover:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["takeover_results"]
        subs  = p.files.get("subdomains","")
        dns   = p.files.get("dns_records","")
        found = 0

        subdomains = safe_read(subs)
        if not subdomains:
            p.log.warn("Takeover: no subdomains"); return

        p.log.info(f"Takeover V7: {len(subdomains)} subs × 50 fingerprints + DNS + NS checks")

        # Method 1: subzy fast scan
        p.shell(
            f"subzy run --targets {subs} --concurrency 20 --hide-fails 2>/dev/null",
            label="subzy", tool_name="subzy",
            append_file=out, timeout=p.tmgr.get("subzy")
        )

        # Method 2: CNAME + body fingerprint (50 services)
        for sub in subdomains[:100]:
            sub = sub.strip()
            if not sub: continue

            # DNS check first (fast)
            cname   = self._get_cname(sub)
            nxdomain = self._is_nxdomain(sub)

            if nxdomain:
                # NXDOMAIN = DNS not resolving → check if CNAME pointed to takeable service
                for svc, cname_re, _, svc_name, can_register in TAKEOVER_FINGERPRINTS:
                    if cname and re.search(cname_re, cname, re.I) and can_register:
                        detail = (f"NXDOMAIN takeover: {sub} → CNAME={cname} "
                                  f"(NXDOMAIN) via {svc_name} — "
                                  f"register the {svc_name} account to claim")
                        with open(out,"a") as f:
                            f.write(f"TAKEOVER_NXDOMAIN_{svc.upper()}: {sub} | {detail}\n")
                        p.add_finding("critical","SUBDOMAIN_TAKEOVER_NXDOMAIN",
                                      f"https://{sub}", detail, "takeover-v7")
                        found += 1
                        break
                continue

            # HTTP-based fingerprint check
            for scheme in ["https","http"]:
                host_url = f"{scheme}://{sub}"
                resp = sync_get(host_url, timeout=8, follow_redirects=True)
                if not resp or resp.get("status",0) == 0:
                    continue
                body = resp.get("body","")
                headers = str(resp.get("headers",{})).lower()

                for svc, cname_re, body_sig, svc_name, can_register in TAKEOVER_FINGERPRINTS:
                    cname_match = cname and re.search(cname_re, cname, re.I)
                    body_match  = re.search(re.escape(body_sig), body, re.I)

                    if body_match and (cname_match or True):
                        sev    = "critical" if can_register else "high"
                        detail = (
                            f"Subdomain takeover via {svc_name}: "
                            f"body='{body_sig[:40]}' "
                            f"{'CNAME='+cname if cname else 'no CNAME'} — "
                            f"{'register account to claim' if can_register else 'contact provider'}"
                        )
                        with open(out,"a") as f:
                            f.write(f"TAKEOVER_{svc.upper()}: {host_url} | {detail}\n")
                        p.add_finding(sev,"SUBDOMAIN_TAKEOVER",
                                      host_url, detail, "takeover-v7")
                        found += 1
                        break
                break

        # Method 3: NS-based takeover check (Bug Hunter Methodology)
        found += self._check_ns_takeover(subdomains[:30], out)

        p.log.success(f"Takeover V7: {found} vulnerable subdomains")

    def _get_cname(self, subdomain: str) -> str:
        """Get CNAME record for subdomain."""
        try:
            result = self.p.shell(
                f"dig +short CNAME {subdomain} 2>/dev/null", label="")
            return result.strip().rstrip(".") if result else ""
        except Exception:
            return ""

    def _is_nxdomain(self, subdomain: str) -> bool:
        """Check if subdomain resolves (False = resolves, True = NXDOMAIN)."""
        try:
            socket.gethostbyname(subdomain)
            return False
        except socket.gaierror:
            return True
        except Exception:
            return False

    def _check_ns_takeover(self, subdomains: list, out: str) -> int:
        """
        Bug Hunter Methodology: dangling NS records.
        If NS server is unregistered → attacker can register it → NS takeover.
        """
        found = 0
        base = self.p.target.split(".")[-2] + "." + self.p.target.split(".")[-1]

        ns_result = self.p.shell(
            f"dig +short NS {base} 2>/dev/null", label="ns check")

        if not ns_result: return 0

        for ns in ns_result.strip().split("\n"):
            ns = ns.strip().rstrip(".")
            if not ns: continue
            if self._is_nxdomain(ns):
                detail = (f"NS takeover: nameserver '{ns}' for {base} "
                          f"does not resolve (NXDOMAIN) — "
                          f"register '{ns}' domain to hijack all DNS for {base}")
                with open(out,"a") as f:
                    f.write(f"NS_TAKEOVER: {base} | {detail}\n")
                self.p.add_finding("critical","NS_TAKEOVER",
                                   f"https://{base}", detail, "ns-takeover", response=response, payload=payload)
                found += 1

        return found
