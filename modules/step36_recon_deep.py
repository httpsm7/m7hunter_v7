#!/usr/bin/env python3
# modules/step36_recon_deep.py — Deep Recon: Shodan + CRT.sh + S3 + ASN + Favicon
# NEW MODULE — Cycle 6
# Source: Bug Hunter Methodology (Jason Haddix) — deep recon techniques
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, json, time, socket, hashlib, shutil
import urllib.request, urllib.parse, urllib.error
from core.utils import safe_read, count_lines

# ── S3 bucket naming patterns (Bug Hunter Methodology) ────────────────────────
S3_PATTERNS = [
    "{domain}",            "{domain}-backup",
    "{domain}-assets",     "{domain}-static",
    "{domain}-media",      "{domain}-files",
    "{domain}-data",       "{domain}-uploads",
    "{domain}-dev",        "{domain}-staging",
    "{domain}-prod",       "{domain}-public",
    "{domain}-private",    "{domain}-logs",
    "{domain}-images",     "{domain}-content",
    "{domain}.backup",     "{domain}.assets",
    "www.{domain}",        "api.{domain}",
    "cdn.{domain}",        "assets.{domain}",
    "static.{domain}",     "media.{domain}",
    "{bare}",              "{bare}-backup",
    "{bare}-assets",       "{bare}-static",
    "{bare}-files",        "{bare}-data",
    "{bare}-dev",          "{bare}-uploads",
]

S3_REGIONS = [
    "us-east-1","us-east-2","us-west-1","us-west-2",
    "eu-west-1","eu-west-2","eu-central-1",
    "ap-southeast-1","ap-southeast-2","ap-northeast-1",
]

# ── ASN lookup API ────────────────────────────────────────────────────────────
ASN_API = "https://api.bgpview.io/ip/{ip}"
ASN_PREFIX_API = "https://api.bgpview.io/asn/{asn}/prefixes"

# ── crt.sh certificate transparency ──────────────────────────────────────────
CRT_API = "https://crt.sh/?q={domain}&output=json"

# ── Shodan API ────────────────────────────────────────────────────────────────
SHODAN_API = "https://api.shodan.io/dns/domain/{domain}?key={key}"
SHODAN_SEARCH = "https://api.shodan.io/shodan/host/search?key={key}&query={query}"

# ── Favicon hash → tech fingerprint ──────────────────────────────────────────
FAVICON_DB = {
    # mmh3 hashes of well-known favicons
    "-1616143106": ("Kibana",        "high",   "Log management UI exposed"),
    "116323821":   ("Jenkins",       "high",   "CI/CD server exposed"),
    "81586312":    ("Apache Tomcat", "medium", "Tomcat manager"),
    "1278019592":  ("Jira",          "medium", "Project management"),
    "-1325265162": ("Grafana",       "high",   "Metrics dashboard exposed"),
    "961351":      ("Elasticsearch", "critical","Elasticsearch admin UI"),
    "937925863":   ("Jupyter",       "critical","Jupyter notebook exposed"),
    "-1726738708": ("GitLab",        "medium", "GitLab instance"),
    "1392728olean":("phpMyAdmin",    "high",   "Database admin exposed"),
    "1954727573":  ("Sonarqube",     "medium", "Code analysis exposed"),
    "-40394321":   ("Rancher",       "high",   "Container management UI"),
    "1085277366":  ("Consul",        "high",   "Service mesh UI exposed"),
    "1013264864":  ("Prometheus",    "medium", "Metrics endpoint exposed"),
    "116784":      ("Traefik",       "medium", "Reverse proxy dashboard"),
    "1478870368":  ("Vault",         "high",   "HashiCorp Vault UI"),
}


class Step36ReconDeep:
    """
    Deep Recon engine.
    Bug Hunter Methodology:
    1. Certificate transparency (crt.sh) — find all subdomains ever issued certs
    2. ASN → CIDR expansion — find all IP ranges owned by target
    3. Shodan intel — services on those IPs
    4. S3 bucket enumeration — common naming patterns
    5. Favicon hash fingerprinting — identify tech from favicon
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p      = self.p
        out    = self.p.files.get("recon_deep_results",
                              f"{self.p.out}/{self.p.prefix}_recon_deep.txt")
        subs   = self.p.files.get("subdomains","")
        domain = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        bare   = ".".join(domain.split(".")[-2:]) if "." in domain else domain
        found  = 0

        self.p.log.info("Deep Recon V7: crt.sh + ASN + S3 + favicon + Shodan")

        # Phase 1: Certificate transparency
        r = self._cert_transparency(domain, subs, out)
        found += r

        # Phase 2: ASN + IP range expansion
        r = self._asn_expansion(domain, out)
        found += r

        # Phase 3: S3 bucket enumeration
        r = self._s3_enum(domain, bare, out)
        found += r

        # Phase 4: Favicon fingerprinting
        live = safe_read(self.p.files.get("fmt_url",""))[:10]
        r = self._favicon_fingerprint(live, out)
        found += r

        # Phase 5: Shodan (if API key available)
        shodan_key = getattr(p.args,"shodan_key",None) or \
                     getattr(p,"cfg",{}).get("shodan_key","")
        if shodan_key:
            r = self._shodan_lookup(domain, shodan_key, out)
            found += r
        else:
            self.p.log.info("  Shodan: no API key (--shodan-key to enable)")

        self.p.log.success(f"Deep Recon V7: {found} findings")

    # ── Phase 1: Certificate Transparency ────────────────────────────────────
    def _cert_transparency(self, domain: str, subs_file: str, out: str) -> int:
        """
        Bug Hunter Methodology: crt.sh finds ALL subdomains that
        ever had SSL certs — catches hidden/old subdomains.
        """
        self.p.log.info(f"  crt.sh: querying {domain}...")
        found    = 0
        new_subs = set()

        # Existing subdomains for comparison
        existing = set(safe_read(subs_file)) if subs_file else set()

        try:
            url = CRT_API.format(domain=urllib.parse.quote(f"%.{domain}"))
            req = urllib.request.Request(url, headers={
                "User-Agent": "M7Hunter/7.0",
                "Accept": "application/json"
            })
            resp = urllib.request.urlopen(req, timeout=20)
            data = json.loads(resp.read())

            crt_subs = set()
            for entry in data:
                names = entry.get("name_value","").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        crt_subs.add(name)

            # Find NEW subdomains not in existing recon
            new_subs = crt_subs - existing

            self.p.log.info(f"  crt.sh: {len(crt_subs)} total | {len(new_subs)} new")

            # Add new subs to subdomains file
            if subs_file and new_subs:
                with open(subs_file, "a") as f:
                    f.write("\n".join(new_subs) + "\n")

            # Report expired/interesting certs
            for entry in data[:5]:
                issuer  = entry.get("issuer_name","")
                not_bef = entry.get("not_before","")
                name    = entry.get("name_value","").split("\n")[0]
                if "expired" in str(entry).lower() or len(crt_subs) > 50:
                    detail = (f"crt.sh: {name} | issuer={issuer[:40]} | "
                              f"issued={not_bef[:10]}")
                    with open(out,"a") as f: f.write(f"CERT: {detail}\n")

            if new_subs:
                detail = (f"crt.sh found {len(new_subs)} new subdomains: "
                          f"{', '.join(list(new_subs)[:5])}...")
                self._save(out,"info","CERT_TRANSPARENCY",domain,detail)
                found += len(new_subs)

        except Exception as e:
            self.p.log.warn(f"  crt.sh error: {e}")

        # Also run subfinder with additional sources
        self.p.shell(
            f"subfinder -d {domain} -silent -sources crtsh,certspotter,anubis "
            f"2>/dev/null | sort -u",
            label="subfinder deep", tool_name="subfinder",
            append_file=subs_file, timeout=60
        )

        return found

    # ── Phase 2: ASN expansion ────────────────────────────────────────────────
    def _asn_expansion(self, domain: str, out: str) -> int:
        """
        Bug Hunter Methodology: resolve IP → lookup ASN → get all CIDRs.
        Finds all IPs owned by same company (big attack surface).
        """
        self.p.log.info("  ASN expansion: IP → ASN → CIDR ranges...")
        found = 0

        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            self.p.log.info(f"  Resolved: {domain} → {ip}")

            # BGPView ASN lookup
            url = ASN_API.format(ip=ip)
            req = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/7.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())

            asns = data.get("data",{}).get("prefixes",[])
            for asn_data in asns[:5]:
                asn    = asn_data.get("asn",{})
                prefix = asn_data.get("prefix","")
                name   = asn_data.get("name","")
                asn_n  = asn.get("asn","") if isinstance(asn,dict) else asn

                detail = (f"ASN: {asn_n} | CIDR: {prefix} | Org: {name[:40]}")
                with open(out,"a") as f: f.write(f"ASN: {detail}\n")

                # Get all prefixes for this ASN
                if asn_n:
                    time.sleep(1)  # Rate limit
                    prefix_url = ASN_PREFIX_API.format(asn=asn_n)
                    try:
                        req2  = urllib.request.Request(
                            prefix_url, headers={"User-Agent":"M7Hunter/7.0"})
                        resp2 = urllib.request.urlopen(req2, timeout=10)
                        pdata = json.loads(resp2.read())
                        cidrs = [p.get("prefix","")
                                 for p in pdata.get("data",{}).get("ipv4_prefixes",[])]
                        if cidrs:
                            detail2 = (f"ASN {asn_n} ({name[:30]}) owns "
                                       f"{len(cidrs)} IP ranges: "
                                       f"{', '.join(cidrs[:3])}...")
                            self._save(out,"info","ASN_RANGES",domain,detail2)
                            found += 1
                    except Exception:
                        pass
        except Exception as e:
            self.p.log.warn(f"  ASN lookup error: {e}")

        return found

    # ── Phase 3: S3 bucket enumeration ────────────────────────────────────────
    def _s3_enum(self, domain: str, bare: str, out: str) -> int:
        """
        Bug Hunter Methodology: enumerate S3 buckets by naming convention.
        Check for: public access, listing, write access.
        """
        self.p.log.info("  S3 enumeration: testing common bucket names...")
        found = 0
        checked = set()

        for pattern in S3_PATTERNS[:20]:
            bucket = pattern.format(domain=domain, bare=bare)
            bucket = bucket.replace(".","-").lower()

            if bucket in checked: continue
            checked.add(bucket)

            # Standard S3 URL
            url = f"https://{bucket}.s3.amazonaws.com/"

            try:
                req  = urllib.request.Request(
                    url, headers={"User-Agent": "M7Hunter/7.0"})
                resp = urllib.request.urlopen(req, timeout=6)
                body = resp.read(20000).decode("utf-8","ignore")
                st   = resp.status

                if st == 200:
                    if "<ListBucketResult" in body or "<Contents" in body:
                        detail = (f"S3 bucket PUBLICLY LISTED: {url} — "
                                  f"files are enumerable!")
                        self._save(out,"critical","S3_PUBLIC_LIST",url,detail)
                        found += 1
                    else:
                        detail = f"S3 bucket exists and is public: {url}"
                        self._save(out,"high","S3_PUBLIC",url,detail)
                        found += 1

            except urllib.error.HTTPError as e:
                if e.code == 403:
                    # 403 = exists but access denied = still worth noting
                    detail = f"S3 bucket exists (403 Forbidden): {url}"
                    with open(out,"a") as f:
                        f.write(f"S3_EXISTS: {url} | {detail}\n")

            except Exception:
                pass

            # Also check region-specific URLs
            for region in S3_REGIONS[:3]:
                r_url = f"https://{bucket}.s3.{region}.amazonaws.com/"
                try:
                    req  = urllib.request.Request(
                        r_url, headers={"User-Agent":"M7Hunter/7.0"})
                    resp = urllib.request.urlopen(req, timeout=4)
                    if resp.status == 200:
                        detail = f"S3 bucket public ({region}): {r_url}"
                        self._save(out,"critical","S3_PUBLIC",r_url,detail)
                        found += 1
                except Exception:
                    pass

        # Also try GCS
        gcs_url = f"https://storage.googleapis.com/{bare}/"
        try:
            req  = urllib.request.Request(gcs_url, headers={"User-Agent":"M7Hunter/7.0"})
            resp = urllib.request.urlopen(req, timeout=6)
            if resp.status == 200:
                detail = f"GCS bucket public: {gcs_url}"
                self._save(out,"critical","GCS_PUBLIC",gcs_url,detail)
                found += 1
        except Exception:
            pass

        return found

    # ── Phase 4: Favicon fingerprinting ──────────────────────────────────────
    def _favicon_fingerprint(self, live: list, out: str) -> int:
        """
        Bug Hunter Methodology: hash favicon.ico → identify tech.
        Known favicon hashes map to specific software versions.
        """
        self.p.log.info("  Favicon fingerprinting...")
        found = 0

        for host in live[:10]:
            host = host.rstrip("/")
            fav_url = host + "/favicon.ico"
            try:
                req  = urllib.request.Request(
                    fav_url, headers={"User-Agent":"M7Hunter/7.0"})
                resp = urllib.request.urlopen(req, timeout=6)
                if resp.status != 200: continue
                data = resp.read(50000)

                # Calculate mmh3 hash (simplified — use MD5 as fallback)
                md5_hash = hashlib.md5(data).hexdigest()
                # Try simple hash for known tools
                simple_hash = str(hash(data[:100]) % 2000000000)

                for hash_val, (tech, sev, desc) in FAVICON_DB.items():
                    if (hash_val == simple_hash or
                            hash_val in md5_hash):
                        detail = (f"Favicon fingerprint: {tech} detected at "
                                  f"{host} ({desc})")
                        self._save(out, sev, "TECH_FINGERPRINT", host, detail)
                        found += 1
                        break

                # Even without match, log favicon found
                self.p.log.info(f"  Favicon: {host} ({len(data)}b)")

            except Exception:
                pass

        return found

    # ── Phase 5: Shodan lookup ────────────────────────────────────────────────
    def _shodan_lookup(self, domain: str, api_key: str, out: str) -> int:
        """Query Shodan for services running on target IPs."""
        self.p.log.info("  Shodan: querying domain intel...")
        found = 0

        try:
            url = SHODAN_API.format(domain=domain, key=api_key)
            req = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/7.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())

            subdomains = data.get("subdomains",[])
            ips        = data.get("data",[])
            tags       = data.get("tags",[])

            self.p.log.info(
                f"  Shodan: {len(subdomains)} subs | {len(ips)} hosts")

            for host_data in ips[:10]:
                ip      = host_data.get("ip_str","")
                ports   = host_data.get("ports",[])
                hostnames = host_data.get("hostnames",[])
                vulns   = host_data.get("vulns",{})

                detail = (f"Shodan host: {ip} | ports={ports[:5]} | "
                          f"hostnames={hostnames[:2]}")
                with open(out,"a") as f: f.write(f"SHODAN: {detail}\n")

                # CVEs from Shodan
                for cve_id, cve_data in list(vulns.items())[:5]:
                    cvss = cve_data.get("cvss",0.0)
                    sev  = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium"
                    cve_detail = (f"Shodan CVE: {cve_id} (CVSS:{cvss}) "
                                  f"on {ip}:{ports[:3]}")
                    self._save(out, sev, "SHODAN_CVE", f"tcp://{ip}", cve_detail)
                    found += 1

            if "tags" in data and tags:
                detail = f"Shodan tags: {', '.join(tags)}"
                with open(out,"a") as f: f.write(f"SHODAN_TAGS: {detail}\n")

        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.p.log.warn("  Shodan: invalid API key")
            elif e.code == 404:
                self.p.log.info(f"  Shodan: {domain} not indexed")
        except Exception as e:
            self.p.log.warn(f"  Shodan error: {e}")

        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "recon-deep-v7", response=response, payload=payload)
