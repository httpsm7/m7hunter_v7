#!/usr/bin/env python3
# modules/step04_ports.py — Port Scan + Service Version + CVE Detection V7
# Strong nmap: -sVC full service scan + CVE lookup via NVD API
# Source: CEH Ch3 + Kali Linux PWK — network scanning methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, shutil, json, time, urllib.request, urllib.parse
from core.utils import count_lines, safe_read, FormatFixer


# ── Service → common CVE patterns ────────────────────────────────────────────
SERVICE_CVE_QUERIES = {
    "apache":     "Apache HTTP Server",
    "nginx":      "nginx",
    "openssh":    "OpenSSH",
    "openssl":    "OpenSSL",
    "php":        "PHP",
    "wordpress":  "WordPress",
    "drupal":     "Drupal",
    "joomla":     "Joomla",
    "tomcat":     "Apache Tomcat",
    "iis":        "Microsoft IIS",
    "mysql":      "MySQL",
    "postgresql": "PostgreSQL",
    "redis":      "Redis",
    "mongodb":    "MongoDB",
    "elasticsearch": "Elasticsearch",
    "jenkins":    "Jenkins",
    "gitlab":     "GitLab",
    "nodejs":     "Node.js",
    "spring":     "Spring Framework",
}

# ── Immediately dangerous services ───────────────────────────────────────────
DANGER_SERVICES = {
    "ftp"       : ("high",    "FTP exposed — unencrypted file transfer"),
    "telnet"    : ("critical","Telnet exposed — plaintext remote access"),
    "smtp"      : ("medium",  "SMTP exposed — mail relay risk"),
    "snmp"      : ("high",    "SNMP exposed — network info disclosure"),
    "rdp"       : ("high",    "RDP exposed — remote desktop attack surface"),
    "vnc"       : ("high",    "VNC exposed — remote desktop unauthenticated"),
    "redis"     : ("critical","Redis exposed — no auth by default, RCE risk"),
    "mongodb"   : ("critical","MongoDB exposed — no auth by default"),
    "memcached" : ("high",    "Memcached exposed — DDoS amplification"),
    "elasticsearch":("critical","Elasticsearch exposed — data leak"),
    "docker"    : ("critical","Docker API exposed — container escape / RCE"),
    "etcd"      : ("critical","etcd exposed — Kubernetes secrets leak"),
    "consul"    : ("high",    "Consul exposed — service mesh control"),
    "zookeeper" : ("high",    "Zookeeper exposed — distributed data leak"),
    "cassandra" : ("high",    "Cassandra exposed — no auth by default"),
    "rsync"     : ("high",    "rsync exposed — file system access"),
}

# ── Port list: common + extended ──────────────────────────────────────────────
COMMON_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
    "1723,3306,3389,5900,6379,8080,8443,8888,9200,27017,"
    "8000,8001,8181,8444,9000,9090,9443,9300,5432,1521,"
    "2375,2376,4243,4567,5000,5001,5601,5672,6380,7001,"
    "7474,8161,8983,9042,9092,9160,11211,15672,27018,50000"
)


class Step04Ports:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p   = self.p
        out = p.files["open_ports"]
        fmt = p.files.get("fmt_host","")
        t   = p.tmgr.get
        found = 0

        # Build target list
        targets = self._get_targets(fmt, p)
        if not targets:
            p.log.warn("Ports: no targets"); return

        p.log.info(f"Port scan: {len(targets)} hosts — naabu + nmap -sVC + CVE lookup")

        # ── Phase 1: Fast port discovery (naabu) ─────────────────
        if shutil.which("naabu"):
            hosts_str = " ".join(f"-host {h}" for h in targets[:20])
            p.shell(
                f"naabu {hosts_str} -p {COMMON_PORTS} "
                f"-silent -rate 5000 -o {out} 2>/dev/null",
                label="naabu fast scan", tool_name="naabu",
                timeout=t("naabu")
            )
        else:
            p.log.warn("naabu not found — using nmap for discovery")

        # ── Phase 2: Strong nmap -sVC ─────────────────────────────
        nmap_out = os.path.join(p.out, f"{p.prefix}_nmap.txt")
        nmap_xml = os.path.join(p.out, f"{p.prefix}_nmap.xml")

        # Build nmap target list
        nmap_targets = []
        if os.path.isfile(out) and count_lines(out) > 0:
            # Use naabu results
            nmap_targets = list(set(
                h.split(":")[0] for h in safe_read(out)[:15] if h.strip()
            ))
        if not nmap_targets:
            nmap_targets = targets[:5]

        targets_str = " ".join(nmap_targets[:10])

        if shutil.which("nmap") and targets_str:
            p.log.info(f"  nmap -sVC on {len(nmap_targets)} hosts...")
            nmap_result = p.shell(
                # NSE scripts from Nmap Scripts book:
                # vuln: CVE detection, banner: service banner,
                # auth: default creds, discovery: service info
                f"nmap -sV -sC --open --min-rate=3000 "
                f"-p {COMMON_PORTS} "
                f"--script="
                f"banner,version,http-title,http-headers,"
                f"http-server-header,ssl-cert,ssh-hostkey,"
                f"ssl-enum-ciphers,http-auth-finder,"
                f"http-methods,http-robots.txt,"
                f"ftp-anon,ftp-bounce,ftp-syst,"
                f"smtp-open-relay,smtp-commands,"
                f"ms-sql-info,mysql-info,mysql-empty-password,"
                f"redis-info,mongodb-info,"
                f"dns-zone-transfer,dns-brute,"
                f"snmp-info,snmp-sysdescr "
                f"-oN {nmap_out} -oX {nmap_xml} "
                f"{targets_str} 2>/dev/null",
                label="nmap -sVC", tool_name="nmap",
                timeout=t("nmap")
            )

            # ── Phase 3: Parse nmap + find danger services ────────
            if os.path.isfile(nmap_out):
                services = self._parse_nmap_services(nmap_out)
                p.log.info(f"  Services found: {len(services)}")

                for host, port, service, version, state in services:
                    # Log discovery
                    p.log.info(f"  {host}:{port} {service} {version}")

                    # Check danger services
                    for svc_key, (sev, msg) in DANGER_SERVICES.items():
                        if svc_key in service.lower():
                            detail = f"{msg} — {host}:{port} {version}"
                            p.add_finding(sev, "EXPOSED_SERVICE",
                                          f"tcp://{host}:{port}", detail,
                                          "nmap-svc", payload=service)
                            found += 1

                    # ── Phase 4: CVE lookup ───────────────────────
                    if version:
                        cves = self._lookup_cves(service, version)
                        for cve_id, cvss, desc in cves:
                            sev = self._cvss_to_severity(cvss)
                            detail = (
                                f"CVE FOUND: {cve_id} (CVSS:{cvss}) | "
                                f"Service: {service} {version} on {host}:{port} | "
                                f"{desc[:120]}"
                            )
                            p.add_finding(sev, "CVE_DETECTED",
                                          f"tcp://{host}:{port}", detail,
                                          "cve-engine",
                                          payload=cve_id)
                            found += 1
                            p.log.finding(sev, "CVE", f"{host}:{port}", detail[:80])

            # Save open ports from nmap if naabu didn't run
            if not os.path.isfile(out) or count_lines(out) == 0:
                p.shell(
                    f"grep -oP '\\d+/open' {nmap_out} 2>/dev/null | "
                    f"head -50 >> {out}",
                    timeout=10
                )

        else:
            p.log.warn("nmap not installed — port scan skipped")
            # Fallback: write target ports from httpx results
            for tgt in targets[:5]:
                with open(out,"a") as f:
                    f.write(f"{tgt}:80\n{tgt}:443\n")

        n = count_lines(out)
        p.log.success(f"Ports: {n} open ports | {found} CVE/service findings")

    # ── Nmap output parser ────────────────────────────────────────────────────
    def _parse_nmap_services(self, nmap_file: str) -> list:
        """
        Parse nmap -sVC output.
        Returns: [(host, port, service, version, state), ...]
        """
        services = []
        current_host = ""

        # Patterns
        host_pat  = re.compile(r"Nmap scan report for (\S+)")
        port_pat  = re.compile(
            r"(\d+)/tcp\s+(open|filtered)\s+(\S+)\s*(.*)"
        )

        try:
            with open(nmap_file) as f:
                for line in f:
                    line = line.strip()
                    hm = host_pat.match(line)
                    if hm:
                        current_host = hm.group(1)
                        # Strip parenthetical IP
                        if "(" in current_host:
                            current_host = current_host.split("(")[0].strip()
                        continue
                    pm = port_pat.match(line)
                    if pm and current_host:
                        port    = pm.group(1)
                        state   = pm.group(2)
                        service = pm.group(3).lower()
                        version = pm.group(4).strip()[:80]
                        services.append((current_host, port, service, version, state))
        except Exception:
            pass
        return services

    # ── CVE lookup via NIST NVD API ───────────────────────────────────────────
    def _lookup_cves(self, service: str, version: str,
                     max_results: int = 5) -> list:
        """
        Query NIST NVD API for CVEs affecting service+version.
        Returns: [(cve_id, cvss_score, description), ...]
        """
        # Build search keyword
        keyword = self._build_cve_query(service, version)
        if not keyword:
            return []

        try:
            url = (
                "https://services.nvd.nist.gov/rest/json/cves/2.0?"
                f"keywordSearch={urllib.parse.quote(keyword)}"
                f"&resultsPerPage={max_results}"
            )
            req  = urllib.request.Request(url, headers={
                "User-Agent": "M7Hunter/7.0 (security research)"
            })
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())

            cves = []
            for vuln in data.get("vulnerabilities", [])[:max_results]:
                cve  = vuln.get("cve", {})
                cid  = cve.get("id", "")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value","")[:150]
                        break

                # Get CVSS score
                cvss = self._extract_cvss(cve)

                # Only report if CVSS >= 7.0 (High/Critical)
                if cvss and float(cvss) >= 7.0:
                    cves.append((cid, cvss, desc))

            time.sleep(0.3)  # NVD rate limit: 5 req/30s without API key
            return cves

        except Exception:
            return []

    def _build_cve_query(self, service: str, version: str) -> str:
        """Build smart CVE search query from service name + version."""
        # Normalize service name
        for key, proper in SERVICE_CVE_QUERIES.items():
            if key in service.lower():
                # Extract version numbers
                ver_match = re.search(r"\d+\.\d+[\.\d]*", version)
                if ver_match:
                    return f"{proper} {ver_match.group()}"
                return proper
        return ""

    def _extract_cvss(self, cve: dict) -> str:
        """Extract highest CVSS score from CVE data."""
        metrics = cve.get("metrics", {})
        for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            m = metrics.get(key, [])
            if m:
                score = m[0].get("cvssData",{}).get("baseScore")
                if score:
                    return str(score)
        return "0"

    def _cvss_to_severity(self, cvss: str) -> str:
        try:
            score = float(cvss)
            if score >= 9.0: return "critical"
            if score >= 7.0: return "high"
            if score >= 4.0: return "medium"
            return "low"
        except Exception:
            return "medium"

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _get_targets(self, fmt_host: str, p) -> list:
        targets = []
        if fmt_host and os.path.isfile(fmt_host):
            targets = safe_read(fmt_host)[:20]

        if not targets:
            # Fallback to target domain
            raw = p.target.replace("https://","").replace("http://","").split("/")[0]
            targets = [raw]

        return [t.strip() for t in targets if t.strip()]
