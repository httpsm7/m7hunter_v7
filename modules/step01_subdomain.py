#!/usr/bin/env python3
# modules/step01_subdomain.py — Subdomain Enumeration
# Tools: subfinder, amass, dnsx, assetfinder
# MilkyWay Intelligence | Author: Sharlix

import os
from core.utils import count_lines, FormatFixer


class Step01Subdomain:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        tgt  = p.target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        out  = p.files["subdomains"]
        fmt  = p.files["fmt_domain"]
        t    = p.tmgr.get

        p.log.info(f"Subdomain enum: {tgt}")

        # subfinder
        p.shell(
            f"subfinder -d {tgt} -silent -all -recursive -t 50 "
            f"-o {out} 2>/dev/null",
            label="subfinder", tool_name="subfinder",
            append_file=out, timeout=t("subfinder")
        )

        # assetfinder
        p.shell(
            f"assetfinder --subs-only {tgt} 2>/dev/null",
            label="assetfinder", tool_name="subfinder",
            append_file=out, timeout=60
        )

        # amass passive
        p.shell(
            f"amass enum -passive -d {tgt} -o /tmp/amass_tmp.txt 2>/dev/null "
            f"&& cat /tmp/amass_tmp.txt >> {out}",
            label="amass passive", tool_name="amass",
            timeout=t("amass")
        )

        # crt.sh
        p.shell(
            f'curl -s "https://crt.sh/?q=%.{tgt}&output=json" 2>/dev/null '
            f'| python3 -c "import sys,json; '
            f'[print(e[\'name_value\']) for e in json.load(sys.stdin) if \'name_value\' in e]" '
            f'2>/dev/null',
            label="crt.sh", append_file=out, timeout=30
        )

        # Deduplicate
        FormatFixer.fix(out, fmt, 'domain')
        n = count_lines(fmt)
        # Python fallback: runs when tools are missing or produce nothing
        if count_lines(subs) == 0:
            self.p.log.warn("  step01: no tools found — using Python subdomain fallback")
            self._python_subdomain_fallback(domain, subs)
        elif count_lines(subs) < 3:
            # Supplement with crt.sh even if some tools ran
            self._python_subdomain_fallback(domain, subs)

        p.log.success(f"Subdomains found: {n}")
        if n == 0:
            p.log.warn("No subdomains — check target format (use domain.com not https://)")


class SubdomainPermutator:
    """
    Bug Hunter Methodology (Jason Haddix): Wide recon via permutation.
    Generates subdomain wordlist from known subs + common prefixes.
    Replaces manual guessing with systematic permutation scanning.
    """

    PREFIXES = [
        "dev","api","staging","prod","test","qa","beta","admin","app","internal",
        "mail","vpn","ftp","cdn","static","media","img","assets","portal","login",
        "auth","sso","cloud","git","gitlab","jenkins","jira","confluence","vault",
        "monitor","grafana","kibana","elastic","redis","db","mysql","postgres","s3",
        "backup","old","new","v1","v2","v3","secure","uat","demo","sandbox","corp",
        "intranet","extranet","remote","proxy","mx","smtp","pop","imap","ns1","ns2",
        "mobile","m","www","www2","shop","store","pay","checkout","account","blog",
    ]

    TRANSFORMS = [
        lambda s: f"dev-{s}",       lambda s: f"{s}-dev",
        lambda s: f"api-{s}",       lambda s: f"{s}-api",
        lambda s: f"staging-{s}",   lambda s: f"{s}-staging",
        lambda s: f"internal-{s}",  lambda s: f"admin-{s}",
        lambda s: f"test-{s}",      lambda s: f"{s}-test",
    ]

    @classmethod
    def generate(cls, base_domain: str, known_subs: list,
                 max_words: int = 1000) -> list:
        """Generate permuted subdomains from known subs + prefix list."""
        words = set()

        # Add prefixes directly
        for p in cls.PREFIXES:
            words.add(f"{p}.{base_domain}")

        # Extract labels from known subs and permute
        labels = set()
        for sub in known_subs:
            parts = sub.replace(f".{base_domain}","").split(".")
            for part in parts:
                if 2 < len(part) < 25 and part.isalnum():
                    labels.add(part)

        for label in list(labels)[:50]:
            for prefix in cls.PREFIXES[:20]:
                words.add(f"{prefix}-{label}.{base_domain}")
                words.add(f"{label}-{prefix}.{base_domain}")

            for transform in cls.TRANSFORMS:
                words.add(f"{transform(label)}.{base_domain}")

        return list(words)[:max_words]

    @classmethod
    def run_puredns(cls, wordlist_path: str, base_domain: str,
                    out_path: str, pipeline) -> int:
        """Resolve permuted subdomains via puredns or dnsx."""
        pipeline.shell(
            f"puredns bruteforce {wordlist_path} {base_domain} "
            f"--resolvers /usr/share/wordlists/resolvers.txt "
            f"-q 2>/dev/null >> {out_path}",
            label="puredns permute", tool_name="puredns", timeout=180
        )
        pipeline.shell(
            f"cat {wordlist_path} | dnsx -silent -a -resp-only 2>/dev/null "
            f">> {out_path}",
            label="dnsx permute", tool_name="dnsx", timeout=120
        )
        return count_lines(out_path)

    def _python_subdomain_fallback(self, domain: str, subs_file: str):
        """
        Python fallback when no tools installed.
        Uses: crt.sh API + common prefix brute force + DNS socket.
        Guarantees at least the base domain is in subdomains.txt.
        """
        import socket, json as _json, urllib.request as _ur

        found = set()

        # Always add base domain
        found.add(domain)

        # 1. crt.sh certificate transparency (no tool needed)
        try:
            import urllib.parse as _up
            url = f"https://crt.sh/?q=%.{_up.quote(domain)}&output=json"
            req = _ur.Request(url, headers={"User-Agent":"M7Hunter/7.0"})
            resp= _ur.urlopen(req, timeout=15)
            data= _json.loads(resp.read())
            for entry in data:
                for name in entry.get("name_value","").split("\n"):
                    sub = name.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.add(sub)
        except Exception as e:
            self.p.log.warn(f"  crt.sh fallback error: {e}")

        # 2. Common subdomain brute force via DNS
        COMMON = ["www","api","mail","admin","dev","staging","app","test",
                  "beta","dashboard","login","auth","cdn","assets","static",
                  "img","images","blog","docs","portal","mobile","m","shop"]
        for prefix in COMMON:
            sub = f"{prefix}.{domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.getaddrinfo(sub, 80)
                found.add(sub)
            except Exception:
                pass

        # Write all found to subdomains file
        if found:
            with open(subs_file, "a") as f:
                f.write("\n".join(sorted(found)) + "\n")
            self.p.log.info(
                f"  Python fallback: {len(found)} subdomains "
                f"(crt.sh + DNS brute force)")
        return len(found)
