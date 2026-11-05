#!/usr/bin/env python3
# modules/step06_nuclei.py — Nuclei Template Scanning
# MilkyWay Intelligence | Author: Sharlix

import os, json
from core.utils import count_lines, safe_read


class Step06Nuclei:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        live = p.files["live_hosts"]
        out  = p.files["nuclei_results"]
        t    = p.tmgr.get

        if not os.path.isfile(live) or count_lines(live) == 0:
            p.log.warn("Nuclei: no live hosts"); return

        p.log.info(f"Nuclei scanning {count_lines(live)} hosts")

        # Build auth flags from new CLI (-s -a -j)
        cookie  = getattr(p.args,'cookie',None) or getattr(p.args,'session',None)
        auth_hdr= getattr(p.args,'authorization',None) or getattr(p.args,'auth',None)
        jwt_tok = getattr(p.args,'jwt',None) or getattr(p.args,'_jwt_token',None)
        auth_flags = []
        if cookie:   auth_flags.append(f'-H "Cookie: {cookie}"')
        if auth_hdr: auth_flags.append(f'-H "Authorization: {auth_hdr}"')
        if jwt_tok and not auth_hdr:
            auth_flags.append(f'-H "Authorization: Bearer {jwt_tok}"')
        cookie_flag = ' '.join(auth_flags)
        json_out    = out.replace(".txt", ".json")

        # Update templates silently
        p.shell("nuclei -update-templates -silent 2>/dev/null", timeout=60)

        # Run nuclei — critical/high/medium
        p.shell(
            f"nuclei -l {live} -silent "
            f"-severity critical,high,medium "
            f"-etags dos,fuzz "
            f"-t cves,exposures,misconfigurations,vulnerabilities,default-logins "
            f"-rl {getattr(p.args,'rate',300)} "
            f"-c 50 "
            f"{cookie_flag} "
            f"-jsonl -o {json_out} 2>/dev/null | tee {out}",
            label="nuclei main scan", tool_name="nuclei", timeout=t("nuclei")
        )

        # Custom M7 templates if exist
        custom_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "templates", "nuclei", "m7-custom")
        if os.path.isdir(custom_dir) and os.listdir(custom_dir):
            p.shell(
                f"nuclei -l {live} -silent -t {custom_dir} "
                f"-rl 100 {cookie_flag} -o /tmp/nuclei_custom.txt 2>/dev/null",
                label="nuclei custom templates", tool_name="nuclei",
                append_file=out, timeout=600
            )

        # Parse JSONL results
        if os.path.isfile(json_out):
            self._parse_nuclei_json(json_out)
        else:
            # Fallback: parse text output
            self._parse_nuclei_text(out)

        n = count_lines(out)
        p.log.success(f"Nuclei: {n} findings")

    def _parse_nuclei_json(self, json_out: str):
        SEV_MAP = {"critical":"critical","high":"high","medium":"medium",
                    "low":"low","info":"info"}
        try:
            with open(json_out) as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        r    = json.loads(line)
                        sev  = SEV_MAP.get(r.get("info",{}).get("severity","info"),"info")
                        url  = r.get("matched-at","") or r.get("host","")
                        name = r.get("info",{}).get("name","Nuclei Finding")
                        tmpl = r.get("template-id","")
                        if url:
                            self.p.add_finding(sev, f"NUCLEI_{tmpl.upper()[:30]}",
                                               url, name, "nuclei")
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

    def _parse_nuclei_text(self, out: str):
        import re
        try:
            with open(out) as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    m = re.search(r'\[(critical|high|medium|low)\]', line, re.I)
                    sev = m.group(1).lower() if m else "info"
                    urls = re.findall(r'https?://\S+', line)
                    if urls:
                        self.p.add_finding(sev, "NUCLEI", urls[0],
                                           line[:100], "nuclei", response=response, payload=payload)
        except Exception:
            pass
