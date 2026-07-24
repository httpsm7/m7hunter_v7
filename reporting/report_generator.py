#!/usr/bin/env python3
# reporting/report_generator.py — Interactive HTML Report Generator V7
# Blueprint Fix: Collapsible findings, PoC commands, severity charts, JSON/TXT export
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import os, json, re
from datetime import datetime
from core.error_handler import get_handler

SEV_COLOR = {"critical":"#ef4444","high":"#f59e0b","medium":"#38bdf8",
             "low":"#a78bfa","info":"#94a3b8"}
SEV_ORDER  = ["critical","high","medium","low","info"]

class ReportGenerator:
    def __init__(self, pipeline):
        self.p   = pipeline
        self.log = pipeline.log
        self.out = pipeline.out
        self.prefix = pipeline.prefix

    def generate_all(self):
        try:
            findings = self.p.findings_engine.get_all()
            html = self.generate_html(findings)
            json_data = self.generate_json(findings)
            txt  = self.generate_txt(findings)
            self.log.success(f"Reports: {html}, {json_data}, {txt}")
            return html, json_data, txt
        except Exception as e:
            get_handler().capture("report_generator", e, "generate_all")
            return "", "", ""

    def generate_html(self, findings: list) -> str:
        path = os.path.join(self.out, f"{self.prefix}_report.html")
        sev_counts = {s:0 for s in SEV_ORDER}
        sev_buttons = ''.join(f'<button class="btn" onclick="filterBy(\'{s}\')">{s.capitalize()}</button>' for s in SEV_ORDER)
        for f in findings:
            s = f.get("severity","info").lower()
            if s in sev_counts: sev_counts[s] += 1
        try:
            with open(path, "w") as fh:
                fh.write(self._html_template(findings, sev_counts))
        except Exception as e:
            get_handler().capture("report_generator", e, "generate_html")
        return path

    def generate_json(self, findings: list) -> str:
        path = os.path.join(self.out, f"{self.prefix}_findings.json")
        try:
            with open(path,"w") as f:
                json.dump({"generated": datetime.now().isoformat(),
                           "target": getattr(self.p,"target",""),
                           "total": len(findings), "findings": findings}, f, indent=2)
        except Exception as e:
            get_handler().capture("report_generator", e, "generate_json")
        return path

    def generate_txt(self, findings: list) -> str:
        path = os.path.join(self.out, f"{self.prefix}_findings.txt")
        try:
            with open(path,"w") as f:
                f.write(f"M7Hunter V7 Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
                f.write(f"Target: {getattr(self.p,'target','')}\n")
                f.write(f"Total: {len(findings)}\n")
                f.write("="*60+"\n\n")
                for sev in SEV_ORDER:
                    group = [x for x in findings if x.get("severity","").lower()==sev]
                    if not group: continue
                    f.write(f"[{sev.upper()}] — {len(group)} finding(s)\n"+"-"*40+"\n")
                    for fn in group:
                        f.write(f"  Type   : {fn.get('vuln_type','?')}\n")
                        f.write(f"  URL    : {fn.get('url','?')}\n")
                        f.write(f"  Detail : {fn.get('detail','?')}\n")
                        f.write(f"  Conf   : {round(fn.get('confidence',0)*100)}%\n")
                        poc = self._make_poc(fn)
                        if poc: f.write(f"  PoC    : {poc}\n")
                        f.write("\n")
        except Exception as e:
            get_handler().capture("report_generator", e, "generate_txt")
        return path

    def _make_poc(self, f: dict) -> str:
        url = f.get("url","")
        if not url: return ""
        payload = f.get("payload","")
        cookie  = getattr(self.p.args,"cookie","") if hasattr(self.p,"args") else ""
        ck = f' -H "Cookie: {cookie}"' if cookie else ""
        if payload:
            return f'curl -sk "{url}" -d "{payload}"{ck} -A "M7Hunter/7"'
        return f'curl -sk "{url}"{ck} -A "M7Hunter/7"'

    def _html_template(self, findings, sev_counts):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target = getattr(self.p,"target","unknown")
        cards  = "\n".join(self._finding_card(f,i) for i,f in enumerate(findings))
        chart_data = json.dumps([{"sev":s,"count":sev_counts[s],"color":SEV_COLOR[s]} for s in SEV_ORDER])
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M7Hunter V7 — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#060a0f;color:#e2e8f0;font-family:'Courier New',monospace;font-size:13px;padding:20px}}
h1{{color:#00ff88;font-size:1.3rem;letter-spacing:.15em;margin-bottom:4px}}
.meta{{color:#475569;font-size:.7rem;margin-bottom:20px}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:20px}}
.stat{{background:#0d1117;border:1px solid #1e293b;padding:12px;border-radius:3px;text-align:center}}
.stat .v{{font-size:1.8rem;font-weight:700}}.stat .l{{font-size:.6rem;color:#475569;letter-spacing:.15em;margin-top:2px}}
.bar-chart{{background:#0d1117;border:1px solid #1e293b;padding:14px;border-radius:3px;margin-bottom:20px}}
.bar-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:.72rem}}
.bar-row .lbl{{width:70px;color:#64748b;text-align:right}}
.bar-bg{{flex:1;height:16px;background:#1e293b;border-radius:2px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:2px;transition:width .3s}}
.bar-cnt{{width:30px;font-weight:700}}
.toolbar{{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center}}
.btn{{padding:5px 12px;border:1px solid #334155;background:#0d1117;color:#94a3b8;
      cursor:pointer;border-radius:2px;font-family:inherit;font-size:.72rem}}
.btn:hover{{border-color:#00ff88;color:#00ff88}}
.btn.active{{border-color:#00ff88;color:#00ff88;background:#00ff8811}}
#search{{background:#0d1117;border:1px solid #334155;color:#e2e8f0;padding:5px 10px;
         font-family:inherit;font-size:.72rem;width:200px;border-radius:2px;outline:none}}
.finding{{border:1px solid #1e293b;border-radius:3px;margin-bottom:8px;overflow:hidden}}
.fhdr{{display:flex;align-items:center;gap:10px;padding:9px 12px;cursor:pointer;background:#0d1117}}
.fhdr:hover{{background:#111722}}
.sbadge{{font-size:.6rem;font-weight:700;padding:2px 7px;border-radius:2px;
          border:1px solid;letter-spacing:.1em;white-space:nowrap}}
.ftype{{font-weight:700;font-size:.8rem}}.furl{{color:#64748b;font-size:.7rem;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.fbody{{padding:12px;background:#060a0f;border-top:1px solid #1e293b;display:none}}
.fbody.open{{display:block}}
.row{{display:flex;gap:8px;margin-bottom:5px;font-size:.7rem}}
.row .k{{color:#475569;min-width:80px;flex-shrink:0}}.row .v{{color:#94a3b8;word-break:break-all}}
.poc{{background:#0d1117;border:1px solid #334155;padding:8px 10px;border-radius:2px;
      font-size:.68rem;color:#00ff88;margin-top:8px;word-break:break-all;cursor:pointer}}
.poc:active{{border-color:#00ff88}}.conf-bar{{height:3px;background:#1e293b;border-radius:2px;margin-top:8px}}
.conf-fill{{height:100%;border-radius:2px}}
footer{{margin-top:30px;color:#1e293b;font-size:.65rem;text-align:center;letter-spacing:.15em}}
</style></head><body>
<h1>M7HUNTER V7 — SECURITY REPORT</h1>
<div class="meta">Target: {target} | Generated: {ts} | Total findings: {len(findings)}</div>
<div class="summary">
  <div class="stat"><div class="v" style="color:#00ff88">{len(findings)}</div><div class="l">TOTAL</div></div>
  {''.join(f'<div class="stat"><div class="v" style="color:{SEV_COLOR[s]}">{sev_counts[s]}</div><div class="l">{s.upper()}</div></div>' for s in SEV_ORDER if sev_counts[s]>0)}
</div>
<div class="bar-chart">
  {''.join(f'<div class="bar-row"><span class="lbl">{s}</span><div class="bar-bg"><div class="bar-fill" style="width:{min(sev_counts[s]/max(len(findings),1)*100,100):.0f}%;background:{SEV_COLOR[s]}"></div></div><span class="bar-cnt" style="color:{SEV_COLOR[s]}">{sev_counts[s]}</span></div>' for s in SEV_ORDER)}
</div>
<div class="toolbar">
  <button class="btn active" onclick="filterBy('')">All</button>
  {sev_buttons}
  <input id="search" placeholder="Search…" oninput="renderAll()">
  <button class="btn" onclick="exportJSON()">Export JSON</button>
</div>
<div id="container">{cards}</div>
<footer>MILKYWAY INTELLIGENCE // M7HUNTER V7 // AUTHORIZED BUG BOUNTY USE ONLY</footer>
<script>
const DATA={json.dumps(findings)};
let _sev='';
function filterBy(s){{_sev=s;document.querySelectorAll('.btn').forEach(b=>b.classList.remove('active'));
  if(event&&event.target) event.target.classList.add('active');renderAll()}}
function renderAll(){{
  const q=(document.getElementById('search').value||'').toLowerCase();
  document.querySelectorAll('.finding').forEach(el=>{{
    const match=(!_sev||el.dataset.sev===_sev)&&(!q||el.textContent.toLowerCase().includes(q));
    el.style.display=match?'':'none';
  }})}}
function toggle(i){{const el=document.getElementById('fb'+i);if(el)el.classList.toggle('open')}}
function copyPoc(el){{navigator.clipboard?.writeText(el.textContent).then(()=>{{el.style.borderColor='#00ff88';setTimeout(()=>el.style.borderColor='',800)}})}}
function exportJSON(){{const b=new Blob([JSON.stringify(DATA,null,2)],{{type:'application/json'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='m7_findings.json';a.click()}}
</script></body></html>"""

    def _finding_card(self, f: dict, i: int) -> str:
        sev   = f.get("severity","info").lower()
        color = SEV_COLOR.get(sev,"#94a3b8")
        conf  = round(f.get("confidence",0)*100)
        poc   = self._make_poc(f)
        poc_html = f'<div class="poc" onclick="copyPoc(this)" title="Click to copy">{poc}</div>' if poc else ""
        return f"""<div class="finding" data-sev="{sev}">
  <div class="fhdr" onclick="toggle({i})">
    <span class="sbadge" style="color:{color};border-color:{color}40;background:{color}11">{sev.upper()}</span>
    <span class="ftype">{f.get('vuln_type','?')}</span>
    <span class="furl">{f.get('url','?')}</span>
    <span style="color:#475569;font-size:.65rem">{conf}%</span>
  </div>
  <div class="fbody" id="fb{i}">
    <div class="row"><span class="k">URL</span><span class="v">{f.get('url','')}</span></div>
    <div class="row"><span class="k">Detail</span><span class="v">{f.get('detail',f.get('evidence',''))}</span></div>
    <div class="row"><span class="k">Confidence</span><span class="v">{conf}%</span></div>
    <div class="row"><span class="k">Tool</span><span class="v">{f.get('tool','m7hunter')}</span></div>
    {poc_html}
    <div class="conf-bar"><div class="conf-fill" style="width:{conf}%;background:{color}"></div></div>
  </div>
</div>"""
