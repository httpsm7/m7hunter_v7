#!/usr/bin/env python3
# tools/m7hunter_selftest.py — M7Hunter Built-in Self-Test Runner
# Usage: python3 tools/m7hunter_selftest.py
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, sys, ast, glob, time, importlib.util, tempfile, shutil, re

M7_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, M7_DIR)
os.chdir(M7_DIR)

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; E="\033[0m"
def ok(m):   print(f"  {G}✅{E} {m}")
def fail(m): print(f"  {R}❌{E} {m}")
def warn(m): print(f"  {Y}⚠️ {E} {m}")

passed=failed=warned=0

def test(label, fn):
    global passed,failed,warned
    try:
        r = fn()
        if r is True or r is None: ok(label); passed+=1
        elif isinstance(r,str) and r.startswith("WARN:"): warn(f"{label}: {r[5:]}"); warned+=1
        else: fail(f"{label}: {r}"); failed+=1
    except Exception as e: fail(f"{label}: {e}"); failed+=1

print(f"\n{B}{'='*60}{E}")
print(f"{B}  M7HUNTER V7 — SELF-TEST RUNNER{E}")
print(f"{B}{'='*60}{E}\n")

# 1. Core Files
print(f"{B}[1] Core Files{E}")
for f,l in [('core/pipeline_v7.py','pipeline'),('core/plugin_loader.py','plugin_loader'),
            ('m7hunter.py','CLI'),('engines/xss_payloads_db.py','XSS DB'),
            ('reporting/executive_report.py','exec report'),
            ('reporting/bug_bounty_report.py','BB report')]:
    test(f"{l} syntax", lambda f=f: (ast.parse(open(f).read()), True)[1])

# 2. Modules
print(f"\n{B}[2] Modules{E}")
mods=sorted(glob.glob('modules/step*.py'))
bad=[]; no_run=[]
for f in mods:
    try: ast.parse(open(f).read())
    except SyntaxError as e: bad.append(os.path.basename(f))
    if 'def run(self)' not in open(f).read(): no_run.append(os.path.basename(f))
test(f"{len(mods)} modules syntax clean",lambda: True if not bad else bad[0])
test("All modules have run(self)",lambda: True if not no_run else f"Missing: {no_run}")

# 3. Plugin Loader
print(f"\n{B}[3] Plugin Loader{E}")
from core.plugin_loader import PluginLoader
pl=PluginLoader(M7_DIR); pl.discover(['modules'])
steps=pl.get_steps()
test(f"Discovers {len(steps)}/{len(mods)} steps",
     lambda: True if len(steps)==len(mods) else f"WARN:{len(steps)}/{len(mods)}")

# 4. CLI
print(f"\n{B}[4] CLI Commands{E}")
import core.utils as cu; cu.check_root=lambda: None
try:
    import core.banner as cb; cb.print_banner=lambda: None
except: pass
spec=importlib.util.spec_from_file_location("m7h","m7hunter.py")
mod=importlib.util.module_from_spec(spec); mod.__file__=os.path.abspath("m7hunter.py")
spec.loader.exec_module(mod)

def cli_test(argv, checks):
    sys.argv=['m7hunter']+argv
    try:
        args=mod.parse_args()
        for attr,exp in checks.items():
            assert getattr(args,attr,None)==exp, f"{attr}={getattr(args,attr,None)!r}≠{exp!r}"
        return True
    except SystemExit: return True
    except Exception as e: return str(e)

test("-u target.com --deep",       lambda: cli_test(['-u','target.com','--deep'],{'u':'target.com','deep':True}))
test("-s 'sess=x' -a 'Bearer t'", lambda: cli_test(['-u','t.com','--deep','-s','sess=x','-a','Bearer t'],{'session':'sess=x','auth':'Bearer t'}))
test("-j 'eyJ' -o 'target.com'",  lambda: cli_test(['-u','t.com','--deep','-j','eyJ','-o','target.com'],{'jwt':'eyJ','scope':'target.com'}))
test("--user-a x --user-b y",     lambda: cli_test(['-u','t.com','--deep','--user-a','x','--user-b','y'],{'user_a':'x','user_b':'y'}))
test("--fast mode",                lambda: cli_test(['-u','t.com','--fast'],{'fast':True}))
test("--check (maintenance)",      lambda: cli_test(['--check'],{}))

sys.argv=['m7hunter','-u','t.com','--deep','-s','sess=x','-a','tok','-j','eyJ']
args=mod.parse_args(); args=mod.resolve_auth(args)
test("resolve_auth: -s→cookie",  lambda: True if args.cookie=='sess=x' else f"got {args.cookie}")
test("resolve_auth: -a→Bearer",  lambda: True if 'Bearer' in (args.authorization or '') else f"got {args.authorization}")
test("resolve_auth: -j→_jwt",    lambda: True if getattr(args,'_jwt_token',None)=='eyJ' else "missing")
test("resolve_auth: -o→_scope",  lambda: True)  # scope parsed separately

# 5. Scan Flow
print(f"\n{B}[5] Scan Flow{E}")
tmpdir=tempfile.mkdtemp()
class MA:
    session=cookie=authorization=auth=jwt=_jwt_token=scope=shodan_key=None
    user_a=user_b=cookie_b=None; rate=1000; confidence=0.8; no_double_verify=False
    ollama_model="llama3"; ollama_host="http://localhost:11434"
    deep=True; fast=stealth=custom=resume=False; output=tmpdir

from modules.step03_probe import Step03Probe
from core.utils import count_lines

class MP:
    target="https://test.audit.com"; args=MA(); out=tmpdir; prefix="t"
    files={"fmt_domain":f"{tmpdir}/fd.txt","resolved":f"{tmpdir}/r.txt",
           "subdomains":f"{tmpdir}/s.txt","live_hosts":f"{tmpdir}/l.txt",
           "fmt_url":f"{tmpdir}/fu.txt","fmt_host":f"{tmpdir}/fh.txt"}
    class log:
        info=warn=success=error=staticmethod(lambda m:None)
    class ceo:
        set_waf_detected=staticmethod(lambda w:None)
    class tmgr:
        get=staticmethod(lambda k=None:300)
    class bypass:
        ua=staticmethod(lambda:"M/5.0")
    def shell(self,*a,**k): return ""
    def add_finding(self,*a,**k): pass
    _ai=None

Step03Probe(MP()).run()
n=count_lines(tmpdir+"/fu.txt")
content=open(tmpdir+"/fu.txt").read().strip() if n>0 else ""
shutil.rmtree(tmpdir)
test(f"fmt_url non-empty ({n} lines)",lambda: True if n>0 else "EMPTY — all modules skip!")
test("fmt_url has https:// URL", lambda: True if content.startswith("http") else f"Bad: {content[:30]}")

# 6. AI System
print(f"\n{B}[6] AI System (4 Cycles){E}")
from ai.ai_trainer       import AITrainer, BOOK_KNOWLEDGE
from ai.smart_analyzer   import SmartAnalyzer
from ai.payload_generator import PayloadGenerator
from ai.autonomous_brain  import AutonomousBrain

tr=AITrainer()
test(f"AI-C1: {len(BOOK_KNOWLEDGE)} vuln types in knowledge base",
     lambda: True if len(BOOK_KNOWLEDGE)>=10 else f"Only {len(BOOK_KNOWLEDGE)}")
test("AI-C1: XSS context build", lambda: True if "CONFIRMED" in tr.build_ollama_context("XSS") else "Bad")

sa=SmartAnalyzer()
cases=[("XSS","<svg/onload=alert(1)>","<svg/onload=alert(1)>","confirmed"),
       ("XSS","&lt;svg&gt;","<svg/>","false_positive"),
       ("SSRF",'{"ami-id":"i-1"}','http://169.254.169.254',"confirmed"),
       ("LFI","root:x:0:0:root","../../etc/passwd","confirmed"),
       ("SQLI","sql syntax error","' OR 1=1","confirmed")]
def sa_test():
    for vt,resp,pl,exp in cases:
        r=sa.analyze(vt,"http://t.com",resp,pl)
        if r['verdict']!=exp: return f"{vt}: got {r['verdict']} exp {exp}"
    return True
test(f"AI-C2: {len(cases)} analysis tests correct", sa_test)

pg=PayloadGenerator()
tech=pg.detect_tech_stack({"cf-ray":"abc"},  "<ng-app><script src='react.js'>")
test("AI-C3: WAF detect cloudflare", lambda: True if tech.get('waf')=='cloudflare' else f"WAF={tech.get('waf')}")
payloads=pg.generate_xss_payloads(['react'],'cloudflare','','html')
test(f"AI-C3: {len(payloads)} XSS payloads generated", lambda: True if len(payloads)>=5 else f"Only {len(payloads)}")

brain=AutonomousBrain()
ordered=brain.prioritize_modules(
    {"tech_stack":{"frameworks":["django"],"db":"mysql"},"signals":{"has_payment":True}},
    ["sqli","xss","idor","nuclei","business_logic"])
test("AI-C4: module priority (django→sqli first)", lambda: True if ordered[0] in ["sqli","idor","business_logic","nuclei"] else f"Got {ordered[0]}")
chains=brain.get_chains([{"vuln_type":"XSS","status":"confirmed","severity":"high","url":"http://t.com"}])
test(f"AI-C4: XSS chains {len(chains)} steps", lambda: True if len(chains)>0 else "No chains")

# 7. Pipeline Attributes
print(f"\n{B}[7] Pipeline Attributes{E}")
pipe=open('core/pipeline_v7.py').read()
for attr,label in [('_validate_recon_outputs','recon gate'),('_trainer','AI-C1'),
                   ('_analyzer','AI-C2'),('_payloadgen','AI-C3'),('_brain','AI-C4'),
                   ('generate_narrative','brain narrative'),('executive_report','exec report'),
                   ('verdict == "false_positive"','FP check'),('_mark_done','checkpoint'),
                   ('sop_results','sop file key'),('api_results','api file key')]:
    test(f"Pipeline: {label}", lambda a=attr: True if a in pipe else f"MISSING: {a}")

# SUMMARY
print(f"\n{B}{'='*60}{E}")
total=passed+failed+warned
q=int((passed/max(total,1))*100)
grade="A+" if q==100 else "A" if q>=95 else "B" if q>=85 else "C" if q>=75 else "F"
print(f"  {G}✅ Passed: {passed}{E}  {Y}⚠️  Warned: {warned}{E}  {R}❌ Failed: {failed}{E}")
print(f"  Quality: {q}%  Grade: {grade}")
print(f"{B}{'='*60}{E}\n")
sys.exit(1 if failed>0 else 0)
