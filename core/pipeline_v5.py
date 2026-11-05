#!/usr/bin/env python3
# core/pipeline_v5.py — M7Hunter v6.0 Pipeline (FIXED + UPGRADED)
# Fixes: race conditions, CEO validator, suspicious_endpoints set,
#        scope enforcement, new vuln engines (CSRF, Race, NoSQL)
# MilkyWay Intelligence | Author: Sharlix

import os, time, json, subprocess, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils              import get_prefix, ensure_dir, count_lines, FormatFixer, is_in_scope
from core.rate_bypass        import RateBypass
from core.timeout_manager    import TimeoutManager
from core.pipeline_cfg_patch import CfgShim
from core.audit_logger       import AuditLogger
from ai.observer             import M7Observer
from ai.pipeline_controller  import PipelineController
from confirm.confidence      import ConfidenceEngine
from confirm.proof_engine    import ProofEngine
from confirm.risk_scorer     import RiskScorer

from modules.step01_subdomain   import SubdomainStep
from modules.step02_dns         import DNSStep
from modules.step03_probe       import ProbeStep
from modules.step04_ports       import PortsStep
from modules.step05_crawl       import CrawlStep
from modules.step06_nuclei      import NucleiStep
from modules.step07_xss         import XSSStep
from modules.step08_sqli        import SQLiStep
from modules.step09_cors        import CORSStep
from modules.step10_lfi         import LFIStep
from modules.step11_ssrf        import SSRFStep
from modules.step12_redirect    import RedirectStep
from modules.step13_takeover    import TakeoverStep
from modules.step14_screenshot  import ScreenshotStep
from modules.step15_wpscan      import WPScanStep
from modules.step16_github      import GitHubDorkStep
from modules.step17_cloud       import CloudEnumStep
from modules.step18_ssti        import SSTIStep
from modules.step19_jwt         import JWTStep
from modules.step20_graphql     import GraphQLStep
from modules.step21_host_header import HostHeaderStep
from modules.step22_idor        import IDORStep
from modules.step23_xxe         import XXEStep
from modules.step24_smuggling   import SmugglingStep
from modules.step25_csrf        import CSRFStep
from modules.step26_race        import RaceConditionStep
from modules.step27_nosql       import NoSQLStep
from modules.report             import ReportGenerator

# ── Phase definitions ────────────────────────────────────────────────
PHASE1_STEPS = [
    "subdomain","dns","probe","nuclei","xss","ssrf",
    "takeover","github","idor","redirect","csrf"
]

PHASE2_STEPS = [
    "ports","crawl","sqli","cors","lfi","screenshot",
    "wpscan","cloud","ssti","jwt","graphql","host_header",
    "xxe","smuggling","race","nosql"
]

FAST_STEPS = PHASE1_STEPS

DEEP_STEPS = [
    "subdomain","dns","probe","ports","crawl","nuclei","xss",
    "sqli","cors","lfi","ssrf","redirect","takeover","screenshot",
    "wpscan","github","cloud","ssti","jwt","graphql","host_header",
    "idor","xxe","smuggling","csrf","race","nosql"
]

RECON_STEPS = ["subdomain","dns","probe","ports","crawl"]
PARALLEL_WORKERS = 6

# CEO step → output file mapping (FIXED: was None before, causing 0-line warnings)
STEP_OUTPUT_MAP = {
    "subdomain"    : "subdomains",
    "dns"          : "resolved",
    "probe"        : "live_hosts",
    "ports"        : "open_ports",
    "crawl"        : "urls",
    "nuclei"       : "nuclei_results",
    "xss"          : "xss_results",
    "sqli"         : "sqli_results",
    "cors"         : "cors_results",
    "lfi"          : "lfi_results",
    "ssrf"         : "ssrf_params",
    "redirect"     : "redirect_results",
    "takeover"     : "takeover_results",
    "github"       : "github_results",
    "cloud"        : "cloud_results",
    "ssti"         : "ssti_results",
    "jwt"          : "jwt_results",
    "graphql"      : "graphql_results",
    "host_header"  : "host_header_results",
    "csrf"         : "csrf_results",
    "race"         : "race_results",
    "nosql"        : "nosql_results",
}

# ── Observer lock wrapper ─────────────────────────────────────────────
_OBSERVER_LOCK = threading.Lock()


class PipelineV6:
    """
    M7Hunter v6.0 — Fixed + Upgraded Dual-Phase Pipeline

    Fixes from v5:
    - Race condition: observer/audit calls now locked
    - CEO validator: correct output file passed per step
    - suspicious_endpoints: set instead of list (O(1) lookup)
    - Scope enforcement: is_in_scope() in add_finding
    - New steps: CSRF (25), Race Condition (26), NoSQL (27)
    - GitHub: skip all dorks if no token (no 401 spam)
    - LFI: response verification before reporting
    - IDOR: stricter confirmation logic
    - SQLmap: correct parser string
    """

    def __init__(self, target, args, tor, oob, notifier, log,
                 scope_list=None, offline_ai=None, ollama_ai=None,
                 confidence_threshold=0.8):
        self.target              = target.strip()
        self.args                = args
        self.tor                 = tor
        self.oob                 = oob
        self.notifier            = notifier
        self.log                 = log
        self.scope_list          = scope_list or []
        self.offline_ai          = offline_ai
        self.ollama_ai           = ollama_ai
        self.confidence_threshold= confidence_threshold

        self.findings            = []
        self.suspicious_endpoints= set()   # FIX: was list → O(n), now set → O(1)
        self._findings_lock      = threading.Lock()
        self._observer_lock      = threading.Lock()  # FIX: new lock for observer
        self._audit_lock         = threading.Lock()  # FIX: new lock for audit
        self._seen_findings      = set()

        self.bypass  = RateBypass(
            min_delay=3.0 if getattr(args,'stealth',False) else 0.3,
            max_delay=8.0 if getattr(args,'stealth',False) else 1.5
        )
        self.tmgr    = TimeoutManager()
        if getattr(args,'stealth',False): self.tmgr.set_stealth()
        elif getattr(args,'fast',False):  self.tmgr.set_fast()

        self.prefix  = get_prefix(self.target)
        self.start_t = time.time()
        self.cfg     = CfgShim(args)
        self.observer= M7Observer(self)
        self.ceo     = PipelineController(self)

        self.confidence = ConfidenceEngine(offline_ai=offline_ai, threshold=confidence_threshold)
        self.proof      = ProofEngine(log=log)
        self.risk       = RiskScorer()

        self.audit = AuditLogger(target=self.target)
        self.audit.start_scan()

        self.auth_headers = {}
        if getattr(args, 'cookie', None):
            self.auth_headers["Cookie"] = args.cookie
        if getattr(args, 'headers', None) and os.path.isfile(args.headers):
            with open(args.headers) as f:
                for line in f:
                    if ':' in line:
                        k, _, v = line.partition(':')
                        self.auth_headers[k.strip()] = v.strip()

        base = getattr(args, 'output', None) or "results"
        ts   = time.strftime("%Y%m%d_%H%M%S")
        self.out = os.path.join(base, f"{self.prefix}_{ts}_v6")
        ensure_dir(self.out)

        p = self.prefix
        self.files = {
            "raw_input"          : os.path.join(self.out, f"{p}_raw_input.txt"),
            "subdomains"         : os.path.join(self.out, f"{p}_subdomains.txt"),
            "resolved"           : os.path.join(self.out, f"{p}_resolved.txt"),
            "live_hosts"         : os.path.join(self.out, f"{p}_live_hosts.txt"),
            "open_ports"         : os.path.join(self.out, f"{p}_open_ports.txt"),
            "urls"               : os.path.join(self.out, f"{p}_urls.txt"),
            "js_files"           : os.path.join(self.out, f"{p}_js_files.txt"),
            "js_secrets"         : os.path.join(self.out, f"{p}_js_secrets.txt"),
            "params"             : os.path.join(self.out, f"{p}_params.txt"),
            "nuclei_results"     : os.path.join(self.out, f"{p}_nuclei.txt"),
            "xss_results"        : os.path.join(self.out, f"{p}_xss.txt"),
            "sqli_params"        : os.path.join(self.out, f"{p}_sqli_params.txt"),
            "sqli_results"       : os.path.join(self.out, f"{p}_sqli_confirmed.txt"),
            "cors_results"       : os.path.join(self.out, f"{p}_cors.txt"),
            "lfi_results"        : os.path.join(self.out, f"{p}_lfi.txt"),
            "ssrf_params"        : os.path.join(self.out, f"{p}_ssrf.txt"),
            "redirect_results"   : os.path.join(self.out, f"{p}_redirect.txt"),
            "takeover_results"   : os.path.join(self.out, f"{p}_takeover.txt"),
            "screenshots_dir"    : os.path.join(self.out, "screenshots"),
            "wpscan_dir"         : os.path.join(self.out, "wpscan"),
            "wayback_urls"       : os.path.join(self.out, f"{p}_wayback.txt"),
            "gau_urls"           : os.path.join(self.out, f"{p}_gau.txt"),
            "dns_records"        : os.path.join(self.out, f"{p}_dns.txt"),
            "github_results"     : os.path.join(self.out, f"{p}_github.txt"),
            "cloud_results"      : os.path.join(self.out, f"{p}_cloud.txt"),
            "ssti_results"       : os.path.join(self.out, f"{p}_ssti.txt"),
            "jwt_results"        : os.path.join(self.out, f"{p}_jwt.txt"),
            "graphql_results"    : os.path.join(self.out, f"{p}_graphql.txt"),
            "host_header_results": os.path.join(self.out, f"{p}_host_header.txt"),
            "csrf_results"       : os.path.join(self.out, f"{p}_csrf.txt"),
            "race_results"       : os.path.join(self.out, f"{p}_race.txt"),
            "nosql_results"      : os.path.join(self.out, f"{p}_nosql.txt"),
            "fmt_domain"         : os.path.join(self.out, f"{p}_fmt_domain.txt"),
            "fmt_url"            : os.path.join(self.out, f"{p}_fmt_url.txt"),
            "fmt_host"           : os.path.join(self.out, f"{p}_fmt_host.txt"),
            "phase1_suspects"    : os.path.join(self.out, f"{p}_phase1_suspects.json"),
            "proof_dir"          : os.path.join(self.out, "proofs"),
            "audit_log"          : os.path.join(self.out, f"{p}_audit.jsonl"),
            "risk_report"        : os.path.join(self.out, f"{p}_risk.json"),
        }

        ensure_dir(self.files["proof_dir"])
        with open(self.files["raw_input"], "w") as f:
            f.write(self.target + "\n")

        self.steps_to_run = self._resolve_steps()
        self.log.set_steps(len(self.steps_to_run) + 1)

    def _resolve_steps(self):
        a = self.args
        if getattr(a,'fast',False) or getattr(a,'phase1_only',False):
            return FAST_STEPS
        elif getattr(a,'deep',False) or getattr(a,'stealth',False) or getattr(a,'continuous',False):
            return DEEP_STEPS
        elif getattr(a,'custom',False):
            return [s for s in DEEP_STEPS if getattr(a, s, False)] or FAST_STEPS
        return FAST_STEPS

    def _step_map(self):
        return {
            "subdomain"  : SubdomainStep,
            "dns"        : DNSStep,
            "probe"      : ProbeStep,
            "ports"      : PortsStep,
            "crawl"      : CrawlStep,
            "nuclei"     : NucleiStep,
            "xss"        : XSSStep,
            "sqli"       : SQLiStep,
            "cors"       : CORSStep,
            "lfi"        : LFIStep,
            "ssrf"       : SSRFStep,
            "redirect"   : RedirectStep,
            "takeover"   : TakeoverStep,
            "screenshot" : ScreenshotStep,
            "wpscan"     : WPScanStep,
            "github"     : GitHubDorkStep,
            "cloud"      : CloudEnumStep,
            "ssti"       : SSTIStep,
            "jwt"        : JWTStep,
            "graphql"    : GraphQLStep,
            "host_header": HostHeaderStep,
            "idor"       : IDORStep,
            "xxe"        : XXEStep,
            "smuggling"  : SmugglingStep,
            "csrf"       : CSRFStep,
            "race"       : RaceConditionStep,
            "nosql"      : NoSQLStep,
        }

    def run(self) -> str:
        self.log.info(f"Output    : {self.out}")
        self.log.info(f"Scan ID   : {self.audit.scan_id}")
        self.log.info(f"Steps     : {' → '.join(self.steps_to_run)}")
        self.log.info(f"Confidence: {self.confidence_threshold}")
        self.log.info(f"Tor       : {'ON' if self.tor else 'OFF'}")
        self.log.info(f"OOB       : {self.oob.server if self.oob else 'OFF'}")
        print()

        if self.notifier:
            self.notifier.send_scan_start(self.target)

        self._save_state()
        completed = self._load_completed()
        step_map  = self._step_map()

        # Phase 1: Recon (sequential)
        recon = [s for s in self.steps_to_run if s in RECON_STEPS]
        for step_name in recon:
            if getattr(self.args,'resume',False) and step_name in completed:
                self.log.warn(f"Skipping (done): {step_name}")
                self.log._step_current += 1
                continue
            self._run_step(step_map, step_name)
            self._mark_completed(step_name)
            self._refresh_fmt_files()

        # Phase 1: Fast vuln scan (parallel)
        p1_vulns = [s for s in self.steps_to_run
                    if s in PHASE1_STEPS and s not in RECON_STEPS]
        if p1_vulns:
            self.log.section("PHASE 1 — FAST VULNERABILITY SCAN")
            self._run_parallel(p1_vulns, step_map, completed)

        # Phase 2: Deep confirmation
        p2_vulns = [s for s in self.steps_to_run
                    if s in PHASE2_STEPS and s not in RECON_STEPS]
        if p2_vulns and not getattr(self.args, 'phase1_only', False):
            self.log.section("PHASE 2 — DEEP CONFIRMATION SCAN")
            self.log.info(f"Suspicious endpoints from Phase-1: {len(self.suspicious_endpoints)}")
            self._run_parallel(p2_vulns, step_map, completed)

        self._generate_proofs()
        self._calculate_risk_scores()

        self.log.step("REPORT")
        report_path = ReportGenerator(self).generate()
        elapsed = time.time() - self.start_t
        self.log.pipeline_done(self.target, elapsed, report_path)

        missed = self.ceo.check_for_missed_critical_steps(self.steps_to_run)
        if missed:
            self.log.warn(f"[CEO] {len(missed)} critical steps missed:")
            for m in missed:
                self.log.warn(f"      → {m['step']}: {m['suggestion']}")

        with self._observer_lock:
            session_file = self.observer.save_session()
        self.log.success(f"Intelligence → {session_file}")

        self.audit.end_scan(
            total_findings=len(self.findings),
            confirmed=sum(1 for f in self.findings if f.get('status')=='confirmed'),
            elapsed=elapsed
        )

        if self.notifier:
            self.notifier.send_scan_done(self.target, len(self.findings), elapsed)

        return report_path

    def _run_step(self, step_map, step_name):
        StepClass = step_map.get(step_name)
        if not StepClass: return
        self.log.step(step_name.upper())
        try:
            with self._observer_lock:
                self.observer.step_start(step_name)
            # FIX: pass output file to CEO so line count is accurate
            output_file_key = STEP_OUTPUT_MAP.get(step_name)
            output_file = self.files.get(output_file_key) if output_file_key else None
            self.ceo.before_step(step_name)
            with self._audit_lock:
                self.audit.log_step_start(step_name)
            StepClass(self).run()
            with self._observer_lock:
                self.observer.step_end(step_name, "success")
            self.ceo.after_step(step_name, output_file=output_file)
            with self._audit_lock:
                self.audit.log_step_end(step_name, "success")
        except KeyboardInterrupt:
            with self._observer_lock:
                self.observer.step_end(step_name, "interrupted")
            self.log.warn("Interrupted"); raise
        except Exception as e:
            with self._observer_lock:
                self.observer.step_end(step_name, "failed", error=str(e))
            with self._audit_lock:
                self.audit.log_step_end(step_name, "failed", error=str(e))
            self.log.error(f"Step {step_name} failed: {e}")

    def _run_parallel(self, steps, step_map, completed):
        max_workers = min(len(steps), PARALLEL_WORKERS)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for step_name in steps:
                if getattr(self.args,'resume',False) and step_name in completed:
                    self.log.warn(f"Skipping (done): {step_name}")
                    continue
                StepClass = step_map.get(step_name)
                if StepClass:
                    self.log.info(f"  → Starting: {step_name}")
                    fut = executor.submit(self._run_step_safe, StepClass, step_name)
                    futures[fut] = step_name
            for fut in as_completed(futures):
                step_name = futures[fut]
                try:
                    fut.result()
                    self._mark_completed(step_name)
                except Exception as e:
                    self.log.error(f"Parallel step {step_name} failed: {e}")

    def _run_step_safe(self, StepClass, step_name):
        """Thread-safe step runner with locks on observer and audit."""
        try:
            self.log.step(step_name.upper())
            with self._observer_lock:
                self.observer.step_start(step_name)
            output_file_key = STEP_OUTPUT_MAP.get(step_name)
            output_file = self.files.get(output_file_key) if output_file_key else None
            self.ceo.before_step(step_name)
            with self._audit_lock:
                self.audit.log_step_start(step_name)
            StepClass(self).run()
            with self._observer_lock:
                self.observer.step_end(step_name, "success")
            self.ceo.after_step(step_name, output_file=output_file)
            with self._audit_lock:
                self.audit.log_step_end(step_name, "success")
        except Exception as e:
            with self._observer_lock:
                self.observer.step_end(step_name, "failed", error=str(e))
            with self._audit_lock:
                self.audit.log_step_end(step_name, "failed", error=str(e))
            self.log.error(f"Step {step_name}: {e}")
            raise

    def add_finding(self, severity, vuln_type, url, detail="", tool="",
                    response="", payload="", baseline_len=0):
        """
        v6 add_finding: scope check → dedup → AI filter → confidence score
        """
        # FIX: scope enforcement
        if self.scope_list and not is_in_scope(str(url), self.scope_list):
            return

        key = f"{severity}:{vuln_type}:{url}"
        with self._findings_lock:
            if key in self._seen_findings:
                return
            self._seen_findings.add(key)

        # AI FP check
        ai_analysis = {}
        if self.offline_ai and response:
            ai_analysis = self.offline_ai.analyze_response(
                vuln_type=vuln_type, url=url, response=response,
                payload=payload, baseline_len=baseline_len
            )
            if ai_analysis.get("is_false_positive"):
                with self._audit_lock:
                    self.audit.log_fp_caught(vuln_type, url, ai_analysis.get("reason", []))
                return

        # Confidence scoring
        conf_result = self.confidence.score(
            vuln_type=vuln_type, url=url, detail=detail,
            response=response, payload=payload,
            ai_analysis=ai_analysis, tool=tool,
        )
        status     = conf_result["status"]
        conf_score = conf_result["score"]

        if conf_score < self.confidence_threshold and status != "confirmed":
            if conf_score < 0.4:
                return

        self.log.finding(severity, vuln_type, url, detail)

        entry = {
            "severity"  : severity,
            "type"      : vuln_type,
            "url"       : url,
            "detail"    : detail,
            "tool"      : tool,
            "payload"   : payload,
            "time"      : time.strftime("%Y-%m-%d %H:%M:%S"),
            "status"    : status,
            "confidence": round(conf_score, 3),
            "risk_score": None,
            "proof"     : None,
        }

        with self._findings_lock:
            self.findings.append(entry)

        # FIX: suspicious_endpoints is now a set
        if status == "potential":
            self.suspicious_endpoints.add(url)

        with self._observer_lock:
            self.observer.record_finding(severity, vuln_type, url, detail, tool)
        with self._audit_lock:
            self.audit.log_finding(entry)

        if self.notifier:
            self.notifier.send_finding(severity, vuln_type, url, detail, tool)

    def add_suspicious(self, url, reason=""):
        """Mark endpoint for Phase-2 deep scan. FIX: set.add() O(1)."""
        self.suspicious_endpoints.add(url)
        self.log.info(f"  [P1→P2] Suspicious: {url[:60]} | {reason}")

    def _generate_proofs(self):
        confirmed = [f for f in self.findings if f.get('status') == 'confirmed']
        if not confirmed: return
        self.log.section(f"PROOF ENGINE — {len(confirmed)} confirmed findings")
        for finding in confirmed:
            proof = self.proof.generate(finding)
            finding['proof'] = proof
            safe_name = finding['type'] + "_" + finding['url'][:30].replace('/', '_').replace(':', '')
            proof_file = os.path.join(self.files["proof_dir"], f"{safe_name}.json")
            with open(proof_file, 'w') as f:
                json.dump({"finding": finding, "proof": proof}, f, indent=2)
            self.log.success(f"Proof → {os.path.basename(proof_file)}")

    def _calculate_risk_scores(self):
        for finding in self.findings:
            finding['risk_score'] = self.risk.score(finding)
        sorted_findings = sorted(self.findings,
            key=lambda f: f.get('risk_score', {}).get('total', 0), reverse=True)
        with open(self.files["risk_report"], 'w') as f:
            json.dump({"target": self.target, "findings": sorted_findings,
                       "generated": time.strftime("%Y-%m-%d %H:%M:%S")}, f, indent=2)

    def _refresh_fmt_files(self):
        if os.path.isfile(self.files["subdomains"]):
            FormatFixer.fix(self.files["subdomains"], self.files["fmt_domain"], "domain")
        if os.path.isfile(self.files["live_hosts"]):
            FormatFixer.fix(self.files["live_hosts"], self.files["fmt_url"], "url")
            FormatFixer.fix(self.files["live_hosts"], self.files["fmt_host"], "host")

    def _state_file(self):
        return os.path.join(self.out, f"{self.prefix}_state.json")

    def _save_state(self):
        with open(self._state_file(), "w") as f:
            json.dump({"target": self.target, "steps": self.steps_to_run,
                       "completed": [], "prefix": self.prefix,
                       "scan_id": self.audit.scan_id, "version": "6.0"}, f, indent=2)

    def _load_completed(self):
        sf = self._state_file()
        if os.path.isfile(sf):
            with open(sf) as f: return json.load(f).get("completed", [])
        return []

    def _mark_completed(self, name):
        sf = self._state_file()
        state = {}
        if os.path.isfile(sf):
            with open(sf) as f: state = json.load(f)
        state.setdefault("completed", [])
        if name not in state["completed"]:
            state["completed"].append(name)
        with open(sf, "w") as f: json.dump(state, f, indent=2)

    def shell(self, cmd: str, label: str = "", use_tor: bool = False,
              append_file: str = None, timeout: int = None,
              tool_name: str = "default") -> str:
        if label:
            self.log.info(f"  ↳ {label}")
        if timeout is None:
            timeout = self.tmgr.get(tool_name)
        if use_tor and self.tor and self.tor.is_running():
            cmd = f"proxychains4 -q {cmd}"
            self.tor.tick()
        if append_file:
            cmd = f"({cmd}) 2>/dev/null | tee -a {append_file}"
        else:
            cmd = f"({cmd}) 2>/dev/null"
        start = time.time()
        with self._audit_lock:
            self.audit.log_command(cmd[:200], tool_name)
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, timeout=timeout)
            elapsed = time.time() - start
            self.tmgr.record(tool_name, elapsed, False)
            with self._observer_lock:
                self.observer.record_tool_call(tool_name, True, int(elapsed * 1000))
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            self.tmgr.record(tool_name, elapsed, True)
            with self._observer_lock:
                self.observer.record_tool_call(tool_name, False, int(elapsed * 1000), timed_out=True)
            self.log.warn(f"  ↳ Timeout ({timeout}s): {label or tool_name}")
            return ""
        except Exception as e:
            self.log.error(f"  ↳ Shell error: {e}")
            return ""
