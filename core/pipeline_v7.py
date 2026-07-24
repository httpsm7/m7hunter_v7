#!/usr/bin/env python3
# core/pipeline_v7.py — M7Hunter V7 Main Pipeline
# Async, plugin-driven, CEO-controlled, double-verify, HTTP/2
# MilkyWay Intelligence | Author: Sharlix

import os
import sys
import time
import json
import asyncio
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# V6 imports (backward compat)
from core.error_handler import get_handler as _get_err_handler
from core.utils          import get_prefix, ensure_dir, count_lines, FormatFixer, is_in_scope
from core.rate_bypass    import RateBypass, TimeoutManager
from core.ceo_engine     import CEOEngine, PipelineState
from core.plugin_loader  import PluginLoader
from core.session_manager import SessionManager
from core.audit_logger   import AuditLogger
from engines.findings_engine  import FindingsEngine
from engines.chain_engine import ChainEngine
from engines.double_verify    import DoubleVerify
from engines.spa_crawler      import SPACrawler

# ── Phase definitions ────────────────────────────────────────────────
# BUG-020 FIX: Added crawl to PHASE1 so xss/ssrf/idor have params
# Added cors, host_header to PHASE1 (were missing — causing 0 findings)
PHASE1_STEPS = [
    "subdomain","dns","probe","crawl","nuclei",
    "xss","ssrf","cors","host_header",
    "takeover","github","idor","redirect","csrf",
]
PHASE2_STEPS = [
    "ports","sqli","lfi","screenshot",
    "wpscan","cloud","ssti","jwt","graphql",
    "xxe","smuggling","race","nosql","ws","proto_pollution",
]
DEEP_STEPS = PHASE1_STEPS + [s for s in PHASE2_STEPS if s not in PHASE1_STEPS]
RECON_STEPS = ["subdomain","dns","probe","ports","crawl"]
PARALLEL_WORKERS = 6

STEP_OUTPUT_MAP = {
    "subdomain":"subdomains","dns":"resolved","probe":"live_hosts",
    "ports":"open_ports","crawl":"urls","nuclei":"nuclei_results",
    "xss":"xss_results","sqli":"sqli_results","cors":"cors_results",
    "lfi":"lfi_results","ssrf":"ssrf_params","redirect":"redirect_results",
    "takeover":"takeover_results","github":"github_results","cloud":"cloud_results",
    "ssti":"ssti_results","jwt":"jwt_results","graphql":"graphql_results",
    "host_header":"host_header_results","csrf":"csrf_results","race":"race_results",
    "nosql":"nosql_results",
}



class _CfgShim:
    """Compatibility shim so modules can use self.p.cfg.get('key')"""
    def __init__(self, args):
        self._args = args
        self._data = {}
    def get(self, key, default=None):
        v = getattr(self._args, key, None)
        return v if v is not None else self._data.get(key, default)
    def set(self, key, val):
        self._data[key] = val

class PipelineV7:
    """
    M7Hunter V7 — Plugin-driven async pipeline.

    New in V7:
    - CEOEngine: live pause/resume/kill, rule enforcement
    - PluginLoader: auto-discover step modules
    - FindingsEngine: central thread-safe registry (fixes findings=0)
    - DoubleVerify: FP reduction before report
    - SPACrawler: headless JS crawling for React/Vue/Next apps
    - HTTP/2 via httpx for concurrent requests
    - Async race condition engine
    - WebSocket testing engine
    - Prototype pollution engine
    """

    def __init__(self, target, args, tor, oob, notifier, log,
                 scope_list=None, offline_ai=None,
                 confidence_threshold=0.8, ceo_rules=None):

        self.target               = target.strip()
        self.args                 = args
        self.tor                  = tor
        self.oob                  = oob
        self.notifier             = notifier
        self.log                  = log
        self.scope_list           = scope_list or []
        self.offline_ai           = offline_ai
        self.confidence_threshold = confidence_threshold

        # V7 components
        self.ceo            = CEOEngine(rules=ceo_rules, log=log)
        self.findings_engine = FindingsEngine()
        self.sessions       = SessionManager(args)
        self.double_verify  = DoubleVerify(self.ceo, log)
        self.spa_crawler    = SPACrawler(log=log)

        # Register graceful stop
        self.ceo.on_stop(self._save_checkpoint)

        # V6 compat
        self.findings       = []  # backward compat list
        self._findings_lock = threading.Lock()
        self._seen_findings = set()
        self._observer_lock = threading.Lock()
        self._audit_lock    = threading.Lock()

        self.bypass  = RateBypass(
            min_delay=3.0 if getattr(args,'stealth',False) else 0.3,
            max_delay=8.0 if getattr(args,'stealth',False) else 1.5,
        )
        self.tmgr    = TimeoutManager()
        if getattr(args,'stealth',False): self.tmgr.set_stealth()
        elif getattr(args,'fast',False):  self.tmgr.set_fast()

        self.cfg     = _CfgShim(args)
        self.prefix  = get_prefix(self.target)
        self.start_t = time.time()

        # Auth headers
        self.auth_headers = self.sessions.get("default")

        # Output dirs
        base = getattr(args,'output',None) or "results"
        ts   = time.strftime("%Y%m%d_%H%M%S")
        self.out = os.path.join(base, f"{self.prefix}_{ts}_v7")
        ensure_dir(self.out)

        # Plugin loader
        self._base_dir  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._plugin_loader = PluginLoader(self._base_dir, log=log)

        # Audit
        self.audit   = AuditLogger(target=self.target)
        self.audit.start_scan()

        # Files
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
            "proof_dir"          : os.path.join(self.out, "proofs"),
            "checkpoint"         : os.path.join(self.out, f"{p}_checkpoint.json"),
        }
        ensure_dir(self.files["proof_dir"])
        ensure_dir(self.files["screenshots_dir"])

        with open(self.files["raw_input"],"w") as f:
            f.write(self.target+"\n")

        self.steps_to_run = self._resolve_steps()
        self.log.set_steps(len(self.steps_to_run)+1)

    # ── Step resolution ──────────────────────────────────────────────
    def _resolve_steps(self):
        a = self.args
        if getattr(a,'fast',False) or getattr(a,'phase1_only',False):
            return PHASE1_STEPS
        if getattr(a,'deep',False) or getattr(a,'stealth',False) or getattr(a,'continuous',False):
            return DEEP_STEPS
        if getattr(a,'custom',False):
            return [s for s in DEEP_STEPS if getattr(a,s,False)] or PHASE1_STEPS
        return PHASE1_STEPS

    # ── Plugin-driven step map ───────────────────────────────────────
    def _build_step_map(self):
        """Auto-discover step classes via PluginLoader."""
        plugins = self._plugin_loader.discover(["modules"])
        step_map = self._plugin_loader.get_steps()

        # V7 new engines (not in modules/)
        from engines.race_engine_v7    import RaceEngineV7
        from engines.websocket_engine  import WebSocketEngine
        from engines.proto_pollution   import ProtoPollutionEngine

        step_map["race"]           = RaceEngineV7
        step_map["ws"]             = WebSocketEngine
        step_map["proto_pollution"] = ProtoPollutionEngine

        return step_map

    # ── Main run ─────────────────────────────────────────────────────
    def run(self) -> str:
        self.log.info(f"Output    : {self.out}")
        self.log.info(f"Scan ID   : {self.audit.scan_id}")
        self.log.info(f"V7 Engine : CEO={self.ceo.get_state()} | HTTP2=enabled | DoubleVerify={self.ceo.should_double_verify()}")
        self.log.info(f"Auth      : {self.sessions.describe()}")
        self.log.info(f"Multi-sess: {'YES (userA+userB)' if self.sessions.has_multi_session() else 'NO'}")
        self.log.info(f"Steps     : {' → '.join(self.steps_to_run)}")
        print()

        if self.notifier:
            self.notifier.send_scan_start(self.target)

        self._save_checkpoint()
        completed = self._load_checkpoint_steps()
        step_map  = self._build_step_map()

        # Recon (sequential)
        for step in [s for s in self.steps_to_run if s in RECON_STEPS]:
            if not self.ceo.step_gate():
                self.log.warn("[CEO] Pipeline stopped during recon")
                break
            if getattr(self.args,'resume',False) and step in completed:
                self.log._step_current += 1
                continue
            self._run_step(step_map, step)
            self._mark_completed(step)
            self._refresh_fmt()

        # Phase 1 vulns (parallel)
        p1 = [s for s in self.steps_to_run if s in PHASE1_STEPS and s not in RECON_STEPS]
        if p1:
            self.log.section("PHASE 1 — FAST VULNERABILITY SCAN (V7)")
            self._run_parallel(p1, step_map, completed)

        # Phase 2 deep (parallel)
        p2 = [s for s in self.steps_to_run if s in PHASE2_STEPS]
        if p2 and not getattr(self.args,'phase1_only',False):
            self.log.section("PHASE 2 — DEEP SCAN + V7 ENGINES")
            self._run_parallel(p2, step_map, completed)

        # Generate report
        self.log.step("REPORT")
        report_path = self._generate_report()
        elapsed = time.time() - self.start_t

        # Print findings summary
        self.findings_engine.print_summary()
        self.log.pipeline_done(self.target, elapsed, report_path)

        self.audit.end_scan(
            total_findings = self.findings_engine.get_stats()["total"],
            confirmed      = self.findings_engine.get_stats()["confirmed"],
            elapsed        = elapsed,
        )

        if self.notifier:
            stats = self.findings_engine.get_stats()
            self.notifier.send_scan_done(self.target, stats["total"], elapsed)

        return report_path

    def _run_step(self, step_map, step_name):
        StepClass = step_map.get(step_name)
        if not StepClass: return
        if not self.ceo.step_gate(): return

        self.log.step(step_name.upper())
        try:
            with self._observer_lock:
                self._observer_step_start(step_name)
            with self._audit_lock:
                self.audit.log_step_start(step_name)
            StepClass(self).run()
            output_file = self.files.get(STEP_OUTPUT_MAP.get(step_name,""))
            with self._audit_lock:
                self.audit.log_step_end(step_name,"success")
        except KeyboardInterrupt:
            self.log.warn("Interrupted"); raise
        except Exception as e:
            with self._audit_lock:
                self.audit.log_step_end(step_name,"failed",error=str(e))
            self.log.error(f"Step {step_name} failed: {e}")
            _get_err_handler().capture(f"pipeline/{step_name}", e, context="run_step")

    def _run_parallel(self, steps, step_map, completed):
        workers = min(len(steps), PARALLEL_WORKERS)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {}
            for step in steps:
                if getattr(self.args,'resume',False) and step in completed: continue
                cls = step_map.get(step)
                if cls:
                    self.log.info(f"  → Starting: {step}")
                    fut = ex.submit(self._run_step_safe, cls, step)
                    futures[fut] = step
            for fut in as_completed(futures):
                step = futures[fut]
                try:
                    fut.result()
                    self._mark_completed(step)
                except Exception as e:
                    self.log.error(f"Step {step} failed: {e}")
                    _get_err_handler().capture(f"pipeline/{step}", e, "parallel_step")

    def _run_step_safe(self, StepClass, step_name):
        if not self.ceo.step_gate(): return
        try:
            self.log.step(step_name.upper())
            with self._observer_lock:  self._observer_step_start(step_name)
            with self._audit_lock:     self.audit.log_step_start(step_name)
            StepClass(self).run()
            with self._audit_lock:     self.audit.log_step_end(step_name,"success")
        except Exception as e:
            # FIX: removed 'raise' — was causing threading.py:1043 crash
            with self._audit_lock: self.audit.log_step_end(step_name,"failed",error=str(e))
            self.log.error(f"{step_name}: {e}")
            from core.error_handler import get_handler
            get_handler().capture(f"step/{step_name}", e, "_run_step_safe")

    # ── add_finding (V7 — with CEO gate + double verify) ─────────────
    def add_finding(self, severity, vuln_type, url, detail="", tool="",
                    response="", payload="", baseline_len=0, status="potential"):
        """V7 add_finding: scope → dedup → CEO gate → double verify → register."""

        # Scope check — only block if scope_list has entries AND url fails
        if self.scope_list and len(self.scope_list) > 0:
            if not is_in_scope(str(url), self.scope_list):
                return

        # CEO gate: confidence + per-type limits
        # FIX: base confidence from severity — not a flat 0.8 which confuses CEO gate
        _sev_conf = {"critical":0.85,"high":0.80,"medium":0.70,"low":0.60,"info":0.50}
        conf = _sev_conf.get(severity.lower(), 0.75)
        if self.offline_ai and response:
            ai  = self.offline_ai.analyze_response(vuln_type, url, response, payload, baseline_len)
            conf = ai.get("confidence", 0.8)
            if ai.get("is_false_positive"):
                with self._audit_lock:
                    self.audit.log_fp_caught(vuln_type, url, ai.get("reason",[]))
                return
            if ai.get("verdict") == "confirmed":
                conf = min(conf + 0.15, 0.99)
                status = "confirmed"

        allow, reason = self.ceo.validate_finding(vuln_type, conf, severity)
        if not allow:
            # Don't silently drop — downgrade to potential/low for visibility
            status   = "potential"
            severity = "low" if severity in ("critical","high","medium") else "info"
            conf     = 0.45

        # URL pattern dedup (CEO rule)
        dedup_url = self.ceo.normalize_url_pattern(url)
        # FIX: include full URL params in dedup to avoid over-deduplication
        dedup_key = f"{vuln_type}:{url[:120]}:{payload[:40]}"
        with self._findings_lock:
            if dedup_key in self._seen_findings: return
            self._seen_findings.add(dedup_key)

        # Double-verify (CEO rule — optional by severity)
        if (self.ceo.should_double_verify() and
                severity in ("critical","high") and
                response and len(response) > 50):
            verify_result = self.double_verify.verify(
                vuln_type, url, payload, response, headers=self.auth_headers)
            if not verify_result["confirmed"]:
                # Downgrade to potential — FIX: was -0.20, too aggressive
                status = "potential"
                conf   = max(0.55, conf - 0.05)
            else:
                conf   = min(conf + verify_result.get("confidence_boost",0), 0.99)
                status = "confirmed"

        # Register in V7 FindingsEngine
        is_new = self.findings_engine.add(
            vuln_type  = vuln_type,
            url        = url,
            detail     = detail,
            payload    = payload,
            tool       = tool,
            response   = response,
            confidence = conf,
            severity   = severity,
            status     = status,
        )
        if not is_new: return

        # V6 compat list
        entry = {
            "severity"  : severity,
            "type"      : vuln_type,
            "url"       : url,
            "detail"    : detail,
            "tool"      : tool,
            "payload"   : payload,
            "time"      : time.strftime("%Y-%m-%d %H:%M:%S"),
            "status"    : status,
            "confidence": round(conf,3),
        }
        with self._findings_lock:
            self.findings.append(entry)

        # Console log
        self.log.finding(severity, vuln_type, url, detail)
        self.ceo.accept_finding(vuln_type)

        # CEO auto-chain
        chains = self.ceo.get_auto_chains(vuln_type)
        if chains:
            for chain_type, chain_module in chains:
                self.log.info(f"  [CEO] Auto-chain triggered: {chain_type}")

        # Notifier
        if self.notifier:
            self.notifier.send_finding(severity, vuln_type, url, detail, tool)

    # ── Checkpoint ───────────────────────────────────────────────────
    def _save_checkpoint(self):
        """FIX BUG-08: Save completed steps list, not findings dedup keys."""
        cp = self.files.get("checkpoint","")
        if not cp: return
        if not hasattr(self, '_completed_steps'):
            self._completed_steps = []
        data = {
            "target"          : self.target,
            "steps"           : self.steps_to_run,
            "completed_steps" : self._completed_steps,
            "findings_count"  : self.findings_engine.get_stats()["total"],
            "timestamp"       : time.strftime("%Y-%m-%d %H:%M:%S"),
            "version"         : "7.0",
        }
        with open(cp,"w") as f: json.dump(data, f, indent=2)

    def _load_checkpoint_steps(self) -> list:
        """FIX BUG-08: Load completed_steps (step names), not findings keys."""
        cp = self.files.get("checkpoint","")
        if cp and os.path.isfile(cp):
            try:
                with open(cp) as f:
                    data = json.load(f)
                # Support both old format and new format
                return data.get("completed_steps", data.get("completed", []))
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("pipeline_v7", _e)
        return []

    def _mark_completed(self, step: str):
        """FIX BUG-08: Track completed steps properly for --resume."""
        if not hasattr(self, '_completed_steps'):
            self._completed_steps = []
        if step not in self._completed_steps:
            self._completed_steps.append(step)
        self._save_checkpoint()

    # ── Report generation ────────────────────────────────────────────
    def _generate_report(self) -> str:
        try:
            from reporting.report_generator import ReportGeneratorV7
            gen   = ReportGeneratorV7(self)
            paths = gen.generate_all()
            for fmt, path in paths.items():
                if path and os.path.isfile(path):
                    self.log.success(f"{fmt.upper():10s} → {path}")
            return paths.get("html","")
        except ImportError:
            # Minimal JSON fallback
            path = os.path.join(self.out, f"{self.prefix}_findings_v7.json")
            self.findings_engine.save(path)
            self.log.success(f"JSON → {path}")
            return path

    # ── Helpers ──────────────────────────────────────────────────────
    def _observer_step_start(self, step_name):
        pass  # lightweight observer

    def _refresh_fmt(self):
        if os.path.isfile(self.files["subdomains"]):
            FormatFixer.fix(self.files["subdomains"], self.files["fmt_domain"],"domain")
        if os.path.isfile(self.files["live_hosts"]):
            FormatFixer.fix(self.files["live_hosts"],  self.files["fmt_url"],   "url")
            FormatFixer.fix(self.files["live_hosts"],  self.files["fmt_host"],  "host")

    def shell(self, cmd:str, label:str="", use_tor:bool=False,
              append_file:str=None, timeout:int=None, tool_name:str="default") -> str:
        if label: self.log.info(f"  ↳ {label}")
        if timeout is None: timeout = self.tmgr.get(tool_name)
        if use_tor and self.tor and self.tor.is_running():
            cmd = f"proxychains4 -q {cmd}"; self.tor.tick()
        # FIX: was 2>/dev/null — this suppressed tool output written to stderr
        # dalfox, kxss, nuclei write findings to stderr — must capture both
        if append_file: cmd = f"({cmd}) | tee -a {append_file}"
        else:           cmd = f"({cmd})"
        start = time.time()
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, timeout=timeout)
            self.tmgr.record(tool_name, time.time()-start, False)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.tmgr.record(tool_name, time.time()-start, True)
            self.log.warn(f"  ↳ Timeout ({timeout}s): {label or tool_name}")
            return ""
        except Exception as e:
            self.log.error(f"  ↳ Shell error: {e}"); return ""
