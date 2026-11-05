#!/usr/bin/env python3
# core/pipeline_v7.py — M7Hunter V7 Main Pipeline (FULL REBUILD)
# Fixed: step ordering, FP check, checkpoint, auto-chain, all new modules wired
# Strategic A→Z flow: Recon → Surface → Vuln → Deep → Advanced → Platform → Report
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, sys, time, json, subprocess, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List

# ── Core imports with clear error messages ───────────────────────
try:
    from core.utils           import get_prefix, ensure_dir, count_lines, FormatFixer, is_in_scope
    from core.rate_bypass     import RateBypass, TimeoutManager
    from core.ceo_engine      import CEOEngine, PipelineState
    from core.plugin_loader   import PluginLoader
    from core.session_manager import SessionManager
    from core.audit_logger    import AuditLogger
except ImportError as _e:
    raise ImportError(
        f"Core module missing: {_e}\n"
        "Run: sudo m7hunter --install"
    )

# ── Engine imports (safe — fallback stubs if missing) ─────────────
try:
    from engines.findings_engine import FindingsEngine
except ImportError:
    class FindingsEngine:
        def __init__(self): self._findings = []
        def add(self, **kw): self._findings.append(kw); return True
        def get_all(self): return self._findings
        def get_stats(self): return {"total": len(self._findings), "confirmed": 0}
        def print_summary(self): pass
        def save(self, path):
            import json
            open(path,"w").write(json.dumps(self._findings, indent=2, default=str))

try:
    from engines.double_verify import DoubleVerify
except ImportError:
    class DoubleVerify:
        def __init__(self, *a, **kw): pass
        def verify(self, *a, **kw): return {"confirmed": False, "confidence_boost": 0}

try:
    from engines.spa_crawler import SPACrawler
except ImportError:
    class SPACrawler:
        def __init__(self, **kw): pass

# ══════════════════════════════════════════════════════════════════════════════
# STRATEGIC PIPELINE ORDER — A to Z
# Each group feeds the next. Within each group, steps run in parallel.
# ══════════════════════════════════════════════════════════════════════════════

# GROUP 0 — RECON (sequential — each step feeds the next)
# subdomains → dns resolve → probe live → port scan → crawl URLs + JS
RECON_STEPS = ["subdomain", "dns", "probe", "ports", "crawl", "recon_deep"]

# GROUP 1 — FAST SURFACE SCAN (parallel — uses live_hosts + subdomains)
# Quick wins: templates, secrets, takeovers, visual recon — no URL params needed
SURFACE_STEPS = ["nuclei", "github", "takeover", "clickjacking", "csrf", "cors", "xss_advanced"]

# GROUP 2 — PARAMETER VULNERABILITY SCAN (parallel — uses crawled URLs)
# All need parameterized URLs from crawl — medium depth
PARAM_STEPS = ["xss", "ssrf", "open_redirect", "lfi", "idor", "redirect", "content"]

# GROUP 3 — DEEP TECHNOLOGY SCAN (parallel — require specific tech context)
# Need JWT tokens, GraphQL endpoints, OAuth endpoints, DB-backed params
DEEP_STEPS = ["sqli", "ssti", "jwt", "graphql", "oauth", "xxe", "nosql", "deserialization", "file_upload", "twofa_bypass", "business_logic", "session_fixation", "password_spray", "dep_confusion", "api_security", "sop_bypass"]

# GROUP 4 — ADVANCED ATTACK CHAINS (parallel — complex multi-step)
# HTTP smuggling, race conditions, protocol-level attacks
ADVANCED_STEPS = ["smuggling", "race", "host_header", "proto_pollution", "ws", "param_pollution", "deserialization"]

# GROUP 5 — PLATFORM-SPECIFIC (parallel — conditional on detected platform)
PLATFORM_STEPS = ["wpscan", "cloud", "screenshot", "hashcrack", "cve_exploit"]

# All steps in strategic order
ALL_STEPS = (RECON_STEPS + SURFACE_STEPS + PARAM_STEPS +
             DEEP_STEPS + ADVANCED_STEPS + PLATFORM_STEPS)

# Mode presets
MODE_FAST    = RECON_STEPS + ["nuclei","xss","cors","ssrf","takeover","csrf"]
MODE_PHASE1  = RECON_STEPS + SURFACE_STEPS + PARAM_STEPS
MODE_DEEP    = ALL_STEPS
MODE_STEALTH = RECON_STEPS + SURFACE_STEPS + PARAM_STEPS[:4]

# Step → output file key mapping (complete — covers all 30 steps)
STEP_OUTPUT_MAP = {
    "subdomain":    "subdomains",
    "dns":          "resolved",
    "probe":        "live_hosts",
    "ports":        "open_ports",
    "crawl":        "urls",
    "nuclei":       "nuclei_results",
    "github":       "github_results",
    "takeover":     "takeover_results",
    "clickjacking": "clickjacking_results",
    "csrf":         "csrf_results",
    "cors":         "cors_results",
    "xss":          "xss_results",
    "ssrf":         "ssrf_params",
    "open_redirect":"redirect_results",
    "redirect":     "redirect_results",
    "lfi":          "lfi_results",
    "idor":         "idor_results",
    "sqli":         "sqli_results",
    "ssti":         "ssti_results",
    "jwt":          "jwt_results",
    "graphql":      "graphql_results",
    "oauth":        "oauth_results",
    "xxe":          "xxe_results",
    "nosql":        "nosql_results",
    "smuggling":    "smuggling_results",
    "race":         "race_results",
    "host_header":  "host_header_results",
    "proto_pollution": "proto_results",
    "ws":           "ws_results",
    "wpscan":       "wpscan_results",
    "cloud":        "cloud_results",
    "screenshot":   "screenshots_dir",
}

# Steps that are independent enough to run even with no crawl data
NO_CRAWL_STEPS = {"nuclei","github","takeover","clickjacking","jwt","graphql"}

PARALLEL_WORKERS = 6


class PipelineV7:
    """
    M7Hunter V7 — Full pipeline, fixed and strategic.

    Flow: Recon → Surface → Params → Deep → Advanced → Platform → Report
    All bugs fixed: FP check, checkpoint, auto-chain, new modules registered.
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
        self.ollama_ai            = None
        self.confidence_threshold = confidence_threshold

        # ── AI Setup ──────────────────────────────────────────────────
        try:
            from ai.ollama_ai import OllamaAI
            self.ollama_ai = OllamaAI(log=log, model="llama3")
            if self.ollama_ai.is_available():
                log.success("Ollama AI connected — smart FP reduction active")
            else:
                self.ollama_ai = None
        except Exception:
            self.ollama_ai = None

        # Active AI: prefer Ollama, fall back to offline
        self._ai = self.ollama_ai or self.offline_ai

        # ── AI Cycles 1-4 ─────────────────────────────────────────────────────
        try:
            from ai.ai_trainer import AITrainer
            self._trainer = AITrainer(log=log)
            log.success(f"AI-C1 Trainer: {self._trainer.get_summary()}")
        except Exception as e:
            self._trainer = None
            log.warn(f"AI-C1 Trainer unavailable: {e}")

        try:
            from ai.smart_analyzer import SmartAnalyzer
            self._analyzer = SmartAnalyzer(
                ollama_ai=self.ollama_ai,
                trainer=self._trainer, log=log)
            log.success("AI-C2 SmartAnalyzer: per-vuln analysis active")
        except Exception as e:
            self._analyzer = None
            log.warn(f"AI-C2 Analyzer unavailable: {e}")

        try:
            from ai.payload_generator import PayloadGenerator
            self._payloadgen = PayloadGenerator(
                ollama_ai=self.ollama_ai, log=log)
            log.success("AI-C3 PayloadGen: custom payload generation active")
        except Exception as e:
            self._payloadgen = None
            log.warn(f"AI-C3 PayloadGen unavailable: {e}")

        try:
            from ai.autonomous_brain import AutonomousBrain
            self._brain = AutonomousBrain(
                ollama_ai=self.ollama_ai,
                trainer=self._trainer,
                payload_gen=self._payloadgen, log=log)
            log.success("AI-C4 AutonomousBrain: strategic decisions active")
        except Exception as e:
            self._brain = None
            log.warn(f"AI-C4 Brain unavailable: {e}")

        # Normalize auth attributes from new CLI flags
        # -s → session → cookie, -a → auth → authorization, -j → jwt
        if hasattr(args, 'session') and args.session and not getattr(args,'cookie',None):
            args.cookie = args.session
        if hasattr(args, 'auth') and args.auth:
            args.authorization = args.auth
        if not hasattr(args, 'cookie'):    args.cookie = None
        if not hasattr(args, 'authorization'): args.authorization = None
        if not hasattr(args, 'jwt'):       args.jwt = None
        if not hasattr(args, 'shodan_key'): args.shodan_key = None

        # ── Core engines ──────────────────────────────────────────────
        self.ceo             = CEOEngine(rules=ceo_rules, log=log)
        self.findings_engine = FindingsEngine()
        self.sessions        = SessionManager(args)
        self.double_verify   = DoubleVerify(self.ceo, log)
        self.spa_crawler     = SPACrawler(log=log)

        self.ceo.on_stop(self._save_checkpoint)

        # ── Thread safety ─────────────────────────────────────────────
        self.findings        = []           # V6 compat
        self._findings_lock  = threading.Lock()
        self._seen_findings  = set()        # dedup keys
        self._completed_steps: List[str] = []   # FIXED: track step names, not finding keys
        self._completed_lock = threading.Lock()
        self._observer_lock  = threading.Lock()
        self._audit_lock     = threading.Lock()
        self.auth_headers    = self.sessions.get("default")

        # ── Rate & timing ─────────────────────────────────────────────
        stealth = getattr(args, "stealth", False)
        fast    = getattr(args, "fast",    False)
        self.bypass = RateBypass(
            min_delay=3.0 if stealth else 0.3,
            max_delay=8.0 if stealth else 1.5,
        )
        self.tmgr = TimeoutManager()
        if stealth: self.tmgr.set_stealth()
        elif fast:  self.tmgr.set_fast()

        # ── Paths ─────────────────────────────────────────────────────
        self.prefix  = get_prefix(self.target)
        self.start_t = time.time()
        base = getattr(args, "output", None) or "results"
        ts   = time.strftime("%Y%m%d_%H%M%S")
        self.out = os.path.join(base, f"{self.prefix}_{ts}_v7")
        ensure_dir(self.out)

        # ── Plugin loader ─────────────────────────────────────────────
        self._base_dir      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._plugin_loader = PluginLoader(self._base_dir, log=log)

        # ── Audit ─────────────────────────────────────────────────────
        self.audit = AuditLogger(target=self.target)
        self.audit.start_scan()

        # ── File registry (complete — all 30 steps + support files) ──
        p = self.prefix
        self.files = {
            # Input
            "raw_input"          : os.path.join(self.out, f"{p}_raw_input.txt"),
            # Recon outputs
            "subdomains"         : os.path.join(self.out, f"{p}_subdomains.txt"),
            "resolved"           : os.path.join(self.out, f"{p}_resolved.txt"),
            "live_hosts"         : os.path.join(self.out, f"{p}_live_hosts.txt"),
            "open_ports"         : os.path.join(self.out, f"{p}_open_ports.txt"),
            "urls"               : os.path.join(self.out, f"{p}_urls.txt"),
            "js_files"           : os.path.join(self.out, f"{p}_js_files.txt"),
            "js_secrets"         : os.path.join(self.out, f"{p}_js_secrets.txt"),
            "params"             : os.path.join(self.out, f"{p}_params.txt"),
            "wayback_urls"       : os.path.join(self.out, f"{p}_wayback.txt"),
            "gau_urls"           : os.path.join(self.out, f"{p}_gau.txt"),
            "dns_records"        : os.path.join(self.out, f"{p}_dns.txt"),
            # Format helpers (refreshed after recon + after each parallel group)
            "fmt_domain"         : os.path.join(self.out, f"{p}_fmt_domain.txt"),
            "fmt_url"            : os.path.join(self.out, f"{p}_fmt_url.txt"),
            "fmt_host"           : os.path.join(self.out, f"{p}_fmt_host.txt"),
            # SQLi
            "sqli_params"        : os.path.join(self.out, f"{p}_sqli_params.txt"),
            "sqli_results"       : os.path.join(self.out, f"{p}_sqli_confirmed.txt"),
            # Vulnerability results — Group 1 Surface
            "nuclei_results"     : os.path.join(self.out, f"{p}_nuclei.txt"),
            "github_results"     : os.path.join(self.out, f"{p}_github.txt"),
            "takeover_results"   : os.path.join(self.out, f"{p}_takeover.txt"),
            "clickjacking_results": os.path.join(self.out, f"{p}_clickjacking.txt"),
            "csrf_results"       : os.path.join(self.out, f"{p}_csrf.txt"),
            "cors_results"       : os.path.join(self.out, f"{p}_cors.txt"),
            # Vulnerability results — Group 2 Params
            "xss_results"        : os.path.join(self.out, f"{p}_xss.txt"),
            "ssrf_params"        : os.path.join(self.out, f"{p}_ssrf.txt"),
            "redirect_results"   : os.path.join(self.out, f"{p}_redirect.txt"),
            "lfi_results"        : os.path.join(self.out, f"{p}_lfi.txt"),
            "idor_results"       : os.path.join(self.out, f"{p}_idor.txt"),
            # Vulnerability results — Group 3 Deep
            "ssti_results"       : os.path.join(self.out, f"{p}_ssti.txt"),
            "jwt_results"        : os.path.join(self.out, f"{p}_jwt.txt"),
            "graphql_results"    : os.path.join(self.out, f"{p}_graphql.txt"),
            "oauth_results"      : os.path.join(self.out, f"{p}_oauth.txt"),
            "xxe_results"        : os.path.join(self.out, f"{p}_xxe.txt"),
            "nosql_results"      : os.path.join(self.out, f"{p}_nosql.txt"),
            # Vulnerability results — Group 4 Advanced
            "smuggling_results"  : os.path.join(self.out, f"{p}_smuggling.txt"),
            "race_results"       : os.path.join(self.out, f"{p}_race.txt"),
            "host_header_results": os.path.join(self.out, f"{p}_host_header.txt"),
            "proto_results"      : os.path.join(self.out, f"{p}_proto_pollution.txt"),
            "ws_results"         : os.path.join(self.out, f"{p}_websocket.txt"),
            "deser_results"      : os.path.join(self.out, f"{p}_deserialization.txt"),
            "hpp_results"         : os.path.join(self.out, f"{p}_hpp.txt"),
            "upload_results"     : os.path.join(self.out, f"{p}_file_upload.txt"),
            "content_results"    : os.path.join(self.out, f"{p}_content.txt"),
            "hashcrack_results"  : os.path.join(self.out, f"{p}_hashcrack.txt"),
            "recon_deep_results" : os.path.join(self.out, f"{p}_recon_deep.txt"),
            "twofa_results"      : os.path.join(self.out, f"{p}_2fa_bypass.txt"),
            "bizlogic_results"   : os.path.join(self.out, f"{p}_business_logic.txt"),
            "session_results"    : os.path.join(self.out, f"{p}_session.txt"),
            "xss_adv_results"    : os.path.join(self.out, f"{p}_xss_advanced.txt"),
            "spray_results"      : os.path.join(self.out, f"{p}_password_spray.txt"),
            "depcf_results"      : os.path.join(self.out, f"{p}_dep_confusion.txt"),
            "exploit_results"    : os.path.join(self.out, f"{p}_cve_exploits.txt"),
            "api_results"        : os.path.join(self.out, f"{p}_api_security.txt"),
            "sop_results"        : os.path.join(self.out, f"{p}_sop_bypass.txt"),
            # Vulnerability results — Group 5 Platform
            "wpscan_results"     : os.path.join(self.out, f"{p}_wpscan.txt"),
            "cloud_results"      : os.path.join(self.out, f"{p}_cloud.txt"),
            # Dirs
            "screenshots_dir"    : os.path.join(self.out, "screenshots"),
            "wpscan_dir"         : os.path.join(self.out, "wpscan"),
            "proof_dir"          : os.path.join(self.out, "proofs"),
            # Checkpoint
            "checkpoint"         : os.path.join(self.out, f"{p}_checkpoint.json"),
        }

        ensure_dir(self.files["proof_dir"])
        ensure_dir(self.files["screenshots_dir"])
        ensure_dir(self.files["wpscan_dir"])

        with open(self.files["raw_input"], "w") as f:
            f.write(self.target + "\n")

        self.steps_to_run = self._resolve_steps()
        self.log.set_steps(len(self.steps_to_run) + 1)

    # ══════════════════════════════════════════════════════════════════
    # STEP RESOLUTION
    # ══════════════════════════════════════════════════════════════════

    def _resolve_steps(self) -> List[str]:
        a = self.args
        if getattr(a, "fast",        False): return MODE_FAST
        if getattr(a, "phase1_only", False): return MODE_PHASE1
        if getattr(a, "stealth",     False): return MODE_STEALTH
        if getattr(a, "deep",        False) or getattr(a, "continuous", False):
            return MODE_DEEP
        if getattr(a, "custom",      False):
            custom = [s for s in ALL_STEPS if getattr(a, s, False)]
            return custom if custom else MODE_PHASE1
        # Default: full deep scan
        return MODE_DEEP

    # ══════════════════════════════════════════════════════════════════
    # STEP MAP
    # ══════════════════════════════════════════════════════════════════

    def _build_step_map(self) -> Dict[str, type]:
        """
        Build complete step → class map.
        Priority: module files > engine classes.
        """
        # Discover all step modules
        self._plugin_loader.discover(["modules"])
        step_map = self._plugin_loader.get_steps()

        # V7 engine-based steps (not in modules/)
        engine_steps = {
            "race":           ("engines.race_engine_v7",   "RaceEngineV7"),
            "ws":             ("engines.websocket_engine",  "WebSocketEngine"),
            "proto_pollution":("engines.proto_pollution",   "ProtoPollutionEngine"),
        }
        for step_key, (mod_path, cls_name) in engine_steps.items():
            if step_key not in step_map:
                try:
                    import importlib
                    mod = importlib.import_module(mod_path)
                    cls = getattr(mod, cls_name, None)
                    if cls:
                        step_map[step_key] = cls
                except Exception as e:
                    self.log.warn(f"  Engine {step_key}: {e}")

        # Log what was discovered
        self.log.info(f"  Pipeline: {len(step_map)} steps registered")
        missing = [s for s in self.steps_to_run if s not in step_map]
        if missing:
            self.log.warn(f"  Missing modules: {', '.join(missing)}")

        return step_map

    # ══════════════════════════════════════════════════════════════════
    # MAIN RUN — A TO Z
    # ══════════════════════════════════════════════════════════════════

    def run(self) -> str:
        self.log.info(f"Output     : {self.out}")
        self.log.info(f"Scan ID    : {self.audit.scan_id}")
        self.log.info(f"AI Engine  : {'Ollama ('+self.ollama_ai.model+')' if self.ollama_ai else 'Offline'}")
        self.log.info(f"V7 Engine  : CEO={self.ceo.get_state()} | DoubleVerify={self.ceo.should_double_verify()}")
        self.log.info(f"Auth       : {self.sessions.describe()}")
        self.log.info(f"Multi-Sess : {'YES (userA+userB)' if self.sessions.has_multi_session() else 'NO'}")
        self.log.info(f"Mode       : {self._mode_label()}")
        self.log.info(f"Steps      : {len(self.steps_to_run)} total")
        print()

        if self.notifier:
            self.notifier.send_scan_start(self.target)

        self._restore_checkpoint()
        step_map = self._build_step_map()

        # ── GROUP 0: RECON (sequential) ───────────────────────────────
        self.log.section("GROUP 0 — RECON")
        for step in [s for s in RECON_STEPS if s in self.steps_to_run]:
            if not self.ceo.step_gate():
                self.log.warn("[CEO] Pipeline halted"); break
            if self._already_done(step):
                self.log.info(f"  ↳ {step} — resumed from checkpoint"); continue
            self._run_step(step_map, step)
            self._mark_done(step)
            self._refresh_fmt()   # FIXED: refresh after every recon step

        # ── Validate recon outputs before proceeding ─────────────────
        self._validate_recon_outputs()

        # ── GROUP 1: FAST SURFACE (parallel) ─────────────────────────
        g1 = [s for s in SURFACE_STEPS if s in self.steps_to_run]
        if g1:
            self.log.section("GROUP 1 — FAST SURFACE SCAN")
            self._run_parallel(g1, step_map)
            self._refresh_fmt()

        # ── GROUP 2: PARAMETER VULNS (parallel) ──────────────────────
        g2 = [s for s in PARAM_STEPS if s in self.steps_to_run]
        if g2:
            self.log.section("GROUP 2 — PARAMETER VULNERABILITY SCAN")
            self._run_parallel(g2, step_map)

        # ── GROUP 3: DEEP TECH (parallel) ────────────────────────────
        g3 = [s for s in DEEP_STEPS if s in self.steps_to_run]
        if g3:
            self.log.section("GROUP 3 — DEEP TECHNOLOGY SCAN")
            self._run_parallel(g3, step_map)

        # ── GROUP 4: ADVANCED CHAINS (parallel) ──────────────────────
        g4 = [s for s in ADVANCED_STEPS if s in self.steps_to_run]
        if g4:
            self.log.section("GROUP 4 — ADVANCED ATTACK CHAINS")
            self._run_parallel(g4, step_map)

        # ── GROUP 5: PLATFORM SPECIFIC (parallel) ────────────────────
        g5 = [s for s in PLATFORM_STEPS if s in self.steps_to_run]
        if g5:
            self.log.section("GROUP 5 — PLATFORM SCAN")
            self._run_parallel(g5, step_map)

        # ── REPORT ───────────────────────────────────────────────────
        self.log.section("REPORT GENERATION")
        report_path = self._generate_report()
        elapsed     = time.time() - self.start_t

        self.findings_engine.print_summary()
        self.log.pipeline_done(self.target, elapsed, report_path)

        stats = self.findings_engine.get_stats()
        self.audit.end_scan(
            total_findings=stats["total"],
            confirmed=stats.get("confirmed", 0),
            elapsed=elapsed,
        )

        if self.notifier:
            self.notifier.send_scan_done(self.target, stats["total"], elapsed)

        self._save_checkpoint()
        return report_path

    # ══════════════════════════════════════════════════════════════════
    # STEP EXECUTION
    # ══════════════════════════════════════════════════════════════════

    def _run_step(self, step_map: dict, step_name: str):
        StepClass = step_map.get(step_name)
        if not StepClass:
            self.log.warn(f"  [{step_name}] No module — skipping")
            return
        if not self.ceo.step_gate():
            return

        self.log.step(step_name.upper())
        try:
            with self._audit_lock:
                self.audit.log_step_start(step_name)
            StepClass(self).run()
            with self._audit_lock:
                self.audit.log_step_end(step_name, "success")
        except KeyboardInterrupt:
            self.log.warn("Interrupted"); raise
        except Exception as e:
            with self._audit_lock:
                self.audit.log_step_end(step_name, "failed", error=str(e))
            self.log.error(f"  [{step_name}] Error: {e}")

    def _run_parallel(self, steps: List[str], step_map: dict):
        """Run steps in parallel, respecting CEO gate and resume."""
        pending = [s for s in steps if not self._already_done(s)]
        if not pending:
            return

        workers = min(len(pending), PARALLEL_WORKERS)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for step in pending:
                cls = step_map.get(step)
                if cls:
                    self.log.info(f"  → Launching: {step}")
                    fut = executor.submit(self._run_step_safe, cls, step)
                    futures[fut] = step
                else:
                    self.log.warn(f"  → No module for: {step}")

            for fut in as_completed(futures):
                step = futures[fut]
                try:
                    fut.result()
                    self._mark_done(step)
                except Exception as e:
                    self.log.error(f"  [{step}] Parallel error: {e}")

    def _run_step_safe(self, StepClass, step_name: str):
        """Thread-safe step runner for parallel execution."""
        if not self.ceo.step_gate():
            return
        try:
            self.log.step(step_name.upper())
            with self._audit_lock:
                self.audit.log_step_start(step_name)
            StepClass(self).run()
            with self._audit_lock:
                self.audit.log_step_end(step_name, "success")
        except Exception as e:
            with self._audit_lock:
                self.audit.log_step_end(step_name, "failed", error=str(e))
            self.log.error(f"  [{step_name}] Error: {e}")
            raise

    # ══════════════════════════════════════════════════════════════════
    # ADD FINDING — FIXED
    # ══════════════════════════════════════════════════════════════════

    def add_finding(self, severity: str, vuln_type: str, url: str,
                    detail: str = "", tool: str = "",
                    response: str = "", payload: str = "",
                    baseline_len: int = 0, status: str = "potential"):
        """
        Central finding registration. Fixed:
        - Correct AI verdict field ('verdict' == 'false_positive')
        - Proper double-verify flow
        - Thread-safe throughout
        """

        # ── 1. Scope check ────────────────────────────────────────────
        if self.scope_list and not is_in_scope(str(url), self.scope_list):
            return

        # ── 2. AI verification (FIXED: use 'verdict' not 'is_false_positive') ─
        conf = self.confidence_threshold
        # ── Smart analysis (AI-C2 SmartAnalyzer + AI-C1 Trainer) ──────────────
        if response:
            try:
                analyzer = getattr(self, '_analyzer', None)
                if analyzer:
                    ai_result = analyzer.analyze(
                        vuln_type, str(url), response, payload,
                        baseline_len, status_code if 'status_code' in dir() else 200)
                elif self._ai:
                    ai_result = self._ai.analyze_response(
                        vuln_type, str(url), response, payload, baseline_len)
                else:
                    ai_result = None

                if ai_result:
                    conf    = float(ai_result.get("confidence", conf))
                    verdict = ai_result.get("verdict", "potential")

                    if verdict == "false_positive":
                        # Train on this FP
                        if self._trainer:
                            self._trainer.record_finding(
                                vuln_type, str(url), payload, response,
                                "false_positive", conf,
                                ai_result.get("reason","AI flagged"))
                        with self._audit_lock:
                            self.audit.log_fp_caught(
                                vuln_type, url, ai_result.get("reason","AI flagged"))
                        return

                    if verdict == "confirmed":
                        conf   = min(conf + 0.15, 0.99)
                        status = "confirmed"
                        # Train on confirmed finding
                        if self._trainer:
                            self._trainer.record_finding(
                                vuln_type, str(url), payload, response,
                                "true_positive", conf)

            except Exception as _e:


                self.log.warn(f'  [M7] Suppressed: {_e}')  # AI failure never blocks finding

        # ── 3. CEO gate ───────────────────────────────────────────────
        allow, reason = self.ceo.validate_finding(vuln_type, conf, severity)
        if not allow:
            return

        # ── 4. Deduplication ──────────────────────────────────────────
        dedup_url = self.ceo.normalize_url_pattern(str(url))
        dedup_key = f"{vuln_type}:{dedup_url}:{payload[:40]}"
        with self._findings_lock:
            if dedup_key in self._seen_findings:
                return
            self._seen_findings.add(dedup_key)

        # ── 5. Double-verify (only for high/critical confirmed) ───────
        if (self.ceo.should_double_verify() and
                severity in ("critical", "high") and
                response and len(response) > 50 and
                status != "confirmed"):
            try:
                vr = self.double_verify.verify(
                    vuln_type, str(url), payload, response,
                    headers=self.auth_headers)
                if vr.get("confirmed"):
                    conf   = min(conf + vr.get("confidence_boost", 0.1), 0.99)
                    status = "confirmed"
                else:
                    status = "potential"
                    conf   = max(0.40, conf - 0.20)
            except Exception as _e:

                self.log.warn(f'  [M7] Suppressed: {_e}')

        # ── 6. Register finding ───────────────────────────────────────
        is_new = self.findings_engine.add(
            vuln_type  = vuln_type,
            url        = str(url),
            detail     = detail,
            payload    = payload,
            tool       = tool,
            response   = response,
            confidence = conf,
            severity   = severity,
            status     = status,
        )
        if not is_new:
            return

        # V6 compat list
        entry = {
            "vuln_type"  : vuln_type,
            "severity"   : severity,
            "url"        : str(url),
            "detail"     : detail,
            "tool"       : tool,
            "payload"    : payload,
            "time"       : time.strftime("%Y-%m-%d %H:%M:%S"),
            "status"     : status,
            "confidence" : round(conf, 3),
        }
        with self._findings_lock:
            self.findings.append(entry)

        # ── 7. Console + notifications ────────────────────────────────
        self.log.finding(severity, vuln_type, str(url), detail)
        self.ceo.accept_finding(vuln_type)

        # ── 8. CEO auto-chain (FIXED: actually triggers chain steps) ──
        chains = self.ceo.get_auto_chains(vuln_type)
        for chain_step, chain_label in (chains or []):
            self.log.info(f"  [CEO→Chain] {vuln_type} → triggers {chain_step}")
            # Schedule chain step to run if not already done
            if chain_step not in self._completed_steps:
                threading.Thread(
                    target=self._run_chain_step,
                    args=(chain_step,),
                    daemon=True
                ).start()

        if self.notifier:
            self.notifier.send_finding(severity, vuln_type, str(url), detail, tool)

    def _run_chain_step(self, step_name: str):
        """Run a CEO-chained step in background."""
        try:
            step_map = self._build_step_map()
            cls = step_map.get(step_name)
            if cls and step_name not in self._completed_steps:
                self.log.info(f"  [CEO→Chain] Running: {step_name}")
                cls(self).run()
                self._mark_done(step_name)
        except Exception as e:
            self.log.warn(f"  [CEO→Chain] {step_name} error: {e}")

    # ══════════════════════════════════════════════════════════════════
    # CHECKPOINT — FIXED (tracks step names, not finding keys)
    # ══════════════════════════════════════════════════════════════════

    def _save_checkpoint(self):
        cp = self.files.get("checkpoint", "")
        if not cp:
            return
        with self._completed_lock:
            completed = list(self._completed_steps)
        data = {
            "target"    : self.target,
            "version"   : "7.0",
            "timestamp" : time.strftime("%Y-%m-%d %H:%M:%S"),
            "steps_plan": self.steps_to_run,
            "completed" : completed,        # FIXED: step names, not finding keys
            "findings"  : self.findings_engine.get_stats().get("total", 0),
        }
        try:
            with open(cp, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as _e:

            self.log.warn(f'  [M7] Suppressed: {_e}')

    def _restore_checkpoint(self):
        """FIXED: restore completed step names from checkpoint."""
        cp = self.files.get("checkpoint", "")
        if not (cp and os.path.isfile(cp)):
            return
        if not getattr(self.args, "resume", False):
            return
        try:
            with open(cp) as f:
                data = json.load(f)
            if data.get("target") == self.target:
                restored = data.get("completed", [])
                # Only restore if they look like step names
                valid    = [s for s in restored if s in ALL_STEPS]
                with self._completed_lock:
                    self._completed_steps = valid
                self.log.info(f"  Resumed: {len(valid)} steps already done")
        except Exception as _e:

            self.log.warn(f'  [M7] Suppressed: {_e}')

    def _mark_done(self, step: str):
        with self._completed_lock:
            if step not in self._completed_steps:
                self._completed_steps.append(step)
        self._save_checkpoint()

    def _already_done(self, step: str) -> bool:
        with self._completed_lock:
            return step in self._completed_steps

    # ══════════════════════════════════════════════════════════════════
    # REPORT
    # ══════════════════════════════════════════════════════════════════

    def _validate_recon_outputs(self):
        """
        ARCHITECTURE CRITICAL: Guarantee fmt_url.txt is never empty.
        Called after GROUP 0 (recon). If recon produced no live hosts,
        we populate from target URL so ALL subsequent modules have data.
        """
        fmt_url  = self.files.get("fmt_url","")
        fmt_host = self.files.get("fmt_host","")
        live     = self.files.get("live_hosts","")

        # Check if fmt_url has content
        from core.utils import count_lines, FormatFixer
        import os

        n = count_lines(fmt_url) if fmt_url and os.path.isfile(fmt_url) else 0

        # Brain: detect tech stack if payloadgen available
        if getattr(self,'_payloadgen',None) and n > 0:
            try:
                import urllib.request
                req  = urllib.request.Request(self.target,
                       headers={"User-Agent":"M7Hunter/7.0"})
                resp = urllib.request.urlopen(req, timeout=8)
                body = resp.read(50000).decode("utf-8","ignore")
                hdrs = {k.lower():v for k,v in resp.headers.items()}
                self._tech = self._payloadgen.detect_tech_stack(hdrs, body)
                self.log.info(f"  Tech: WAF={self._tech.get('waf','none')} "
                              f"FW={self._tech.get('frameworks',[])} "
                              f"DB={self._tech.get('db','?')}")
            except Exception:
                self._tech = {}
        else:
            self._tech = {}

        if n == 0:
            self.log.warn("PIPELINE: fmt_url.txt empty after recon — "
                          "forcing target URL as fallback")

            # Try to build fmt_url from live_hosts
            if live and os.path.isfile(live) and count_lines(live) > 0:
                FormatFixer.fix(live, fmt_url, "url")
                FormatFixer.fix(live, fmt_host, "host")
                n = count_lines(fmt_url) if fmt_url else 0

            # Still empty → write target directly
            if n == 0:
                raw = self.target
                if not raw.startswith("http"):
                    raw = "https://" + raw
                domain = raw.replace("https://","").replace("http://","").split("/")[0]

                if fmt_url:
                    with open(fmt_url,"w") as f: f.write(raw + "\n")
                if fmt_host:
                    with open(fmt_host,"w") as f: f.write(domain + "\n")
                if live and not os.path.isfile(live):
                    with open(live,"w") as f: f.write(raw + "\n")

                self.log.warn(f"PIPELINE: Fallback set → {raw}")
                self.log.warn("PIPELINE: Limited recon data — "
                              "scan continues with direct target only")
                self.log.warn("PIPELINE: Run --install to get full tool coverage")
        else:
            self.log.success(f"PIPELINE: Recon validated — "
                             f"{n} live hosts ready for vuln scan ✅")

    def _generate_report(self) -> str:
        html_path = ""

        # Standard report
        try:
            from reporting.report_generator import ReportGeneratorV6
            gen   = ReportGeneratorV6(self)
            paths = gen.generate_all()
            for fmt, path in paths.items():
                if path and os.path.isfile(path):
                    self.log.success(f"  {fmt.upper():10s} → {path}")
            html_path = paths.get("html", "")
        except Exception as e:
            self.log.warn(f"  Standard report error: {e}")
            path = os.path.join(self.out, f"{self.prefix}_findings_v7.json")
            try:
                self.findings_engine.save(path)
                self.log.success(f"  JSON       → {path}")
                html_path = path
            except Exception as _e:

                self.log.warn(f'  [M7] Suppressed: {_e}')

        # Executive Report (non-technical stakeholders)
        try:
            from reporting.executive_report import ExecutiveReportGenerator
            if self.findings:
                ex  = ExecutiveReportGenerator(target=self.target, out_dir=self.out)
                exp = ex.generate(self.findings)
                if exp and os.path.isfile(exp):
                    self.log.success(f"  EXECUTIVE  → {exp}")
        except Exception as e:
            self.log.warn(f"  Exec report error: {e}")

        # AI Brain: generate attack narrative
        try:
            brain = getattr(self, '_brain', None)
            if brain and self.findings:
                narrative = brain.generate_narrative(
                    self.findings, self.target)
                narrative_path = os.path.join(
                    self.out, f"{self.prefix}_attack_narrative.txt")
                with open(narrative_path,'w') as f:
                    f.write(narrative)
                self.log.success(f"  NARRATIVE  → {narrative_path}")
                # Log AI summary
                self.log.info(f"  {brain.get_summary()}")
                if self._trainer:
                    self.log.info(f"  {self._trainer.get_summary()}")
        except Exception as e:
            self.log.warn(f"  Brain narrative error: {e}")

        # Bug Bounty report (HackerOne / Bugcrowd format)
        try:
            from reporting.bug_bounty_report import BugBountyReportGenerator
            findings = self.findings
            if findings:
                bb  = BugBountyReportGenerator(target=self.target, out_dir=self.out)
                bbs = bb.generate_all(findings)
                for fmt, path in bbs.items():
                    if path and os.path.isfile(path):
                        self.log.success(f"  BB_{fmt.upper():7s}  → {path}")
        except Exception as e:
            self.log.warn(f"  BB report error: {e}")

        return html_path

    # ══════════════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════════════

    def _refresh_fmt(self):
        """Refresh formatted helper files after recon steps."""
        if os.path.isfile(self.files["subdomains"]):
            FormatFixer.fix(
                self.files["subdomains"],
                self.files["fmt_domain"], "domain")
        if os.path.isfile(self.files["live_hosts"]):
            FormatFixer.fix(
                self.files["live_hosts"],
                self.files["fmt_url"], "url")
            FormatFixer.fix(
                self.files["live_hosts"],
                self.files["fmt_host"], "host")

    def _mode_label(self) -> str:
        a = self.args
        if getattr(a, "fast",        False): return "FAST"
        if getattr(a, "stealth",     False): return "STEALTH"
        if getattr(a, "phase1_only", False): return "PHASE1"
        if getattr(a, "deep",        False): return "DEEP"
        if getattr(a, "continuous",  False): return "CONTINUOUS"
        if getattr(a, "custom",      False): return "CUSTOM"
        return "DEEP (default)"

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
        try:
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, timeout=timeout)
            self.tmgr.record(tool_name, time.time() - start, False)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.tmgr.record(tool_name, time.time() - start, True)
            self.log.warn(f"  ↳ Timeout ({timeout}s): {label or tool_name}")
            return ""
        except Exception as e:
            self.log.error(f"  ↳ Shell error: {e}")
            return ""
