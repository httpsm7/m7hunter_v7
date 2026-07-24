#!/usr/bin/env python3
# core/pipeline_edrp.py — Event-Driven Resource-Orchestrated Pipeline
# Blueprint: wake→execute→persist→release→sleep→next
# Integrates Scheduler + ResourceController + StateManager + EngineRegistry
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import os, uuid, time, threading
from core.scheduler          import Scheduler, StageState
from core.resource_controller import ResourceController
from core.state_manager       import StateManager
from core.engine_registry     import get_registry, EngineRegistry
from core.error_handler       import get_handler

class EDRPipeline:
    """
    Event-Driven Resource-Orchestrated Pipeline (EDRP).

    Blueprint design:
    User Input → Scope Engine → Recon Scheduler → Subdomain Engine
    → DNS/IP Resolver → Port Scanner → HTTP Fingerprinter
    → Crawler/Parameter Mapper → Vuln Engine Selector
    → Focused Verification → AI Confidence Review
    → Findings Store → Report Generator → Sleep + Checkpoint

    RAM rule: only one heavy module active at a time.
    Playwright only on demand. AI only on suspicious findings.
    Crawl depth limited by memory state. Batch output to SQLite.
    Unload engines after completion.
    """

    def __init__(self, pipeline):
        self.p          = pipeline
        self.log        = pipeline.log
        self.args       = pipeline.args
        self.target     = pipeline.target
        self.out        = pipeline.out
        self.prefix     = pipeline.prefix
        self.scan_id    = self._make_scan_id()
        self._start_time= time.time()

        # Blueprint components
        self.registry   = get_registry()
        self.state      = StateManager()
        self.rctrl      = ResourceController(
            ram_limit_mb=getattr(self.args, "ram_limit_mb", 8192),
            log=self.log
        )
        self.scheduler  = Scheduler(
            pipeline   = pipeline,
            resource_ctrl= self.rctrl,
            state_mgr  = self.state,
            registry   = self.registry,
            log        = self.log,
        )

        # AI gate reference
        self._ai_ctrl   = None
        self._dashboard_thread = None

    def _make_scan_id(self) -> str:
        """Resume: reuse existing scan_id or create new."""
        if getattr(self.args, "resume", False):
            existing = self.state.find_resumable_scan(self.target) if hasattr(self, "state") else None
            if existing:
                self.log.info(f"[EDRP] Resuming scan: {existing['scan_id']}")
                return existing["scan_id"]
        sid = f"{self.prefix}_{str(uuid.uuid4())[:8]}"
        return sid

    # ── Main entry point ──────────────────────────────────────────────
    def run(self):
        self.log.info(f"[EDRP] Starting — scan_id={self.scan_id}")
        self.log.info(f"[EDRP] Target: {self.target}")

        # Register scan in SQLite
        self.state.create_scan(self.scan_id, self.target, vars(self.args))

        # Start resource monitor
        self.rctrl.start_monitoring(interval=5.0)
        self.log.info(f"[EDRP] Resource monitor started")

        # Determine engines to run
        lab        = getattr(self.args, "lab", False)
        available  = self.registry.available_engines(lab=lab)
        engines    = self._select_engines(available)

        self.log.info(f"[EDRP] Engines selected: {len(engines)}")
        for e in engines:
            spec = self.registry.get(e)
            rc   = spec.ram_class if spec else "?"
            self.log.info(f"  [{rc:8s}] {e}")

        # Register stage-done callback → push to web dashboard
        self.scheduler.on_stage_done(self._on_stage_done)

        # Start optional web dashboard in background
        if getattr(self.args, "dashboard", False):
            self._start_dashboard()

        # ── Run the EDRP loop ─────────────────────────────────────────
        resume = getattr(self.args, "resume", False)
        try:
            self.scheduler.run_all(engines, resume=resume)
        except KeyboardInterrupt:
            self.log.warn("[EDRP] Interrupted — saving checkpoint")
            self.scheduler.stop()
        except Exception as e:
            get_handler().capture("pipeline_edrp", e, "run_all")

        # ── AI confidence gate (post-scan) ────────────────────────────
        self._run_ai_gate()

        # ── Generate reports ──────────────────────────────────────────
        self._generate_reports()

        # ── Final checkpoint + sleep ──────────────────────────────────
        self.state.finish_scan(self.scan_id, "completed")
        self.state.save_checkpoint(self.scan_id, "final", {
            "duration_s": round(time.time() - self._start_time, 1),
            "resource"  : self.rctrl.status_str(),
            "stages"    : self.scheduler.stage_states(),
        })
        self.rctrl.stop_monitoring()

        # Summary
        summary = self.state.scan_summary(self.scan_id)
        self.log.success(
            f"[EDRP] COMPLETE — {summary.get('total_findings',0)} findings "
            f"in {round(time.time()-self._start_time,1)}s"
        )
        return summary

    # ── Engine selection ──────────────────────────────────────────────
    def _select_engines(self, available: list) -> list:
        args = self.args

        # Phase control flags
        if getattr(args, "phase1_only", False):
            phase1 = ["step01_subdomain","step02_dns","step03_probe",
                      "step04_ports","step05_crawl","step06_nuclei","step13_takeover"]
            return [e for e in available if e in phase1]

        if getattr(args, "recon_only", False):
            return [e for e in available
                    if self.registry.get(e) and
                    self.registry.get(e).stage_group in ("recon","probe")]

        # Exclude screenshots if --no-screenshots
        result = list(available)
        if getattr(args, "no_screenshots", False):
            result = [e for e in result if e != "step14_screenshot"]

        # Exclude wpscan unless target is WordPress
        if not getattr(args, "wordpress", False):
            result = [e for e in result if e != "step15_wpscan"]

        return result

    # ── Callbacks ─────────────────────────────────────────────────────
    def _on_stage_done(self, name: str, ex):
        """Called by Scheduler when any stage completes."""
        try:
            from web.server import broadcast_progress
            pct = self._calc_progress()
            broadcast_progress(name, pct, f"{name} done ({ex.findings_n} findings)")
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("pipeline_edrp", _e)

    def _calc_progress(self) -> int:
        states = self.scheduler.stage_states()
        if not states: return 0
        done = sum(1 for s in states.values()
                   if s in ("done","failed","skipped","sleeping"))
        return round(done / len(states) * 100)

    # ── AI gate (Blueprint: only on suspicious/ambiguous findings) ────
    def _run_ai_gate(self):
        if not self.rctrl.ai_allowed():
            self.log.warn("[EDRP] AI gate skipped — RAM too high")
            return
        try:
            findings = self.state.get_findings(self.scan_id)
            ambiguous = [
                f for f in findings
                if 0.50 <= f.get("confidence", 0) <= 0.84
            ]
            if not ambiguous:
                self.log.info("[EDRP] AI gate: no ambiguous findings to review")
                return
            self.log.info(f"[EDRP] AI gate: reviewing {len(ambiguous)} ambiguous findings")
            from integrations.ollama_ai import OllamaAI
            ai = OllamaAI(log=self.log)
            for f in ambiguous[:20]:   # cap at 20 to control RAM
                try:
                    result = ai.verify_finding(f)
                    if result and result.get("confidence"):
                        f["ai_confidence"]  = result["confidence"]
                        f["ai_verdict"]     = result.get("verdict", "")
                        f["ai_explanation"] = result.get("explanation", "")
                        self.state.save_checkpoint(
                            self.scan_id,
                            f"ai_{f.get('id','')}",
                            result
                        )
                except Exception as e:
                    get_handler().capture("pipeline_edrp", e, "ai_gate_finding")
        except ImportError:
            self.log.info("[EDRP] AI gate skipped — ollama not available")
        except Exception as e:
            get_handler().capture("pipeline_edrp", e, "_run_ai_gate")

    # ── Reporting ─────────────────────────────────────────────────────
    def _generate_reports(self):
        try:
            findings = self.state.get_findings(self.scan_id)
            self.log.info(f"[EDRP] Generating reports — {len(findings)} total findings")

            # Inject SQLite findings back into findings_engine for report_generator
            if hasattr(self.p, "findings_engine"):
                for f in findings:
                    try:
                        self.p.findings_engine.add(
                            vuln_type  = f.get("vuln_type",""),
                            url        = f.get("url",""),
                            detail     = f.get("detail",""),
                            confidence = f.get("confidence",0),
                            severity   = f.get("severity","info"),
                        )
                    except Exception as _e:
                        from core.error_handler import get_handler
                        get_handler().capture("pipeline_edrp", _e)

            from reporting.report_generator import ReportGenerator
            rg = ReportGenerator(self.p)
            html, j, txt = rg.generate_all()
            self.log.success(f"[EDRP] Reports: {html}")
        except Exception as e:
            get_handler().capture("pipeline_edrp", e, "_generate_reports")

    # ── Dashboard ─────────────────────────────────────────────────────
    def _start_dashboard(self):
        def _run():
            try:
                from web.server import run_dashboard
                run_dashboard(self.p, port=getattr(self.args,"port",8719))
            except Exception as e:
                get_handler().capture("pipeline_edrp", e, "dashboard")
        self._dashboard_thread = threading.Thread(target=_run, daemon=True)
        self._dashboard_thread.start()
        self.log.info(f"[EDRP] Dashboard: http://127.0.0.1:{getattr(self.args,'port',8719)}")
