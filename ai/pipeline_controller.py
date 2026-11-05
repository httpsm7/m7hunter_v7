#!/usr/bin/env python3
# ai/pipeline_controller.py — M7 Pipeline Controller v6 (FIXED)
# FIX: after_step now receives output_file from pipeline — no more 0-line false warnings
# FIX: _validate_output uses actual file content not None
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import time
from ai.tool_knowledge import ToolCommandEngine, TOOL_KB
from ai.pattern_engine import PatternEngine, CRITICAL_STEPS
from core.utils import count_lines

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"
W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


class PipelineController:
    def __init__(self, pipeline, log=None):
        self.pipeline       = pipeline
        self.log            = log or pipeline.log
        self.cmd_engine     = ToolCommandEngine(log)
        self.pattern_engine = PatternEngine()
        self._step_registry = {}

    def before_step(self, step_name: str) -> dict:
        result = {"proceed": True, "warnings": [], "input_fixed": False}
        self._step_registry[step_name] = {
            "start"       : time.time(),
            "end"         : None,
            "output_count": 0,
            "issues"      : [],
        }
        warnings = self._check_dependencies(step_name)
        result["warnings"] = warnings
        fixed = self._fix_input_format(step_name)
        result["input_fixed"] = fixed
        if warnings:
            for w in warnings:
                self.log.warn(f"[CEO] {w}")
        return result

    def after_step(self, step_name: str, output_file: str = None) -> dict:
        """
        FIX: output_file is now passed from pipeline (was always None before).
        This means line counts are now accurate instead of always showing 0.
        """
        reg    = self._step_registry.get(step_name, {})
        result = {"output_count": 0, "issues": [], "suggestions": []}

        # FIX: Use the passed output_file parameter
        if output_file and os.path.isfile(output_file):
            count = count_lines(output_file)
            result["output_count"] = count
            reg["output_count"]    = count
        elif not output_file:
            # Step doesn't have a single output file (e.g. screenshot, wpscan)
            # Don't warn about 0 lines
            reg["output_count"] = -1  # sentinel: no file to check

        reg["end"] = time.time()

        # FIX: Only validate if we have a real output file
        if output_file and result["output_count"] >= 0:
            issues = self._validate_output(step_name, result["output_count"])
            result["issues"] = issues
            reg["issues"]    = issues
            if issues:
                for issue in issues:
                    self.log.warn(f"[CEO] {issue}")
                    result["suggestions"].append(
                        self._get_fix_suggestion(step_name, issue))

        return result

    def validate_and_fix_command(self, tool: str, command: str) -> tuple:
        is_valid, issue, fixed = self.cmd_engine.validate_command(tool, command)
        if not is_valid:
            self.log.warn(f"[CEO] Command issue for {tool}: {issue}")
            self.log.info(f"[CEO] Auto-fixed: {fixed[:100]}")
            self.pattern_engine.record_fix_worked("command_fix", tool, command, fixed)
            return fixed, True, issue
        return command, False, ""

    def get_correct_command(self, tool: str, mode: str = "default", **kwargs) -> str:
        cmd = self.cmd_engine.get_command(tool, mode, **kwargs)
        if not cmd:
            self.log.warn(f"[CEO] Unknown tool: {tool}")
        return cmd

    def _fix_input_format(self, step_name: str) -> bool:
        p = self.pipeline
        f = p.files
        fixed = False

        FORMAT_RULES = {
            "dns"       : {"source": f.get("subdomains"),  "dest": f.get("fmt_domain"), "format": "domain"},
            "probe"     : {"source": f.get("resolved") or f.get("subdomains"), "dest": f.get("fmt_host"), "format": "host"},
            "ports"     : {"source": f.get("resolved") or f.get("subdomains"), "dest": f.get("fmt_host"), "format": "host"},
            "crawl"     : {"source": f.get("live_hosts"),  "dest": f.get("fmt_url"),    "format": "url"},
            "nuclei"    : {"source": f.get("live_hosts"),  "dest": f.get("fmt_url"),    "format": "url"},
            "xss"       : {"source": f.get("live_hosts"),  "dest": f.get("fmt_url"),    "format": "url"},
            "screenshot": {"source": f.get("live_hosts"),  "dest": f.get("fmt_url"),    "format": "url"},
            "takeover"  : {"source": f.get("subdomains"),  "dest": f.get("fmt_domain"), "format": "domain"},
            "csrf"      : {"source": f.get("live_hosts"),  "dest": f.get("fmt_url"),    "format": "url"},
            "race"      : {"source": f.get("live_hosts"),  "dest": f.get("fmt_url"),    "format": "url"},
            "nosql"     : {"source": f.get("live_hosts"),  "dest": f.get("fmt_url"),    "format": "url"},
        }

        if step_name in FORMAT_RULES:
            rule   = FORMAT_RULES[step_name]
            source = rule.get("source")
            dest   = rule.get("dest")
            fmt    = rule.get("format")

            if source and dest and fmt and os.path.isfile(source):
                from core.utils import FormatFixer
                n = FormatFixer.fix(source, dest, fmt)
                if n > 0:
                    fixed = True
                    self.log.info(f"[CEO] Format fixed for {step_name}: {n} entries → {fmt} format")

        return fixed

    def _check_dependencies(self, step_name: str) -> list:
        p = self.pipeline
        f = p.files
        warnings = []

        DEPS = {
            "dns"       : [("subdomains", f.get("subdomains"))],
            "probe"     : [("resolved",   f.get("resolved"))],
            "ports"     : [("resolved",   f.get("resolved"))],
            "crawl"     : [("live_hosts", f.get("live_hosts"))],
            "nuclei"    : [("live_hosts", f.get("live_hosts"))],
            "xss"       : [("live_hosts", f.get("live_hosts"))],
            "sqli"      : [("urls",       f.get("urls"))],
            "ssrf"      : [("urls",       f.get("urls"))],
            "takeover"  : [("subdomains", f.get("subdomains"))],
            "csrf"      : [("live_hosts", f.get("live_hosts"))],
            "race"      : [("live_hosts", f.get("live_hosts"))],
            "nosql"     : [("live_hosts", f.get("live_hosts"))],
        }

        if step_name in DEPS:
            for dep_name, dep_file in DEPS[step_name]:
                if dep_file and not os.path.isfile(dep_file):
                    warnings.append(
                        f"Step '{step_name}' depends on '{dep_name}' "
                        f"but file not found: {dep_file}")
                elif dep_file and os.path.isfile(dep_file):
                    n = count_lines(dep_file)
                    if n == 0:
                        warnings.append(
                            f"Step '{step_name}': dependency '{dep_name}' is empty")

        return warnings

    def _validate_output(self, step_name: str, output_count: int) -> list:
        """
        FIX: Minimum thresholds only for steps that must produce output.
        Steps that legitimately find nothing (no vulns) don't get warned.
        """
        issues = []

        # Only warn for recon steps that MUST produce output if target exists
        MUST_PRODUCE = {
            "subdomain": 1,
            "dns"      : 1,
            "probe"    : 1,
        }

        if step_name in MUST_PRODUCE and output_count < MUST_PRODUCE[step_name]:
            issues.append(
                f"Step '{step_name}' produced {output_count} lines "
                f"(expected at least {MUST_PRODUCE[step_name]}) — "
                f"check tool installation")

        return issues

    def _get_fix_suggestion(self, step_name: str, issue: str) -> str:
        SUGGESTIONS = {
            "subdomain": "subfinder -d target.com -silent | head -5 (test manually)",
            "dns"      : "dnsx -version && dnsx -l subdomains.txt -silent | head -5",
            "probe"    : "httpx -version && httpx -l resolved.txt -silent | head -5",
        }
        return SUGGESTIONS.get(step_name, f"Check {step_name} step configuration")

    def check_for_missed_critical_steps(self, steps_completed: list) -> list:
        missed = []
        for step in CRITICAL_STEPS:
            if step not in steps_completed:
                missed.append({
                    "step"      : step,
                    "reason"    : "Critical step not in pipeline",
                    "suggestion": f"Add --{step} flag or use --deep mode",
                })
        return missed

    def get_step_summary(self) -> dict:
        summary = {}
        for step, data in self._step_registry.items():
            elapsed = None
            if data.get("start") and data.get("end"):
                elapsed = round(data["end"] - data["start"], 1)
            summary[step] = {
                "elapsed_sec" : elapsed,
                "output_count": data.get("output_count", 0),
                "issues"      : data.get("issues", []),
            }
        return summary

    def what_does_tool_need(self, tool: str) -> str:
        return self.cmd_engine.get_input_format(tool)

    def how_to_run(self, tool: str, mode: str = "default", **kwargs) -> str:
        return self.cmd_engine.get_command(tool, mode, **kwargs)

    def fix_broken_command(self, tool: str, broken_cmd: str) -> str:
        fixed, was_fixed, issue = self.validate_and_fix_command(tool, broken_cmd)
        return fixed

    def full_tool_health_check(self) -> dict:
        results = {}
        for tool in self.cmd_engine.list_all_tools():
            results[tool] = self.cmd_engine.check_tool(tool)
        return results
