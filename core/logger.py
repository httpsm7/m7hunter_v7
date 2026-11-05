#!/usr/bin/env python3
# core/logger.py — M7Hunter V7 Logger
# MilkyWay Intelligence | Author: Sharlix

import sys
from datetime import datetime

R    = "\033[91m"
B    = "\033[34m"
C    = "\033[96m"
Y    = "\033[93m"
G    = "\033[92m"
W    = "\033[97m"
DIM  = "\033[2m"
RST  = "\033[0m"
BOLD = "\033[1m"


class Logger:
    def __init__(self, no_color: bool = False):
        self.no_color       = no_color
        self._step_total    = 0
        self._step_current  = 0
        self._findings_count = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }

    def _ts(self) -> str:
        return f"{DIM}[{datetime.now().strftime('%H:%M:%S')}]{RST}"

    def set_steps(self, total: int):
        self._step_total   = total
        self._step_current = 0

    def step(self, name: str):
        self._step_current += 1
        bar = self._progress_bar(self._step_current, self._step_total)
        print(f"\n{B}{'━' * 70}{RST}")
        print(f"{B}  STEP [{self._step_current}/{self._step_total}]{RST}  "
              f"{BOLD}{W}{name}{RST}  {bar}")
        print(f"{B}{'━' * 70}{RST}\n")

    def _progress_bar(self, cur: int, tot: int) -> str:
        if not tot:
            return ""
        filled = int((cur / tot) * 24)
        bar    = f"{G}{'█' * filled}{DIM}{'░' * (24 - filled)}{RST}"
        pct    = int((cur / tot) * 100)
        return f"[{bar}] {G}{pct}%{RST}"

    def section(self, title: str):
        print(f"\n{B}{'═' * 70}{RST}")
        print(f"{B}  ▶  {W}{BOLD}{title}{RST}")
        print(f"{B}{'═' * 70}{RST}\n")

    def info(self, msg: str):
        print(f"{self._ts()} {C}[*]{RST} {msg}")

    def success(self, msg: str):
        print(f"{self._ts()} {G}[✓]{RST} {msg}")

    def warn(self, msg: str):
        print(f"{self._ts()} {Y}[!]{RST} {msg}")

    def error(self, msg: str):
        print(f"{self._ts()} {R}[✗]{RST} {msg}", file=sys.stderr)

    def debug(self, msg: str):
        print(f"{self._ts()} {DIM}[D] {msg}{RST}")

    def finding(self, severity: str, vuln_type: str, url: str, detail: str = ""):
        col_map = {
            "critical": f"{R}{BOLD}",
            "high"    : R,
            "medium"  : Y,
            "low"     : G,
            "info"    : C,
        }
        col = col_map.get(severity.lower(), W)
        sev = severity.upper().ljust(8)
        self._findings_count[severity.lower()] = \
            self._findings_count.get(severity.lower(), 0) + 1
        print(
            f"{self._ts()} {col}[{sev}]{RST} "
            f"{Y}{vuln_type}{RST} → "
            f"{W}{url[:70]}{RST} "
            f"{DIM}{detail[:60]}{RST}"
        )

    def pipeline_done(self, target: str, elapsed: float, report_path: str):
        fc    = self._findings_count
        total = sum(fc.values())
        print(f"""
{G}{'═' * 70}{RST}
{G}  ✅  PIPELINE COMPLETE — {target}{RST}
{G}  ⏱   Time     : {elapsed:.1f}s  ({elapsed / 60:.1f} min){RST}
{G}  🚨  Findings : {total} total  |  {R}CRIT:{fc.get('critical', 0)}{G}  HIGH:{fc.get('high', 0)}  {Y}MED:{fc.get('medium', 0)}{G}  LOW:{fc.get('low', 0)}{RST}
{G}  📊  Report   : {report_path}{RST}
{G}{'═' * 70}{RST}
""")
