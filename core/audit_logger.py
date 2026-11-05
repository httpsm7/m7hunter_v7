#!/usr/bin/env python3
# core/audit_logger.py — Structured Audit Logger
# MilkyWay Intelligence | Author: Sharlix

import os, json, time, uuid, threading

AUDIT_DIR = os.path.expanduser("~/.m7hunter/audit/")


class AuditLogger:
    def __init__(self, target: str):
        self.target   = target
        self.scan_id  = str(uuid.uuid4())[:12]
        self.start_ts = time.time()
        self._lock    = threading.Lock()
        os.makedirs(AUDIT_DIR, exist_ok=True)
        safe = (target.replace("https://", "").replace("http://", "")
                .split("/")[0][:20].replace(".", "_"))
        self.log_file = os.path.join(AUDIT_DIR, f"scan_{self.scan_id}_{safe}.jsonl")
        self._fh = open(self.log_file, "a")

    def _write(self, event: str, data: dict):
        entry = {
            "scan_id"  : self.scan_id,
            "event"    : event,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed"  : round(time.time() - self.start_ts, 2),
            "data"     : data,
        }
        with self._lock:
            self._fh.write(json.dumps(entry) + "\n")
            self._fh.flush()

    def start_scan(self):
        self._write("scan_start", {"target": self.target,
                                    "scan_id": self.scan_id, "version": "7.0"})

    def end_scan(self, total_findings: int, confirmed: int, elapsed: float):
        self._write("scan_end", {
            "total_findings": total_findings,
            "confirmed"     : confirmed,
            "elapsed_sec"   : round(elapsed, 1),
        })
        try:
            self._fh.close()
        except Exception:
            pass

    def log_step_start(self, step: str):
        self._write("step_start", {"step": step})

    def log_step_end(self, step: str, status: str, error: str = ""):
        self._write("step_end", {"step": step, "status": status, "error": error})

    def log_finding(self, finding: dict):
        self._write("finding", {
            "type"    : finding.get("type"),
            "severity": finding.get("severity"),
            "url"     : finding.get("url", "")[:100],
            "status"  : finding.get("status"),
        })

    def log_fp_caught(self, vuln_type: str, url: str, reasons: list):
        self._write("fp_caught", {
            "vuln_type": vuln_type,
            "url"      : url[:100],
            "reasons"  : reasons[:3],
        })

    def log_command(self, cmd: str, tool: str = ""):
        import hashlib
        self._write("command", {
            "tool"    : tool,
            "cmd_hash": hashlib.md5(cmd.encode()).hexdigest()[:8],
        })
