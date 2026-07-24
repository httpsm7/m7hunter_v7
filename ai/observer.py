#!/usr/bin/env python3
# ai/observer.py — Session Intelligence Observer
# MilkyWay Intelligence | Author: Sharlix

import os, json, time, threading, hashlib
from datetime import datetime

SESSIONS_DB = os.path.expanduser("~/.m7hunter/sessions/")


class M7Observer:
    def __init__(self, pipeline=None):
        self.pipeline   = pipeline
        self.session_id = hashlib.md5(
            f"{time.time()}{os.getpid()}".encode()
        ).hexdigest()[:12]
        self.session_data = {
            "session_id" : self.session_id,
            "timestamp"  : datetime.now().isoformat(),
            "target"     : getattr(pipeline, "target", "unknown") if pipeline else "unknown",
            "version"    : "7.0",
            "steps"      : {},
            "findings"   : [],
            "tool_health": {},
            "timing"     : {"start": time.time(), "end": None, "total_sec": None},
        }
        self._lock = threading.Lock()
        os.makedirs(SESSIONS_DB, exist_ok=True)

    def step_start(self, name: str):
        with self._lock:
            self.session_data["steps"][name] = {
                "name": name, "start_time": time.time(),
                "end_time": None, "duration_ms": None,
                "status": "running", "output_count": 0,
            }

    def step_end(self, name: str, status: str = "success",
                  output_count: int = 0, error: str = None):
        with self._lock:
            step = self.session_data["steps"].get(name)
            if not step:
                return
            end = time.time()
            step.update({
                "end_time"    : end,
                "duration_ms" : int((end - step["start_time"]) * 1000),
                "status"      : status,
                "output_count": output_count,
            })
            if error:
                step["error"] = error

    def record_finding(self, severity: str, vuln_type: str, url: str,
                        detail: str, tool: str):
        with self._lock:
            self.session_data["findings"].append({
                "severity" : severity,
                "vuln_type": vuln_type,
                "url"      : url,
                "detail"   : detail,
                "tool"     : tool,
                "timestamp": datetime.now().isoformat(),
            })

    def save_session(self) -> str:
        self.session_data["timing"]["end"] = time.time()
        self.session_data["timing"]["total_sec"] = round(
            self.session_data["timing"]["end"] - self.session_data["timing"]["start"], 1
        )
        path = os.path.join(SESSIONS_DB, f"session_{self.session_id}.json")
        with open(path, "w") as f:
            json.dump(self.session_data, f, indent=2)
        return path
