#!/usr/bin/env python3
# ai/memory_store.py — AI Decision Memory Store
# Blueprint 5.5: Persist AI decisions for cross-finding correlation
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import json, time, threading, os
from pathlib import Path
from core.error_handler import get_handler

MEMORY_DIR = Path.home() / ".m7hunter" / "ai_memory"

class MemoryStore:
    """
    Blueprint 5.5: AI memory for decision persistence.

    Stores:
    - AI verification decisions
    - Risk scores per finding
    - Correlation results
    - Session context

    Used for:
    - Avoiding re-analysis of same findings
    - Cross-scan pattern learning
    - Reducing AI calls (cache hit)
    """

    def __init__(self, scan_id: str = "default", persist: bool = True):
        self.scan_id  = scan_id
        self.persist  = persist
        self._lock    = threading.Lock()
        self._memory  : dict[str, dict] = {}
        self._decisions: list[dict]     = []
        self._session_context: dict     = {}
        if persist:
            MEMORY_DIR.mkdir(parents=True, exist_ok=True)
            self._load()

    def store_decision(self, role: str, finding: dict, result: dict):
        """Store an AI decision for a finding."""
        key = self._make_key(finding)
        entry = {
            "key"       : key,
            "role"      : role,
            "vuln_type" : finding.get("vuln_type", ""),
            "url"       : finding.get("url", ""),
            "result"    : result,
            "timestamp" : time.time(),
            "scan_id"   : self.scan_id,
        }
        with self._lock:
            self._memory[key]  = entry
            self._decisions.append(entry)
        if self.persist:
            self._save()

    def get_decision(self, finding: dict) -> dict | None:
        """Retrieve cached AI decision — avoid re-analysis."""
        key = self._make_key(finding)
        with self._lock:
            return self._memory.get(key)

    def has_decision(self, finding: dict) -> bool:
        return self._make_key(finding) in self._memory

    def store_context(self, key: str, value):
        """Store session-level context (e.g. target tech stack, WAF type)."""
        with self._lock:
            self._session_context[key] = {
                "value": value,
                "timestamp": time.time()
            }

    def get_context(self, key: str, default=None):
        with self._lock:
            entry = self._session_context.get(key)
            return entry["value"] if entry else default

    def get_all_decisions(self) -> list:
        with self._lock:
            return list(self._decisions)

    def get_confirmed_findings(self) -> list:
        with self._lock:
            return [
                d for d in self._decisions
                if d.get("result", {}).get("verdict") == "confirmed"
            ]

    def get_false_positives(self) -> list:
        with self._lock:
            return [
                d for d in self._decisions
                if d.get("result", {}).get("verdict") == "false_positive"
            ]

    def cache_hit_rate(self) -> float:
        total = len(self._decisions)
        if not total:
            return 0.0
        hits = sum(1 for d in self._decisions if "cached" in d.get("result",{}).get("_meta",""))
        return round(hits / total, 3)

    def summary(self) -> dict:
        confirmed = len(self.get_confirmed_findings())
        fp        = len(self.get_false_positives())
        total     = len(self._decisions)
        return {
            "total_decisions": total,
            "confirmed"      : confirmed,
            "false_positives": fp,
            "needs_review"   : total - confirmed - fp,
            "cache_hit_rate" : self.cache_hit_rate(),
        }

    def clear_session(self):
        with self._lock:
            self._memory.clear()
            self._decisions.clear()
            self._session_context.clear()

    @staticmethod
    def _make_key(finding: dict) -> str:
        import hashlib
        raw = f"{finding.get('vuln_type','')}{finding.get('url','')}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def _path(self) -> Path:
        return MEMORY_DIR / f"{self.scan_id}_memory.json"

    def _save(self):
        try:
            data = {
                "scan_id"        : self.scan_id,
                "memory"         : self._memory,
                "session_context": self._session_context,
                "saved_at"       : time.time(),
            }
            self._path().write_text(json.dumps(data, indent=2))
        except Exception as e:
            get_handler().capture("memory_store", e, "_save")

    def _load(self):
        try:
            p = self._path()
            if p.exists():
                data = json.loads(p.read_text())
                self._memory          = data.get("memory", {})
                self._session_context = data.get("session_context", {})
                self._decisions = list(self._memory.values())
        except Exception as e:
            get_handler().capture("memory_store", e, "_load")

