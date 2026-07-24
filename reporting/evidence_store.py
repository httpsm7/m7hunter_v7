#!/usr/bin/env python3
# reporting/evidence_store.py — Evidence Storage for Report Drill-Down
# Blueprint Phase 8: Screenshots, request/response pairs, reproduction steps
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import os, json, hashlib, time, base64
from pathlib import Path
from core.error_handler import get_handler

class EvidenceStore:
    """
    Blueprint Phase 8: Evidence-driven reporting.
    Stores per-finding evidence: screenshots, raw HTTP, reproduction steps.
    Each finding gets a unique evidence_id linked to the finding record.
    """

    def __init__(self, out_dir: str, scan_id: str):
        self.base     = Path(out_dir) / "evidence" / scan_id
        self.base.mkdir(parents=True, exist_ok=True)
        self._index   = {}        # evidence_id → metadata
        self._index_path = self.base / "index.json"
        self._load_index()

    # ── Core API ──────────────────────────────────────────────────────
    def store(self, finding: dict,
              screenshot_path: str = None,
              request_raw: str = None,
              response_raw: str = None,
              extra_files: dict = None) -> str:
        """
        Store evidence for a finding. Returns evidence_id.
        All evidence linked to finding by evidence_id.
        """
        evidence_id = self._make_id(finding)
        ev_dir      = self.base / evidence_id
        ev_dir.mkdir(exist_ok=True)

        meta = {
            "evidence_id"  : evidence_id,
            "vuln_type"    : finding.get("vuln_type", ""),
            "url"          : finding.get("url", ""),
            "severity"     : finding.get("severity", ""),
            "confidence"   : finding.get("confidence", 0),
            "timestamp"    : time.time(),
            "files"        : {},
            "reproduction" : self._build_reproduction(finding),
        }

        # Screenshot
        if screenshot_path and os.path.isfile(screenshot_path):
            dest = ev_dir / "screenshot.png"
            try:
                import shutil
                shutil.copy2(screenshot_path, dest)
                meta["files"]["screenshot"] = str(dest.relative_to(self.base))
            except Exception as e:
                get_handler().capture("evidence_store", e, "store_screenshot")

        # Raw HTTP request
        if request_raw:
            req_file = ev_dir / "request.txt"
            try:
                req_file.write_text(request_raw, encoding="utf-8")
                meta["files"]["request"] = str(req_file.relative_to(self.base))
            except Exception as e:
                get_handler().capture("evidence_store", e, "store_request")

        # Raw HTTP response
        if response_raw:
            resp_file = ev_dir / "response.txt"
            try:
                resp_file.write_text(response_raw[:50000], encoding="utf-8")
                meta["files"]["response"] = str(resp_file.relative_to(self.base))
            except Exception as e:
                get_handler().capture("evidence_store", e, "store_response")

        # Extra files (payloads, logs, etc.)
        for name, content in (extra_files or {}).items():
            try:
                xf = ev_dir / name
                if isinstance(content, bytes):
                    xf.write_bytes(content)
                else:
                    xf.write_text(str(content), encoding="utf-8")
                meta["files"][name] = str(xf.relative_to(self.base))
            except Exception as e:
                get_handler().capture("evidence_store", e, f"store_extra:{name}")

        self._index[evidence_id] = meta
        self._save_index()
        return evidence_id

    def get(self, evidence_id: str) -> dict | None:
        return self._index.get(evidence_id)

    def get_all(self) -> list:
        return list(self._index.values())

    def get_screenshot_b64(self, evidence_id: str) -> str | None:
        """Return screenshot as base64 for HTML embedding."""
        meta = self._index.get(evidence_id)
        if not meta:
            return None
        ss = meta["files"].get("screenshot")
        if not ss:
            return None
        path = self.base / ss
        if not path.exists():
            return None
        try:
            data = path.read_bytes()
            return base64.b64encode(data).decode()
        except Exception as e:
            get_handler().capture("evidence_store", e, "get_screenshot_b64")
            return None

    def get_request(self, evidence_id: str) -> str:
        return self._read_file(evidence_id, "request")

    def get_response(self, evidence_id: str) -> str:
        return self._read_file(evidence_id, "response")

    # ── Reproduction steps ────────────────────────────────────────────
    def _build_reproduction(self, finding: dict) -> list[str]:
        """Auto-generate reproduction steps from finding data."""
        steps = []
        url     = finding.get("url", "")
        payload = finding.get("payload", "")
        vtype   = finding.get("vuln_type", "").upper()
        tool    = finding.get("tool", "")

        steps.append(f"1. Open browser or terminal")
        steps.append(f"2. Navigate to: {url}")

        if payload:
            steps.append(f"3. Inject payload: {payload[:200]}")

        if "XSS" in vtype:
            steps.append(f"4. Observe JavaScript execution in browser console")
        elif "SQLI" in vtype:
            steps.append(f"4. Observe database error or delayed response")
        elif "SSRF" in vtype:
            steps.append(f"4. Check OOB callback server for DNS/HTTP hit")
        elif "IDOR" in vtype:
            steps.append(f"4. Observe unauthorized data in response")
        elif "LFI" in vtype:
            steps.append(f"4. Observe file content in response body")
        elif "SSTI" in vtype:
            steps.append(f"4. Observe evaluated expression result (e.g. 49 for 7*7)")

        steps.append(f"5. Tool used: {tool or 'm7hunter'}")

        # curl PoC
        if url:
            curl = f"curl -sk \"{url}\""
            if payload:
                curl += f" --data \"{payload[:100]}\""
            steps.append(f"PoC: {curl}")

        return steps

    # ── Summary for report ────────────────────────────────────────────
    def summary_table(self) -> list[dict]:
        """Return evidence summary for HTML report table."""
        rows = []
        for ev_id, meta in self._index.items():
            rows.append({
                "evidence_id": ev_id,
                "vuln_type"  : meta.get("vuln_type",""),
                "severity"   : meta.get("severity",""),
                "confidence" : meta.get("confidence",0),
                "has_screenshot": "screenshot" in meta.get("files",{}),
                "has_request"   : "request"    in meta.get("files",{}),
                "has_response"  : "response"   in meta.get("files",{}),
                "repro_steps"   : len(meta.get("reproduction",[])),
            })
        return sorted(rows, key=lambda r: r["confidence"], reverse=True)

    # ── Internal ──────────────────────────────────────────────────────
    def _make_id(self, finding: dict) -> str:
        key = f"{finding.get('vuln_type','')}{finding.get('url','')}{time.time()}"
        return hashlib.sha256(key.encode()).hexdigest()[:12]

    def _read_file(self, evidence_id: str, key: str) -> str:
        meta = self._index.get(evidence_id)
        if not meta:
            return ""
        fp = meta["files"].get(key)
        if not fp:
            return ""
        path = self.base / fp
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _load_index(self):
        try:
            if self._index_path.exists():
                self._index = json.loads(self._index_path.read_text())
        except Exception as e:
            get_handler().capture("evidence_store", e, "_load_index")

    def _save_index(self):
        try:
            self._index_path.write_text(
                json.dumps(self._index, indent=2), encoding="utf-8"
            )
        except Exception as e:
            get_handler().capture("evidence_store", e, "_save_index")
