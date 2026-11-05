#!/usr/bin/env python3
# ai/ai_trainer.py — M7Hunter AI Training System
# Persistent learning from confirmed/denied findings + book knowledge
# Builds training data, extracts patterns, feeds Ollama context
# AI-Cycle 1 — MilkyWay Intelligence | Author: Sharlix + M7AI

import os, json, time, re, hashlib
from pathlib import Path
from typing import Dict, List, Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
M7_AI_DIR       = Path.home() / ".m7hunter" / "ai"
TRAINING_FILE   = M7_AI_DIR / "training_data.jsonl"
PATTERNS_FILE   = M7_AI_DIR / "learned_patterns.json"
STATS_FILE      = M7_AI_DIR / "training_stats.json"
FEEDBACK_FILE   = M7_AI_DIR / "feedback.jsonl"

# ── Book-extracted knowledge base (from all 11 books) ────────────────────────
BOOK_KNOWLEDGE = {
    # From Bug Bounty Bootcamp (Vickie Li)
    "XSS": {
        "confirmed_indicators": [
            "payload reflects UNENCODED in HTML context",
            "<svg/onload= appears in response body",
            "onerror=alert appears unencoded",
            "JavaScript executes in browser context",
            "alert(1) box appears",
            "DOM sink receives user input without sanitization",
        ],
        "fp_indicators": [
            "payload encoded as &lt; &gt; &amp;",
            "response contains \\u003c (unicode encoding)",
            "WAF returned 403 with payload",
            "payload in comment <!-- -->",
            "response is application/json not text/html",
            "CSP header blocks inline scripts",
        ],
        "source": "Bug Bounty Bootcamp Ch6 + XSS Payloads Book",
    },
    "SQLI": {
        "confirmed_indicators": [
            "You have an error in your SQL syntax",
            "ORA- Oracle error code",
            "pg_query() failed PostgreSQL",
            "SQLSTATE appears in response",
            "time delay measurable (>5s for SLEEP)",
            "boolean condition changes response length",
            "union select returns extra column data",
        ],
        "fp_indicators": [
            "generic error page (not DB-specific)",
            "WAF returns 403/406",
            "input validation message: please enter valid",
            "response identical with true/false conditions",
        ],
        "source": "Bug Bounty Bootcamp Ch9 + CEH Ch14",
    },
    "SSRF": {
        "confirmed_indicators": [
            "ami-id appears in response (AWS metadata)",
            "AccessKeyId appears (AWS credentials)",
            "computeMetadata appears (GCP)",
            "service-accounts appears (GCP)",
            "169.254.169.254 responds with metadata",
            "internal IP appears in response",
            "docker API responds at :2375",
            "redis version string in response",
        ],
        "fp_indicators": [
            "connection refused returned",
            "network unreachable returned",
            "timeout on connection",
            "DNS resolution failed",
            "WAF blocked request",
        ],
        "source": "Bug Bounty Bootcamp Ch13",
    },
    "SSTI": {
        "confirmed_indicators": [
            "7*7=49 evaluated (math expression worked)",
            "7777777 in response (multiplication evaluated)",
            "uid= gid= appears (RCE via os.popen)",
            "template error with engine name (Jinja2/Twig/etc)",
            "__class__ appears in error",
            "FreeMarker error with template context",
        ],
        "fp_indicators": [
            "literal {{ }} returned without evaluation",
            "7*7 returned as string not 49",
            "template syntax in error message only",
        ],
        "source": "Bug Bounty Bootcamp Ch16",
    },
    "IDOR": {
        "confirmed_indicators": [
            "different user data returned for same endpoint",
            "email of another user appears in response",
            "account details differ between sessions",
            "private files of another user accessible",
            "admin data returned to regular user",
        ],
        "fp_indicators": [
            "same data returned regardless of ID",
            "error 403 forbidden on other IDs",
            "empty response on ID change",
        ],
        "source": "Bug Bounty Bootcamp Ch10",
    },
    "JWT": {
        "confirmed_indicators": [
            "alg:none accepted by server",
            "same endpoint returns 200 with forged token",
            "weak secret cracked (token signature verified)",
            "RS256 confusion: HS256 with public key accepted",
        ],
        "fp_indicators": [
            "401 returned for modified token",
            "server returns invalid token error",
            "token rejected with clear error",
        ],
        "source": "Bug Bounty Bootcamp Ch18",
    },
    "LFI": {
        "confirmed_indicators": [
            "root:x:0:0:root appears (/etc/passwd leak)",
            "daemon:x:1:1 appears in response",
            "BEGIN RSA PRIVATE KEY in response",
            "PHP source code appears",
            "Windows SYSTEM32 path in response",
            "[boot loader] appears (boot.ini)",
        ],
        "fp_indicators": [
            "file not found error",
            "access denied / permission denied",
            "generic 404 page",
        ],
        "source": "Kali Linux PWK + Bug Bounty Bootcamp",
    },
    "RCE": {
        "confirmed_indicators": [
            "uid=0(root) gid=0(root) appears",
            "uid=33(www-data) appears",
            "command output with expected format",
            "/bin/bash: appears",
            "whoami output in response",
        ],
        "fp_indicators": [
            "command literally in response (not executed)",
            "generic error page",
        ],
        "source": "Kali Linux PWK + CEH",
    },
    "XXE": {
        "confirmed_indicators": [
            "root:x:0:0 in response (file disclosure)",
            "internal IP in response (SSRF via XXE)",
            "XML parsing error with entity reference",
            "DOCTYPE processed by parser",
        ],
        "fp_indicators": [
            "XML entity disallowed error",
            "DOCTYPE not processed",
            "generic parse error",
        ],
        "source": "Bug Bounty Bootcamp Ch11",
    },
    "NOSQL": {
        "confirmed_indicators": [
            "authentication bypassed (logged in as admin)",
            "role:admin in response",
            "isAdmin:true in response",
            "all user records returned (no filter)",
            "5s+ delay with $where sleep injection",
        ],
        "fp_indicators": [
            "operator syntax error returned",
            "invalid query format error",
            "generic 400 error",
        ],
        "source": "Bug Bounty Bootcamp Ch19",
    },
}

# ── Vuln-type scoring weights ─────────────────────────────────────────────────
SEVERITY_CONFIDENCE_MAP = {
    # (min_confidence, severity_if_confirmed)
    "XSS":   (0.75, "high"),
    "SQLI":  (0.80, "critical"),
    "SSRF":  (0.85, "critical"),
    "SSTI":  (0.90, "critical"),
    "RCE":   (0.95, "critical"),
    "IDOR":  (0.70, "high"),
    "LFI":   (0.80, "high"),
    "JWT":   (0.85, "critical"),
    "XXE":   (0.80, "high"),
    "NOSQL": (0.80, "critical"),
}


class AITrainer:
    """
    M7Hunter AI Training System.
    Manages:
    - Training data from confirmed/denied findings
    - Book knowledge extraction
    - Pattern learning from scan results
    - Ollama context building
    - Feedback loop from manual review
    """

    def __init__(self, log=None):
        self.log    = log
        self._stats = self._load_stats()
        M7_AI_DIR.mkdir(parents=True, exist_ok=True)

    # ── Record finding outcome ─────────────────────────────────────────────────
    def record_finding(self, vuln_type: str, url: str, payload: str,
                        response: str, outcome: str,
                        confidence: float = 0.0, notes: str = ""):
        """
        Record a finding outcome for training.
        outcome: 'true_positive' | 'false_positive' | 'potential'
        """
        entry = {
            "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
            "vuln_type":  vuln_type.upper(),
            "url":        url[:200],
            "payload":    payload[:200],
            "response":   response[:500],
            "outcome":    outcome,
            "confidence": confidence,
            "notes":      notes[:200],
            "id":         hashlib.md5(f"{vuln_type}{url}{payload}".encode()).hexdigest()[:8],
        }
        with open(TRAINING_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self._update_stats(outcome, vuln_type)

        # Update learned patterns
        if outcome == "false_positive":
            self._learn_fp_pattern(vuln_type, response)
        elif outcome == "true_positive":
            self._learn_confirmed_pattern(vuln_type, response)

    # ── Learn FP pattern ──────────────────────────────────────────────────────
    def _learn_fp_pattern(self, vuln_type: str, response: str):
        patterns = self._load_patterns()
        vt       = vuln_type.upper()

        # Extract distinctive phrases from FP response
        phrases = self._extract_distinctive_phrases(response)
        if not phrases:
            return

        if vt not in patterns.get("fp_patterns",{}):
            patterns.setdefault("fp_patterns",{})[vt] = []

        for phrase in phrases[:3]:
            if phrase not in patterns["fp_patterns"][vt]:
                patterns["fp_patterns"][vt].append(phrase)
                if self.log:
                    self.log.info(f"  [AI Train] Learned FP pattern: '{phrase}' for {vt}")

        self._save_patterns(patterns)

    # ── Learn confirmed pattern ────────────────────────────────────────────────
    def _learn_confirmed_pattern(self, vuln_type: str, response: str):
        patterns = self._load_patterns()
        vt       = vuln_type.upper()

        phrases = self._extract_distinctive_phrases(response)
        if not phrases:
            return

        if vt not in patterns.get("confirmed_patterns",{}):
            patterns.setdefault("confirmed_patterns",{})[vt] = []

        for phrase in phrases[:3]:
            if phrase not in patterns["confirmed_patterns"][vt]:
                patterns["confirmed_patterns"][vt].append(phrase)

        self._save_patterns(patterns)

    # ── Build Ollama context ───────────────────────────────────────────────────
    def build_ollama_context(self, vuln_type: str) -> str:
        """
        Build rich context for Ollama based on:
        1. Book knowledge for this vuln type
        2. Learned patterns from past scans
        """
        vt      = vuln_type.upper().split("_")[0]
        book_kn = BOOK_KNOWLEDGE.get(vt, {})
        patterns= self._load_patterns()

        ctx = f"=== {vt} Analysis Context ===\n\n"

        if book_kn:
            ctx += f"Source: {book_kn.get('source','')}\n\n"
            ctx += "CONFIRMED indicators:\n"
            for ind in book_kn.get("confirmed_indicators",[]):
                ctx += f"  ✓ {ind}\n"
            ctx += "\nFALSE POSITIVE indicators:\n"
            for ind in book_kn.get("fp_indicators",[]):
                ctx += f"  ✗ {ind}\n"

        # Add learned patterns
        learned_fp = patterns.get("fp_patterns",{}).get(vt,[])
        learned_ok = patterns.get("confirmed_patterns",{}).get(vt,[])

        if learned_fp:
            ctx += f"\nLearned FP patterns (from {len(learned_fp)} past scans):\n"
            for p in learned_fp[:5]:
                ctx += f"  ✗ {p}\n"

        if learned_ok:
            ctx += f"\nLearned confirmed patterns:\n"
            for p in learned_ok[:5]:
                ctx += f"  ✓ {p}\n"

        # Add training stats
        stats     = self._stats
        vt_stats  = stats.get("by_type",{}).get(vt,{})
        tp        = vt_stats.get("true_positive",0)
        fp        = vt_stats.get("false_positive",0)
        total     = tp + fp
        if total > 0:
            accuracy = f"{tp/(total)*100:.0f}%"
            ctx += f"\nHistorical: {tp} TP / {fp} FP ({accuracy} accuracy)\n"

        return ctx

    # ── Get confidence adjustment ─────────────────────────────────────────────
    def get_confidence_adjustment(self, vuln_type: str,
                                   response: str) -> float:
        """
        Adjust confidence based on learned patterns.
        Returns: adjustment in range [-0.3, +0.3]
        """
        vt       = vuln_type.upper().split("_")[0]
        patterns = self._load_patterns()
        adjust   = 0.0

        # Check learned FP patterns
        fp_patterns = patterns.get("fp_patterns",{}).get(vt,[])
        for pat in fp_patterns:
            if pat.lower() in response.lower():
                adjust -= 0.15
                break

        # Check learned confirmed patterns
        ok_patterns = patterns.get("confirmed_patterns",{}).get(vt,[])
        for pat in ok_patterns:
            if pat.lower() in response.lower():
                adjust += 0.10
                break

        # Apply book knowledge
        book_kn = BOOK_KNOWLEDGE.get(vt, {})
        for ind in book_kn.get("confirmed_indicators",[]):
            if any(word.lower() in response.lower()
                   for word in ind.split()[:3] if len(word)>3):
                adjust += 0.05
                break

        for ind in book_kn.get("fp_indicators",[]):
            if any(word.lower() in response.lower()
                   for word in ind.split()[:3] if len(word)>3):
                adjust -= 0.05
                break

        return max(-0.30, min(0.30, adjust))

    # ── Export training data for Ollama fine-tuning ───────────────────────────
    def export_for_ollama(self) -> str:
        """Export training data as Ollama-compatible JSONL for fine-tuning."""
        if not TRAINING_FILE.exists():
            return ""

        export_path = M7_AI_DIR / "ollama_finetune.jsonl"
        exported    = 0

        with open(export_path, "w") as out:
            with open(TRAINING_FILE) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        vt    = entry.get("vuln_type","")
                        ctx   = self.build_ollama_context(vt)

                        # Build conversation pair
                        pair = {
                            "messages": [
                                {"role": "system",
                                 "content": f"You are M7Hunter AI security analyst.\n{ctx}"},
                                {"role": "user",
                                 "content": (f"Analyze: vuln={vt} "
                                             f"payload={entry.get('payload','')} "
                                             f"response={entry.get('response','')[:300]}")},
                                {"role": "assistant",
                                 "content": json.dumps({
                                     "verdict":    entry.get("outcome","potential"),
                                     "confidence": entry.get("confidence",0.5),
                                     "reason":     entry.get("notes",""),
                                     "severity":   SEVERITY_CONFIDENCE_MAP.get(vt,("",None))[1] or "medium",
                                 })},
                            ]
                        }
                        out.write(json.dumps(pair) + "\n")
                        exported += 1
                    except Exception:
                        pass

        return str(export_path) if exported > 0 else ""

    # ── Training summary ──────────────────────────────────────────────────────
    def get_summary(self) -> str:
        stats = self._stats
        total = stats.get("total_findings",0)
        tp    = stats.get("true_positives",0)
        fp    = stats.get("false_positives",0)
        acc   = f"{tp/(tp+fp)*100:.0f}%" if (tp+fp) > 0 else "N/A"

        return (f"AI Training: {total} findings recorded | "
                f"TP:{tp} FP:{fp} | Accuracy:{acc} | "
                f"Patterns: {self._count_patterns()} learned")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _extract_distinctive_phrases(self, text: str) -> List[str]:
        if not text: return []
        # Extract 3-6 word distinctive phrases
        words  = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())
        unique = list(dict.fromkeys(words))[:10]
        return unique[:5]

    def _load_patterns(self) -> dict:
        if PATTERNS_FILE.exists():
            try:
                return json.loads(PATTERNS_FILE.read_text())
            except Exception:
                pass
        return {"fp_patterns":{}, "confirmed_patterns":{}}

    def _save_patterns(self, patterns: dict):
        PATTERNS_FILE.write_text(json.dumps(patterns, indent=2))

    def _load_stats(self) -> dict:
        if STATS_FILE.exists():
            try:
                return json.loads(STATS_FILE.read_text())
            except Exception:
                pass
        return {"total_findings":0,"true_positives":0,
                "false_positives":0,"by_type":{}}

    def _update_stats(self, outcome: str, vuln_type: str):
        vt = vuln_type.upper()
        self._stats["total_findings"] = self._stats.get("total_findings",0)+1
        if outcome == "true_positive":
            self._stats["true_positives"] = self._stats.get("true_positives",0)+1
        elif outcome == "false_positive":
            self._stats["false_positives"] = self._stats.get("false_positives",0)+1
        by_type = self._stats.setdefault("by_type",{})
        by_type.setdefault(vt, {})
        by_type[vt][outcome] = by_type[vt].get(outcome, 0) + 1
        STATS_FILE.write_text(json.dumps(self._stats,indent=2))

    def _count_patterns(self) -> int:
        p = self._load_patterns()
        return sum(len(v) for v in p.get("fp_patterns",{}).values()) + \
               sum(len(v) for v in p.get("confirmed_patterns",{}).values())


# ── Book knowledge extractor (runs once at install) ───────────────────────────
def extract_book_knowledge_to_disk():
    """Write book knowledge to disk for offline AI use."""
    M7_AI_DIR.mkdir(parents=True, exist_ok=True)
    knowledge_path = M7_AI_DIR / "book_knowledge.json"
    knowledge_path.write_text(json.dumps(BOOK_KNOWLEDGE, indent=2))
    return str(knowledge_path)


if __name__ == "__main__":
    trainer = AITrainer()
    print(trainer.get_summary())

    # Test recording a finding
    trainer.record_finding(
        vuln_type="XSS",
        url="https://example.com/search?q=test",
        payload="<svg/onload=alert(1)>",
        response="<html>...<svg/onload=alert(1)>...</html>",
        outcome="true_positive",
        confidence=0.95,
        notes="Payload reflected unencoded in HTML body"
    )

    # Test context building
    ctx = trainer.build_ollama_context("XSS")
    print(f"\nContext ({len(ctx)} chars):\n{ctx[:300]}...")

    # Test confidence adjustment
    adj = trainer.get_confidence_adjustment(
        "XSS", "<html>&lt;svg/onload=alert(1)&gt;</html>")
    print(f"\nFP response adjustment: {adj:+.2f}")

    path = extract_book_knowledge_to_disk()
    print(f"\nBook knowledge saved: {path}")
