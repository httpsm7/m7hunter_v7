#!/usr/bin/env python3
# modules/step22_idor.py — IDOR Engine v6 (FIXED — eliminates 148 FPs)
# FIX: Confirmation requires DIFFERENT response body content, not same size
# FIX: Personal data pattern detection in response (email, phone, etc.)
# FIX: Cross-user confirmation: test with multiple IDs, not just +1/-1
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import hashlib
import urllib.request
import urllib.parse
from core.utils import safe_read, count_lines

# Personal data patterns that indicate real IDOR
PERSONAL_DATA_PATTERNS = [
    (r'"email"\s*:\s*"[^"@]+@[^"]+\.[^"]+"',  "email address"),
    (r'"phone"\s*:\s*"[\d\+\-\s\(\)]{7,}"',   "phone number"),
    (r'"mobile"\s*:\s*"[\d\+\-\s\(\)]{7,}"',  "mobile number"),
    (r'"address"\s*:\s*"[^"]{10,}"',           "address"),
    (r'"ssn"\s*:\s*"[\d\-]{9,}"',             "SSN"),
    (r'"dob"\s*:\s*"[\d\-]{8,}"',             "date of birth"),
    (r'"credit_card"\s*:\s*"[\d\*\-]{13,}"',  "credit card"),
    (r'"account_number"\s*:\s*"[^"]{5,}"',    "account number"),
    (r'"password_hash"\s*:\s*"[a-f0-9]{32,}"',"password hash"),
    (r'"api_key"\s*:\s*"[A-Za-z0-9_\-]{20,}"',"API key"),
    (r'"secret"\s*:\s*"[^"]{8,}"',            "secret value"),
    (r'"token"\s*:\s*"[A-Za-z0-9_\-\.]{20,}"',"token"),
    (r'"role"\s*:\s*"admin"',                  "admin role"),
    (r'"is_admin"\s*:\s*true',                 "admin flag"),
]

IDOR_PARAMS = re.compile(
    r'[?&](id|user_id|uid|account_id|account|profile_id|order_id|'
    r'invoice_id|document_id|file_id|record_id|item_id|pid|cid|'
    r'eid|tid|rid|bid|vid|sid|object_id|resource_id|ref_id|'
    r'userId|accountId|orderId|profileId)=(\d+|[0-9a-f\-]{32,})',
    re.IGNORECASE
)



def _get_live_hosts(p, limit=100):
    """Returns live hosts - ALWAYS includes main target as fallback."""
    tgt = p.target.strip()
    if not tgt.startswith("http"):
        tgt = "https://" + tgt

    hosts = []
    seen  = set()

    for key in ("fmt_url", "live_hosts", "resolved"):
        src = p.files.get(key, "")
        if not src or not os.path.isfile(src):
            continue
        from core.utils import safe_read
        for line in safe_read(src):
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            if line not in seen:
                seen.add(line)
                hosts.append(line)
        if hosts:
            break

    # GUARANTEED: always include main target
    if tgt not in seen:
        hosts.insert(0, tgt)

    return hosts[:limit]


class IDORStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        urls = self.f.get("urls","")
        out  = os.path.join(self.p.out, f"{self.p.prefix}_idor.txt")
        found = 0

        if not os.path.isfile(urls):
            self.log.warn("IDOR: no URLs file"); return

        all_urls = safe_read(urls)

        # Find IDOR-prone URLs
        idor_candidates = []
        seen_patterns = set()
        for url in all_urls:
            matches = IDOR_PARAMS.findall(url)
            if matches:
                # Dedup by URL pattern (replace ID with {ID})
                normalized = re.sub(r'(=)\d+', r'={ID}', url)
                if normalized not in seen_patterns:
                    seen_patterns.add(normalized)
                    idor_candidates.append((url, matches[0]))

        self.log.info(f"IDOR candidates: {len(idor_candidates)} (unique patterns)")

        for url, (param, value) in idor_candidates[:60]:
            result = self._test_idor(url, param, value)
            if result:
                sev, detail, evidence = result
                line = f"IDOR_CONFIRMED: {url} | {detail}"
                with open(out, "a") as f:
                    f.write(line + "\n")
                self.p.add_finding(sev, "IDOR", url, detail, "idor-engine")
                found += 1

        self.log.success(f"IDOR: {found} confirmed → {os.path.basename(out)}")

    def _test_idor(self, url: str, param: str, value: str):
        """
        FIX: Strict IDOR confirmation:
        1. Get baseline response for original ID
        2. Test with DIFFERENT IDs
        3. Require: different response body (not same size)
        4. Require: personal data patterns OR clearly different JSON
        Returns (severity, detail, evidence) or None.
        """
        if not value.isdigit() and len(value) < 32:
            return None

        orig_val = int(value) if value.isdigit() else value

        # Get authenticated baseline
        auth_flag = f"-H 'Cookie: {self.p.args.cookie}'" if getattr(self.p.args,"cookie",None) else ""

        baseline = self._fetch(url, auth_flag)
        if not baseline or baseline.get("status") not in (200, 201):
            return None

        baseline_body = baseline.get("body","")
        baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()

        # FIX: Test multiple different IDs
        if value.isdigit():
            test_vals = [str(orig_val + 1), str(orig_val + 2), str(max(1, orig_val - 1)), "1", "2"]
        else:
            # UUID-like
            test_vals = ["00000000-0000-0000-0000-000000000001",
                         "00000000-0000-0000-0000-000000000002"]

        for test_val in test_vals:
            if test_val == value:
                continue

            test_url = re.sub(
                rf'([?&]{re.escape(param)}=){re.escape(value)}',
                rf'\g<1>{test_val}',
                url, flags=re.IGNORECASE
            )
            if test_url == url:
                continue

            resp = self._fetch(test_url, auth_flag)
            if not resp or resp.get("status") not in (200, 201):
                continue

            body = resp.get("body", "")
            body_hash = hashlib.md5(body.encode()).hexdigest()

            # FIX: Skip if same response (not IDOR, just same generic page)
            if body_hash == baseline_hash:
                continue

            # FIX: Skip if response is empty or too small
            if len(body) < 50:
                continue

            # FIX: Check for personal data patterns (high confidence)
            for pattern, data_type in PERSONAL_DATA_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match and not re.search(pattern, baseline_body, re.IGNORECASE):
                    detail = (f"param={param} tested_id={test_val} | "
                              f"exposes {data_type} not in own-ID response")
                    return ("critical", detail, match.group()[:100])

            # FIX: Also check if body is significantly different JSON
            # (different content = different user's data)
            if len(body) > 200 and abs(len(body) - len(baseline_body)) > 100:
                # Extract any IDs in response to check if they differ
                ids_baseline = set(re.findall(r'"id"\s*:\s*(\d+)', baseline_body))
                ids_response = set(re.findall(r'"id"\s*:\s*(\d+)', body))
                if ids_response and ids_baseline and ids_response != ids_baseline:
                    detail = (f"param={param} tested_id={test_val} | "
                              f"different user IDs in response: {ids_response}")
                    return ("high", detail, body[:200])

        return None

    def _fetch(self, url: str, auth_flag: str = "", timeout: int = 8) -> dict:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept"    : "application/json, */*",
            })
            if auth_flag and "Cookie:" in auth_flag:
                cookie = auth_flag.split("Cookie: ",1)[-1].rstrip("'")
                req.add_header("Cookie", cookie)
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(50000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None
