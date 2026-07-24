import os
import hmac, hashlib
#!/usr/bin/env python3
# modules/step19_jwt.py — JWT Security Testing
# MilkyWay Intelligence | Author: Sharlix

import re, base64, json, hmac, hashlib, time
from core.utils import safe_read
from core.http_client import sync_get

WEAK_SECRETS = [
    "secret","password","123456","test","admin","jwt","token",
    "secret123","mysecret","change_me","your-256-bit-secret",
    "your-secret-key","supersecret","hs256","jwtkey","","null",
]

JWT_PATHS = [
    "/api/me","/api/user","/api/profile","/api/account",
    "/api/admin","/api/v1/me","/api/v2/me","/dashboard","/admin",
]



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


class Step19Jwt:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["jwt_results"]
        live  = safe_read(p.files.get("fmt_url",""))[:100]
        found = 0

        if not live:
            p.log.warn("JWT: no live hosts"); return

        p.log.info("JWT security testing")

        # Extract JWTs from cookie/auth header
        jwts_to_test = []

        cookie = getattr(p.args,"cookie",None) or ""
        auth   = getattr(p.args,"authorization",None) or ""

        for src in [cookie, auth]:
            matches = re.findall(
                r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                src
            )
            jwts_to_test.extend(matches)

        # Discover JWTs from live hosts
        for host in live[:5]:
            for path in JWT_PATHS[:5]:
                resp = sync_get(host.rstrip("/")+path, timeout=6)
                if resp:
                    body = resp.get("body","")
                    hdrs = str(resp.get("headers",""))
                    for src in [body, hdrs]:
                        matches = re.findall(
                            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                            src
                        )
                        jwts_to_test.extend(matches)

        jwts_to_test = list(set(jwts_to_test))[:100]
        if not jwts_to_test:
            p.log.info("JWT: No tokens found to test")
            return

        p.log.info(f"JWT: testing {len(jwts_to_test)} tokens")

        for jwt_token in jwts_to_test:
            results = self._audit_jwt(jwt_token, live[0] if live else "")
            for sev, vuln_type, detail in results:
                with open(out,"a") as f:
                    f.write(f"{vuln_type}: {detail}\n")
                p.add_finding(sev, vuln_type, live[0] if live else p.target,
                               detail, "jwt-engine")
                found += 1

        p.log.success(f"JWT: {found} issues found")

    def _decode_part(self, part: str) -> dict:
        try:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return {}

    def _audit_jwt(self, token: str, base_url: str) -> list:
        issues = []
        parts  = token.split(".")
        if len(parts) != 3:
            return issues

        header  = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])

        alg = header.get("alg","")

        # Test 1: alg:none bypass
        if alg and alg.lower() != "none":
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg":"none","typ":"JWT"}).encode()
            ).rstrip(b"=").decode()
            none_token = f"{none_header}.{parts[1]}."
            if base_url:
                resp = self._test_token(none_token, base_url)
                if resp and resp.get("status",0) == 200:
                    issues.append(("critical","JWT_ALG_NONE_BYPASS",
                        f"alg:none bypass accepted — JWT signature not verified"))

        # Test 2: Weak secret brute force (HS256)
        if alg in ("HS256","HS384","HS512"):
            msg = f"{parts[0]}.{parts[1]}".encode()
            for secret in WEAK_SECRETS:
                sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                if sig_b64 == parts[2]:
                    issues.append(("critical","JWT_WEAK_SECRET",
                        f"Weak JWT secret cracked: '{secret}' — "
                        f"forge any token with this secret"))
                    break

        # Test 3: Expired token still accepted
        exp = payload.get("exp", 0)
        if exp and exp < time.time():
            if base_url:
                resp = self._test_token(token, base_url)
                if resp and resp.get("status",0) == 200:
                    issues.append(("high","JWT_EXPIRED_ACCEPTED",
                        f"Expired JWT (exp:{exp}) still accepted by server"))

        # Test 4: No expiry
        if not exp:
            issues.append(("medium","JWT_NO_EXPIRY",
                f"JWT has no 'exp' claim — token never expires"))

        # Test 5: Sensitive data in payload
        for key in ["password","secret","api_key","credit_card","ssn"]:
            if key in str(payload).lower():
                issues.append(("high","JWT_SENSITIVE_DATA",
                    f"Sensitive field '{key}' found in JWT payload (not encrypted)"))

        return issues

    def _test_token(self, token: str, base_url: str) -> dict:
        for path in JWT_PATHS[:3]:
            resp = sync_get(
                base_url.rstrip("/")+path,
                headers={"Authorization": f"Bearer {token}"},
                timeout=6
            )
            if resp and resp.get("status",0) in (200,201):
                return resp
        return None
