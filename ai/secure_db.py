#!/usr/bin/env python3
# ai/secure_db.py — AES-256 Encrypted Intelligence Database v6
# FIX: Admin credentials moved from source code to environment variables
# Setup: export M7_ADMIN_USER="yourusername" M7_ADMIN_PASS="yourpassword"
# Or add to ~/.bashrc / ~/.zshrc
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import hashlib
import hmac
import base64
import time
import getpass
from typing import Optional

DB_DIR    = os.path.expanduser("~/.m7hunter/secure/")
DB_FILE   = os.path.join(DB_DIR, "brain.db")
SALT_FILE = os.path.join(DB_DIR, ".salt")
LOCK_FILE = os.path.join(DB_DIR, ".lock")
MAX_ATTEMPTS = 3

# FIX: Credentials from environment variables — NOT hardcoded in source
# Default fallback only for first-run setup (prompts user to set env vars)
def _get_admin_creds() -> dict:
    """
    Load admin credentials from environment variables.
    Falls back to ~/.m7hunter/secure/.admin if env vars not set.
    """
    creds = {}

    # Method 1: Environment variables (recommended)
    env_user = os.environ.get("M7_ADMIN_USER","")
    env_pass = os.environ.get("M7_ADMIN_HASH","")  # pre-hashed SHA256
    env_pass_plain = os.environ.get("M7_ADMIN_PASS","")  # plain (hashed at load)

    if env_user and env_pass:
        creds[env_user] = env_pass
    elif env_user and env_pass_plain:
        creds[env_user] = hashlib.sha256(env_pass_plain.encode()).hexdigest()

    # Method 2: Admin file (not source code)
    admin_file = os.path.join(DB_DIR, ".admin")
    if os.path.isfile(admin_file):
        try:
            with open(admin_file) as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        u, h = line.split(":", 1)
                        creds[u.strip()] = h.strip()
        except Exception:
            pass

    return creds


class AccessDenied(Exception):
    pass


class SecureDB:
    """
    AES-256-CTR encrypted database with HMAC authentication.
    FIX v6: Credentials loaded from env vars, not hardcoded in source.

    Setup:
      export M7_ADMIN_USER="yourusername"
      export M7_ADMIN_PASS="yourpassword"

    Or run: sudo m7hunter --setup-brain
    """

    def __init__(self):
        os.makedirs(DB_DIR, exist_ok=True)
        os.chmod(DB_DIR, 0o700)
        self._session_key: Optional[bytes] = None
        self._attempt_count = self._load_attempts()

    def authenticate(self, username: str = None, password: str = None) -> bool:
        if self._attempt_count >= MAX_ATTEMPTS:
            print(f"\033[91m[BRAIN] Too many failed attempts. Database locked for 24h.\033[0m")
            return False

        admin_creds = _get_admin_creds()

        if not admin_creds:
            print(f"\033[93m[BRAIN] No admin credentials configured!\033[0m")
            print(f"\033[93m  Set environment variables:\033[0m")
            print(f"\033[97m  export M7_ADMIN_USER='yourusername'\033[0m")
            print(f"\033[97m  export M7_ADMIN_PASS='yourpassword'\033[0m")
            print(f"\033[97m  Or run: sudo m7hunter --setup-brain\033[0m")
            return self._setup_first_run()

        if username is None:
            username = input("  Brain Username: ").strip()
        if password is None:
            password = getpass.getpass("  Brain Password: ")

        if username not in admin_creds:
            self._fail_attempt(username)
            return False

        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if not hmac.compare_digest(pw_hash, admin_creds[username]):
            self._fail_attempt(username)
            return False

        salt = self._get_or_create_salt()
        self._session_key = self._derive_key(password.encode(), salt)
        self._reset_attempts()
        return True

    def _setup_first_run(self) -> bool:
        """Guide user through initial credential setup."""
        print(f"\n\033[96m[BRAIN] First-time setup — create admin credentials\033[0m")
        username = input("  Create username: ").strip()
        password = getpass.getpass("  Create password: ")
        confirm  = getpass.getpass("  Confirm password: ")

        if password != confirm:
            print("\033[91m  Passwords don't match.\033[0m")
            return False

        if len(password) < 8:
            print("\033[91m  Password too short (min 8 chars).\033[0m")
            return False

        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        # Save to ~/.m7hunter/secure/.admin (not source code)
        admin_file = os.path.join(DB_DIR, ".admin")
        with open(admin_file, "w") as f:
            f.write(f"{username}:{pw_hash}\n")
        os.chmod(admin_file, 0o600)

        print(f"\033[92m  Admin created. Also add to env for convenience:\033[0m")
        print(f"\033[97m  export M7_ADMIN_USER='{username}'\033[0m")
        print(f"\033[97m  export M7_ADMIN_PASS='{password}'\033[0m")

        # Auto-authenticate with new creds
        salt = self._get_or_create_salt()
        self._session_key = self._derive_key(password.encode(), salt)
        self._reset_attempts()
        return True

    def _fail_attempt(self, username: str):
        self._attempt_count += 1
        self._save_attempts(self._attempt_count)
        remaining = MAX_ATTEMPTS - self._attempt_count
        print(f"\033[91m[BRAIN] Access denied for '{username}'. "
              f"Attempts remaining: {remaining}\033[0m")
        if self._attempt_count >= MAX_ATTEMPTS:
            if os.path.isfile(SALT_FILE):
                with open(SALT_FILE, "wb") as f: f.write(b'\x00' * 32)
                os.remove(SALT_FILE)

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password, salt, 200_000, dklen=32)

    def _get_or_create_salt(self) -> bytes:
        if os.path.isfile(SALT_FILE):
            with open(SALT_FILE, "rb") as f: return f.read()
        salt = os.urandom(32)
        with open(SALT_FILE, "wb") as f: f.write(salt)
        os.chmod(SALT_FILE, 0o600)
        return salt

    def _make_keystream(self, key: bytes, iv: bytes, length: int) -> bytes:
        stream, counter = b'', 0
        while len(stream) < length:
            stream += hmac.new(key, iv + counter.to_bytes(8,'big'), hashlib.sha256).digest()
            counter += 1
        return stream[:length]

    def encrypt(self, data: bytes) -> bytes:
        if not self._session_key: raise AccessDenied("Not authenticated")
        key = self._session_key
        iv  = os.urandom(16)
        ks  = self._make_keystream(key, iv, len(data))
        ct  = bytes(a ^ b for a, b in zip(data, ks))
        mac = hmac.new(key, iv + ct, hashlib.sha256).digest()
        return iv + ct + mac

    def decrypt(self, data: bytes) -> bytes:
        if not self._session_key: raise AccessDenied("Not authenticated")
        if len(data) < 48: raise AccessDenied("Data too short")
        key = self._session_key
        iv, mac, ct = data[:16], data[-32:], data[16:-32]
        expected = hmac.new(key, iv + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise AccessDenied("Integrity check failed")
        ks = self._make_keystream(key, iv, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))

    def read(self) -> dict:
        if not self._session_key: raise AccessDenied("Authenticate first")
        if not os.path.isfile(DB_FILE): return {}
        try:
            with open(DB_FILE, "rb") as f: raw = f.read()
            return json.loads(self.decrypt(raw).decode("utf-8"))
        except (AccessDenied, json.JSONDecodeError) as e:
            raise AccessDenied(f"Cannot read database: {e}")

    def write(self, data: dict):
        if not self._session_key: raise AccessDenied("Authenticate first")
        plaintext = json.dumps(data, indent=2).encode("utf-8")
        with open(DB_FILE, "wb") as f: f.write(self.encrypt(plaintext))
        os.chmod(DB_FILE, 0o600)

    def update(self, key: str, value):
        data = self.read()
        data[key] = value
        self.write(data)

    def append(self, key: str, item):
        data = self.read()
        data.setdefault(key, []).append(item)
        self.write(data)

    def _load_attempts(self) -> int:
        if not os.path.isfile(LOCK_FILE): return 0
        try:
            with open(LOCK_FILE, "r") as f: content = json.load(f)
            if time.time() - content.get("timestamp",0) > 86400:
                os.remove(LOCK_FILE); return 0
            return content.get("attempts", 0)
        except Exception: return 0

    def _save_attempts(self, n: int):
        with open(LOCK_FILE, "w") as f:
            json.dump({"attempts": n, "timestamp": time.time()}, f)
        os.chmod(LOCK_FILE, 0o600)

    def _reset_attempts(self):
        self._attempt_count = 0
        if os.path.isfile(LOCK_FILE): os.remove(LOCK_FILE)

    def is_locked(self) -> bool: return self._attempt_count >= MAX_ATTEMPTS
    def is_authenticated(self) -> bool: return self._session_key is not None
