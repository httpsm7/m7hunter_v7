#!/usr/bin/env python3
# core/secure_store.py — Fernet Encrypted Credential Vault
# Blueprint Fix: No more plaintext tokens/cookies on disk
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import os, json, stat, base64, hashlib
from pathlib import Path

STORE_DIR  = Path.home() / ".m7hunter"
STORE_FILE = STORE_DIR / "vault.enc"
KEY_FILE   = STORE_DIR / ".vaultkey"

def _get_key() -> bytes:
    env = os.environ.get("M7HUNTER_KEY", "")
    if env and len(env) >= 16:
        return base64.urlsafe_b64encode(hashlib.sha256(env.encode()).digest())
    try:
        import keyring
        k = keyring.get_password("m7hunter", "vault_key")
        if k: return k.encode()
    except Exception as _e:
        pass
    except Exception as _e:
        pass
        from core.error_handler import get_handler
        get_handler().capture("secure_store", _e)
    STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if KEY_FILE.exists():
        with open(KEY_FILE,"rb") as f: return f.read().strip()
    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        with open(KEY_FILE,"wb") as f: f.write(key)
        os.chmod(KEY_FILE, stat.S_IRUSR|stat.S_IWUSR)
        return key
    except ImportError: return b""

class SecureStore:
    def __init__(self):
        self._fernet = None; self._data = {}; self._ok = False
        try:
            from cryptography.fernet import Fernet
            k = _get_key()
            if k: self._fernet = Fernet(k); self._ok = True; self._load()
        except Exception as _e:
            pass
        except Exception as _e:
            pass
            from core.error_handler import get_handler
            get_handler().capture("secure_store", _e)

    def _load(self):
        if not STORE_FILE.exists(): return
        try:
            with open(STORE_FILE,"rb") as f: raw = f.read()
            self._data = json.loads(self._fernet.decrypt(raw).decode())
        except Exception: self._data = {}

    def _save(self):
        STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        enc = self._fernet.encrypt(json.dumps(self._data).encode())
        with open(STORE_FILE,"wb") as f: f.write(enc)
        os.chmod(STORE_FILE, stat.S_IRUSR|stat.S_IWUSR)

    def set(self, k, v):
        if not self._ok: return False
        self._data[k] = v; self._save(); return True

    def get(self, k, default=None):
        return self._data.get(k, default) if self._ok else default

    def encrypt(self, text: str) -> str:
        if not self._ok or not text: return text
        try: return self._fernet.encrypt(text.encode()).decode()
        except Exception: return text

    def decrypt(self, token: str) -> str:
        if not self._ok or not token: return token
        try: return self._fernet.decrypt(token.encode()).decode()
        except Exception: return token

    @property
    def available(self): return self._ok
