#!/usr/bin/env python3
# integrations/ollama_manager.py — Auto Ollama Manager
# Auto-start, port conflict handling, model auto-pull
# MilkyWay Intelligence | Author: Sharlix

import subprocess
import time
import urllib.request
import json
import os
import threading
import shutil

OLLAMA_URL   = "http://localhost:11434"
DEFAULT_MODEL = "llama3"
FALLBACK_MODEL = "phi3"


class OllamaManager:
    """
    Auto-manages Ollama lifecycle:
    - Checks if already running
    - Starts if not running
    - Handles port conflicts
    - Auto-pulls required model
    """

    def __init__(self, model: str = DEFAULT_MODEL, log=None):
        self.model   = model
        self.log     = log
        self._proc   = None
        self._ready  = False

    def _log(self, msg: str, level: str = "info"):
        if self.log:
            getattr(self.log, level, self.log.info)(msg)
        else:
            print(f"[Ollama] {msg}")

    def ensure_running(self) -> bool:
        """Make sure Ollama is running. Returns True if ready."""
        # 1. Already running?
        if self._check_alive():
            self._log("Ollama already running ✓")
            self._ready = True
            return True

        # 2. Try to start
        if not shutil.which("ollama"):
            self._log("Ollama not installed — install via: curl -fsSL https://ollama.com/install.sh | sh", "warn")
            return False

        self._log("Starting Ollama server...")
        try:
            self._proc = subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait up to 10s
            for _ in range(20):
                time.sleep(0.5)
                if self._check_alive():
                    self._log("Ollama started ✓")
                    self._ready = True
                    return True

            self._log("Ollama start timeout", "warn")
            return False

        except FileNotFoundError:
            self._log("Ollama binary not found", "warn")
            return False
        except Exception as e:
            # Port already in use — another instance running
            if "address already in use" in str(e).lower() or "11434" in str(e):
                self._log("Ollama port 11434 busy — using existing instance")
                if self._check_alive():
                    self._ready = True
                    return True
            self._log(f"Ollama start failed: {e}", "warn")
            return False

    def ensure_model(self, model: str = None) -> bool:
        """Pull model if not present."""
        model = model or self.model
        if not self._ready:
            return False

        # Check if model exists
        try:
            r = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=5)
            data = json.loads(r.read())
            models = [m["name"].split(":")[0] for m in data.get("models", [])]
            if model in models or model.split(":")[0] in models:
                self._log(f"Model {model} ready ✓")
                return True
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("ollama_manager", _e)

        # Pull model
        self._log(f"Pulling model: {model} (may take a few minutes)...")
        try:
            proc = subprocess.Popen(
                ["ollama", "pull", model],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Non-blocking wait with timeout
            try:
                proc.wait(timeout=300)
                if proc.returncode == 0:
                    self._log(f"Model {model} pulled ✓")
                    return True
                else:
                    # Try fallback
                    self._log(f"Pull failed for {model}, trying {FALLBACK_MODEL}", "warn")
                    self.model = FALLBACK_MODEL
                    return self.ensure_model(FALLBACK_MODEL)
            except subprocess.TimeoutExpired:
                proc.kill()
                self._log("Model pull timeout — using existing models", "warn")
                return False
        except Exception as e:
            self._log(f"Model pull error: {e}", "warn")
            return False

    def setup(self) -> bool:
        """Full setup: start + pull model."""
        if not self.ensure_running():
            return False
        # Pull model in background thread (non-blocking)
        threading.Thread(
            target=self.ensure_model,
            daemon=True
        ).start()
        return True

    def _check_alive(self) -> bool:
        try:
            r = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3)
            return r.status == 200
        except Exception:
            return False

    def is_ready(self) -> bool:
        return self._ready

    def stop(self):
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("ollama_manager", _e)
