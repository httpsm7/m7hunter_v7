#!/usr/bin/env python3
# modules/step14_screenshot.py — Screenshot Live Hosts
# FIX: gowitness path, chromium fallback, thread-safe
# MilkyWay Intelligence | Author: Sharlix

import os
import shutil
import subprocess
from core.utils import count_lines, safe_read



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


class Step14Screenshot:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p      = self.p
        live   = p.files["live_hosts"]
        ss_dir = p.files["screenshots_dir"]
        os.makedirs(ss_dir, exist_ok=True)

        if not os.path.isfile(live) or count_lines(live) == 0:
            p.log.warn("Screenshot: no live hosts")
            pass  # continue with fallback

        hosts = safe_read(live)[:50]
        # Extract clean URLs
        clean = []
        for h in hosts:
            url = h.split()[0].strip() if h.split() else h.strip()
            if url.startswith("http"): clean.append(url)
        if not clean:
            p.log.warn("Screenshot: no valid URLs"); return

        # Write clean URL list
        url_file = os.path.join(p.out, f"{p.prefix}_ss_urls.txt")
        with open(url_file, "w") as f:
            f.write("\n".join(clean) + "\n")

        p.log.info(f"Screenshots: {len(clean)} hosts")

        # Find gowitness binary
        gowitness = self._find_gowitness()

        if gowitness:
            result = self._run_gowitness(gowitness, url_file, ss_dir, p)
        else:
            p.log.warn("gowitness not found — trying chromium fallback")
            result = self._run_chromium_fallback(clean, ss_dir, p)

        n = len([f for f in os.listdir(ss_dir) if f.endswith((".png",".jpg",".jpeg"))])
        p.log.success(f"Screenshots: {n} captured → {ss_dir}")

    def _find_gowitness(self):
        search_paths = [
            shutil.which("gowitness"),
            os.path.expanduser("~/go/bin/gowitness"),
            "/usr/local/bin/gowitness",
            "/usr/bin/gowitness",
        ]
        for p in search_paths:
            if p and os.path.isfile(p) and os.access(p, os.X_OK):
                return p

        # Try installing
        try:
            subprocess.run(
                "go install github.com/sensepost/gowitness@latest 2>/dev/null",
                shell=True, timeout=120, env={**os.environ,
                    "GOPATH": os.path.expanduser("~/go"),
                    "PATH": os.path.expanduser("~/go/bin") + ":/usr/local/go/bin:" + os.environ.get("PATH","")
                }
            )
            return os.path.expanduser("~/go/bin/gowitness")
        except Exception:
            return None

    def _run_gowitness(self, gowitness, url_file, ss_dir, p):
        """Run gowitness with proper args."""
        cmds = [
            # New gowitness v3+ syntax
            f"{gowitness} scan file -f {url_file} --screenshot-path {ss_dir} --timeout 10 --threads 5 2>/dev/null",
            # Old gowitness v2 syntax
            f"{gowitness} file -f {url_file} --screenshot-path {ss_dir} --delay 1 --timeout 10 --threads 5 2>/dev/null",
            # Fallback with full path
            f"{gowitness} scan file -f {url_file} -P {ss_dir} --timeout 10 2>/dev/null",
        ]
        for cmd in cmds:
            try:
                r = subprocess.run(cmd, shell=True, timeout=300,
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    return True
            except Exception:
                continue
        return False

    def _run_chromium_fallback(self, urls, ss_dir, p):
        """Chromium/puppeteer screenshot fallback."""
        chromium = shutil.which("chromium") or shutil.which("chromium-browser") or \
                   shutil.which("google-chrome")
        if not chromium:
            p.log.warn("No browser available for screenshots"); return False

        captured = 0
        for url in urls[:20]:
            safe_name = url.replace("://","_").replace("/","_").replace(":","_")[:60]
            out_file  = os.path.join(ss_dir, f"{safe_name}.png")
            try:
                subprocess.run([
                    chromium, "--headless", "--no-sandbox",
                    "--disable-dev-shm-usage", "--disable-gpu",
                    f"--screenshot={out_file}",
                    "--window-size=1280,720",
                    url
                ], timeout=15, capture_output=True)
                if os.path.isfile(out_file):
                    captured += 1
            except Exception:
                continue
        return captured > 0
