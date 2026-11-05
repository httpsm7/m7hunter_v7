#!/usr/bin/env python3
# core/plugin_loader.py — M7Hunter V7 Plugin Loader (FIXED)
# Fixes: NUM_TO_NAME now covers step01–step30, correct class discovery
# MilkyWay Intelligence | Author: Sharlix + M7AI

import os, sys, importlib, importlib.util
from typing import Dict, List, Type, Any

# ── Complete step number → pipeline key mapping ───────────────────────────────
NUM_TO_NAME = {
    "01": "subdomain",         # step01_subdomain.py
    "02": "dns",               # step02_dns.py
    "03": "probe",             # step03_probe.py
    "04": "ports",             # step04_ports.py
    "05": "crawl",             # step05_crawl.py
    "06": "nuclei",            # step06_nuclei.py
    "07": "xss",               # step07_xss.py
    "08": "sqli",              # step08_sqli.py
    "09": "cors",              # step09_cors.py
    "10": "lfi",               # step10_lfi.py
    "11": "ssrf",              # step11_ssrf.py
    "12": "redirect",          # step12_redirect.py (legacy)
    "13": "takeover",          # step13_takeover.py
    "14": "screenshot",        # step14_screenshot.py
    "15": "wpscan",            # step15_wpscan.py
    "16": "github",            # step16_github.py
    "17": "cloud",             # step17_cloud.py
    "18": "ssti",              # step18_ssti.py
    "19": "jwt",               # step19_jwt.py
    "20": "graphql",           # step20_graphql.py
    "21": "host_header",       # step21_host_header.py
    "22": "idor",              # step22_idor.py
    "23": "xxe",               # step23_xxe.py
    "24": "smuggling",         # step24_smuggling.py
    "25": "csrf",              # step25_csrf.py
    "26": "race",              # step26_race.py
    "27": "nosql",             # step27_nosql.py
    "28": "clickjacking",      # step28_clickjacking.py  ← NEW (was 'ws', now fixed)
    "29": "oauth",             # step29_oauth.py         ← NEW
    "30": "open_redirect",     # step30_open_redirect_chain.py ← NEW
    "31": "deserialization",   # step31_deserialization.py       ← NEW
    "32": "param_pollution",   # step32_param_pollution.py       ← NEW
    "33": "file_upload",      # step33_file_upload.py          ← NEW
    "34": "content",          # step34_content_discovery.py    ← NEW
    "35": "hashcrack",        # step35_hashcrack.py            ← NEW
    "36": "recon_deep",       # step36_recon_deep.py           ← NEW
    "37": "twofa_bypass",     # step37_2fa_bypass.py           ← NEW
    "38": "business_logic",   # step38_business_logic.py       ← NEW
    "39": "session_fixation",  # step39_session_fixation.py    ← NEW
    "40": "xss_advanced",      # step40_xss_advanced.py        ← NEW
    "41": "password_spray",    # step41_password_spray.py      ← NEW
    "42": "dep_confusion",     # step42_dependency_confusion.py ← NEW
    "43": "cve_exploit",       # step43_cve_exploit.py          ← NEW
    "44": "api_security",      # step44_api_security.py         ← NEW
    "45": "sop_bypass",        # step45_sop_bypass.py           ← NEW
}


class PluginMeta:
    def __init__(self, name: str, module: Any, cls: Any, path: str):
        self.name    = name
        self.module  = module
        self.cls     = cls
        self.path    = path
        self.enabled = True

    def __repr__(self):
        return f"Plugin({self.name}, enabled={self.enabled})"


class PluginLoader:
    """
    V7 Plugin Loader — Fixed & Complete.
    Discovers all step modules and maps them to pipeline step keys.
    """

    def __init__(self, base_dir: str, log=None):
        self.base_dir = base_dir
        self.log      = log
        self._plugins: Dict[str, PluginMeta] = {}

    def discover(self, folders: List[str] = None) -> Dict[str, PluginMeta]:
        folders = folders or ["plugins", "engines", "modules"]
        for folder in folders:
            folder_path = os.path.join(self.base_dir, folder)
            if not os.path.isdir(folder_path):
                continue
            for filename in sorted(os.listdir(folder_path)):
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue
                module_name = filename[:-3]
                plugin_path = os.path.join(folder_path, filename)
                self._load_plugin(module_name, plugin_path, folder)
        return self._plugins

    def _load_plugin(self, name: str, path: str, folder: str):
        try:
            spec   = importlib.util.spec_from_file_location(
                f"m7v7.{folder}.{name}", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            cls = self._find_class(module, name)
            meta = PluginMeta(name, module, cls, path)
            self._plugins[name] = meta

        except Exception as e:
            if self.log:
                self.log.warn(f"[Plugin] Failed to load {name}: {e}")

    def _find_class(self, module, name: str):
        """
        Find the main class in a module.
        Strategy:
        1. Look for CamelCase version of filename
        2. Look for any class with run() method
        """
        # Build candidate names
        parts    = name.split("_")
        # For stepNN_name → StepNNName or just NameStep
        camel    = "".join(w.capitalize() for w in parts)
        # Without leading StepNN prefix
        no_step  = "".join(w.capitalize() for w in parts[2:]) if len(parts) > 2 else camel

        candidates = {camel, no_step, f"Step{no_step}", f"{no_step}Step"}

        # First pass: exact name match
        for attr_name in dir(module):
            if attr_name in candidates:
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and hasattr(attr, "run"):
                    return attr

        # Second pass: case-insensitive
        camel_lower = camel.lower()
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and
                    hasattr(attr, "run") and
                    attr_name.lower().replace("_","") == camel_lower.replace("_","")):
                return attr

        # Third pass: any class with run()
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and
                    hasattr(attr, "run") and
                    attr_name not in ("type","object","Exception")):
                return attr

        return None

    def get_steps(self) -> Dict[str, Type]:
        """Return {step_key: class} for all discovered step modules."""
        steps = {}
        for name, meta in self._plugins.items():
            if not name.startswith("step") or not meta.cls:
                continue
            # Extract numeric part: step01_subdomain → "01"
            num = ""
            for i, ch in enumerate(name[4:]):
                if ch.isdigit():
                    num += ch
                else:
                    break
            if num in NUM_TO_NAME:
                key = NUM_TO_NAME[num]
                steps[key] = meta.cls
            else:
                # Fallback: use everything after stepNN_
                remainder = name[4:].lstrip("0123456789").lstrip("_")
                if remainder:
                    steps[remainder] = meta.cls

        return steps

    def get(self, name: str) -> PluginMeta:
        return self._plugins.get(name)

    def list_enabled(self) -> List[str]:
        return [n for n, m in self._plugins.items() if m.enabled]

    def disable(self, name: str):
        if name in self._plugins:
            self._plugins[name].enabled = False

    def enable(self, name: str):
        if name in self._plugins:
            self._plugins[name].enabled = True

    def reload(self, name: str):
        if name in self._plugins:
            path   = self._plugins[name].path
            folder = os.path.basename(os.path.dirname(path))
            del self._plugins[name]
            self._load_plugin(name, path, folder)
            if self.log:
                self.log.success(f"[Plugin] Reloaded: {name}")


if __name__ == "__main__":
    import os, sys
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pl   = PluginLoader(base)
    pl.discover(["modules"])
    steps = pl.get_steps()
    print(f"Discovered {len(steps)} steps:")
    for k, v in sorted(steps.items()):
        print(f"  {k:20s} → {v.__name__ if v else 'NO CLASS'}")
