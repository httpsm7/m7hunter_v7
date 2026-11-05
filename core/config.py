#!/usr/bin/env python3
# core/config.py — Configuration Manager
# MilkyWay Intelligence | Author: Sharlix

import os

DEFAULTS = {
    "threads": 50, "rate": 1000,
    "timeout_default": 300, "timeout_nuclei": 1800, "timeout_sqlmap": 600,
    "timeout_gau": 120, "timeout_amass": 300,
    "telegram_token": "", "telegram_chat": "", "discord_webhook": "",
    "github_token": "", "shodan_key": "", "vt_key": "", "wpscan_token": "",
    "interactsh_url": "", "nuclei_templates": "",
    "output_dir": "results", "proxy": "", "cookie": "",
    "double_verify": True, "http2": True, "confidence": 0.8,
}


class ConfigManager:
    def __init__(self, args):
        self.args = args
        self.data = dict(DEFAULTS)

    def load(self):
        candidates = []
        if getattr(self.args, 'config', None):
            candidates.append(self.args.config)
        candidates += [
            os.path.expanduser("~/.m7hunter.yaml"),
            os.path.expanduser("~/.m7hunter/config.yaml"),
            os.path.join(os.path.dirname(__file__), '..', 'config', 'm7hunter.yaml'),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                self._parse_file(path)
                break
        self._apply_cli()

    def _parse_file(self, path: str):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ':' in line:
                        k, _, v = line.partition(':')
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if not k or not v:
                            continue
                        if v.isdigit():
                            self.data[k] = int(v)
                        elif v.lower() in ('true', 'yes'):
                            self.data[k] = True
                        elif v.lower() in ('false', 'no'):
                            self.data[k] = False
                        else:
                            self.data[k] = v
        except Exception:
            pass

    def _apply_cli(self):
        a = self.args
        mapping = {
            "threads"       : getattr(a, "threads", None),
            "rate"          : getattr(a, "rate", None),
            "github_token"  : getattr(a, "github_token", None),
            "shodan_key"    : getattr(a, "shodan_key", None),
            "telegram_token": getattr(a, "telegram_token", None),
            "telegram_chat" : getattr(a, "telegram_chat", None),
            "output_dir"    : getattr(a, "output", None),
            "proxy"         : getattr(a, "proxy", None),
            "cookie"        : getattr(a, "cookie", None),
            "confidence"    : getattr(a, "confidence", None),
        }
        for k, v in mapping.items():
            if v is not None:
                self.data[k] = v

    def get(self, key: str, default=None):
        return self.data.get(key, default)
