#!/usr/bin/env python3
# core/config.py — M7Hunter V7 Config Loader
# FIX Q-06: Config now properly loaded and applied to args
# MilkyWay Intelligence | Author: Sharlix

import os
import yaml
from typing import Any

DEFAULT_CONFIG_PATHS = [
    os.path.expanduser("~/.m7hunter.yaml"),
    os.path.expanduser("~/.m7hunter/config.yaml"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "config", "m7hunter.yaml"),
]


def load_config(config_file: str = None) -> dict:
    """Load YAML config from file or default paths."""
    paths = [config_file] if config_file else DEFAULT_CONFIG_PATHS
    for path in paths:
        if path and os.path.isfile(path):
            try:
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                return data
            except Exception as e:
                print(f"[!] Config load error ({path}): {e}")
    return {}


def apply_config(args, config: dict):
    """
    Apply config values to args — only if the arg was not set on CLI.
    CLI args always take precedence.
    """
    MAPPINGS = {
        "threads"        : "threads",
        "rate"           : "rate",
        "output_dir"     : "output",
        "proxy"          : "proxy",
        "confidence"     : "confidence",
        "double_verify"  : None,           # handled specially
        "github_token"   : "github_token",
        "shodan_key"     : "shodan_key",
        "wpscan_token"   : "wpscan_token",
        "telegram_token" : "telegram_token",
        "telegram_chat"  : "telegram_chat",
        "discord_webhook": "discord_webhook",
        "interactsh_url" : "interactsh_url",
    }
    for cfg_key, arg_key in MAPPINGS.items():
        if cfg_key not in config: continue
        if arg_key is None: continue
        # Only apply if arg is still at default/None
        current = getattr(args, arg_key, None)
        if current is None or current == "" or current == 0:
            setattr(args, arg_key, config[cfg_key])
    return args
