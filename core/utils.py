#!/usr/bin/env python3
# core/utils.py — M7Hunter V7 Utilities
# MilkyWay Intelligence | Author: Sharlix

import os, re, sys


def check_root():
    if os.geteuid() != 0:
        print("\n\033[91m[!] M7Hunter requires root privileges!\033[0m")
        print("\033[93m    Run: sudo python3 m7hunter.py\033[0m\n")
        sys.exit(1)


def get_prefix(target: str) -> str:
    domain = re.sub(r'^https?://', '', target).strip()
    domain = re.split(r'[:/]', domain)[0]
    label  = domain.split('.')[0]
    clean  = re.sub(r'[^a-zA-Z0-9]', '', label)
    return (clean[:3] if len(clean) >= 3 else clean.ljust(3, '0')).lower()


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def count_lines(path: str) -> int:
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def safe_read(path: str) -> list:
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []


def is_in_scope(url: str, scope: list) -> bool:
    if not scope:
        return True
    url_lower = url.lower()
    for s in scope:
        s = s.strip().lower()
        if s and (s in url_lower or url_lower.endswith(s)):
            return True
    return False


class FormatFixer:
    @staticmethod
    def _is_ip(v: str) -> bool:
        parts = v.split('.')
        try:
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False

    @staticmethod
    def _bare(line: str) -> str:
        line = line.strip()
        line = re.sub(r'\s+\[.*', '', line)
        line = re.sub(r'^https?://', '', line)
        line = re.split(r'[:/]', line)[0]
        return line.strip()

    @classmethod
    def fix(cls, src: str, dst: str, mode: str) -> int:
        if not os.path.isfile(src):
            return 0
        with open(src) as f:
            raw = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        out = []
        for line in raw:
            bare = cls._bare(line)
            if not bare:
                continue
            if mode == 'domain':
                out.append(bare.split(':')[0])
            elif mode == 'url':
                scheme = 'http' if line.startswith('http://') else 'https'
                out.append(f"{scheme}://{bare}")
            elif mode == 'ip':
                if cls._is_ip(bare):
                    out.append(bare)
            elif mode == 'host':
                out.append(bare)
            else:
                out.append(line)
        seen, deduped = set(), []
        for l in out:
            if l not in seen:
                seen.add(l)
                deduped.append(l)
        with open(dst, 'w') as f:
            f.write('\n'.join(deduped) + '\n')
        return len(deduped)
