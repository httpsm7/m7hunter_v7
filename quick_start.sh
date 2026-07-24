#!/usr/bin/env bash
# quick_start.sh — One command venv setup (no root needed)
# Works on Kali Linux with Python 3.13
# MilkyWay Intelligence | AUTHORIZED USE ONLY

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo "[*] M7Hunter V7 — Quick Start"
echo "[*] Python: $(python3 --version)"

# 1. Create venv
if [[ ! -d "$VENV_DIR" ]]; then
    echo "[*] Creating virtualenv..."
    python3 -m venv "$VENV_DIR"
fi

# 2. Upgrade pip/setuptools first (MUST for Python 3.13)
echo "[*] Upgrading pip + setuptools + wheel..."
"${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel --quiet

# 3. Install dependencies
echo "[*] Installing requirements (Python 3.13 compatible)..."
"${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt" --quiet

# 4. Playwright
echo "[*] Installing Playwright chromium..."
"${VENV_DIR}/bin/python" -m playwright install chromium --with-deps 2>/dev/null || \
    echo "[!] Playwright failed (optional — skip for now)"

# 5. Verify
echo ""
echo "[*] Verifying installs..."
"${VENV_DIR}/bin/python" - << 'PYEOF'
import sys
print(f"  Python {sys.version.split()[0]}")
checks = [
    ("pydantic",     "pydantic"),
    ("httpx",        "httpx"),
    ("cryptography", "cryptography"),
    ("lxml",         "lxml"),
    ("aiohttp",      "aiohttp"),
    ("flask",        "flask"),
    ("structlog",    "structlog"),
    ("yaml",         "pyyaml"),
    ("psutil",       "psutil"),
]
ok = fail = 0
for imp, name in checks:
    try:
        m = __import__(imp)
        v = getattr(m, "__version__", "?")
        print(f"  ✓ {name} {v}")
        ok += 1
    except ImportError as e:
        print(f"  ✗ {name}: {e}")
        fail += 1
print(f"\n  {ok} OK, {fail} failed")
PYEOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Setup complete. Run:"
echo "  source .venv/bin/activate"
echo "  python m7hunter.py --help"
echo ""
echo "  OR without activating:"
echo "  .venv/bin/python m7hunter.py -u target.com --edrp"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
