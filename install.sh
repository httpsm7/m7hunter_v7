#!/usr/bin/env bash
# install.sh — M7Hunter V7 Installer
# Python 3.13 compatible | Go 1.24.3
# MilkyWay Intelligence | AUTHORIZED USE ONLY

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YEL}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
head_() { echo -e "\n${BLU}━━━ $* ━━━${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Detect Python ─────────────────────────────────────────────────────
head_ "Python Check"
PYTHON=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        PYVER=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$PYVER" | cut -d. -f1)
        MINOR=$(echo "$PYVER" | cut -d. -f2)
        if [[ $MAJOR -eq 3 && $MINOR -ge 11 ]]; then
            PYTHON="$py"
            info "Found Python $PYVER at $(command -v $py)"
            break
        fi
    fi
done
[[ -z "$PYTHON" ]] && error "Python 3.11+ required. Install with: apt install python3.13"

# ── OS check ─────────────────────────────────────────────────────────
if grep -qiE "kali|ubuntu|debian" /etc/os-release 2>/dev/null; then
    info "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
else
    warn "Untested OS — Kali/Ubuntu/Debian recommended"
fi

# ── Helpers ───────────────────────────────────────────────────────────
apt_install() {
    dpkg -l "$1" &>/dev/null && { info "  Already installed: $1"; return; }
    info "  Installing: $1"
    DEBIAN_FRONTEND=noninteractive apt-get install -yq "$1" 2>&1 | tail -1
}

go_install() {
    local pkg="$1" bin="$2"
    command -v "$bin" &>/dev/null && { info "  Already installed: $bin"; return; }
    info "  go install: $bin"
    GOPATH="$HOME/go" go install "${pkg}@latest" 2>&1 | grep -v "^$" | tail -2 \
        || warn "  Failed: $bin (non-fatal, install manually)"
}

# ── System packages ───────────────────────────────────────────────────
head_ "System Packages"
apt-get update -qq
for pkg in python3 python3-pip python3-venv git curl wget jq \
           nmap masscan tor proxychains4 chromium dnsutils \
           libssl-dev libffi-dev libxml2-dev libxslt1-dev \
           build-essential ca-certificates net-tools; do
    apt_install "$pkg"
done

# ── Go 1.24.3 ────────────────────────────────────────────────────────
head_ "Go 1.24.3"
REQUIRED_GO="1.24.3"
CURRENT_GO=$(go version 2>/dev/null | grep -oP '\d+\.\d+(\.\d+)?' | head -1 || echo "0")
NEED_GO=true

if [[ "$CURRENT_GO" != "0" ]]; then
    # Compare major.minor
    CURR_MINOR=$(echo "$CURRENT_GO" | cut -d. -f2)
    [[ $CURR_MINOR -ge 24 ]] && NEED_GO=false && info "Go $CURRENT_GO already installed"
fi

if $NEED_GO; then
    info "Installing Go $REQUIRED_GO..."
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    GOTAR="go${REQUIRED_GO}.linux-${ARCH}.tar.gz"
    curl -fsSL "https://go.dev/dl/${GOTAR}" -o /tmp/gotar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/gotar.gz
    rm /tmp/gotar.gz
    cat > /etc/profile.d/go.sh << 'GOEOF'
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
export GOPATH="$HOME/go"
GOEOF
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    export GOPATH="$HOME/go"
    info "Go $(go version) installed"
fi

export PATH="/usr/local/go/bin:${HOME}/go/bin:$PATH"
export GOPATH="${HOME}/go"

# ── Go security tools ─────────────────────────────────────────────────
head_ "Go Tools"
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder:subfinder"
    "github.com/projectdiscovery/httpx/cmd/httpx:httpx"
    "github.com/projectdiscovery/dnsx/cmd/dnsx:dnsx"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei:nuclei"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu:naabu"
    "github.com/projectdiscovery/katana/cmd/katana:katana"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client:interactsh-client"
    "github.com/projectdiscovery/alterx/cmd/alterx:alterx"
    "github.com/hakluke/hakrawler:hakrawler"
    "github.com/lc/gau/v2/cmd/gau:gau"
    "github.com/tomnomnom/waybackurls:waybackurls"
    "github.com/tomnomnom/anew:anew"
    "github.com/tomnomnom/qsreplace:qsreplace"
    "github.com/tomnomnom/gf:gf"
    "github.com/tomnomnom/assetfinder:assetfinder"
    "github.com/hahwul/dalfox/v2:dalfox"
    "github.com/sensepost/gowitness:gowitness"
    "github.com/sensepost/subzy:subzy"
    "github.com/ffuf/ffuf/v2:ffuf"
    "github.com/gospiderteam/gospider:gospider"
    "github.com/trufflesecurity/trufflehog/v3:trufflehog"
)
for entry in "${GO_TOOLS[@]}"; do
    go_install "${entry%%:*}" "${entry##*:}"
done

# ── Python venv (recommended over system-wide install) ────────────────
head_ "Python Virtual Environment"
VENV_DIR="${SCRIPT_DIR}/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating venv at ${VENV_DIR}..."
    $PYTHON -m venv "$VENV_DIR"
fi

VENV_PY="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

info "Upgrading pip + setuptools + wheel (critical for Python 3.13)..."
"$VENV_PIP" install --quiet --upgrade pip setuptools wheel

info "Installing Python dependencies (Python 3.13 compatible)..."
"$VENV_PIP" install --quiet -r "${SCRIPT_DIR}/requirements.txt"

info "Installing Playwright browsers..."
"${VENV_DIR}/bin/python" -m playwright install chromium --with-deps 2>&1 \
    | tail -3 || warn "Playwright install failed (optional)"

# Create wrapper script that uses venv
cat > /usr/local/bin/m7hunter << WRAPPER
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${SCRIPT_DIR}/m7hunter.py" "\$@"
WRAPPER
chmod +x /usr/local/bin/m7hunter

# ── Nuclei templates ──────────────────────────────────────────────────
head_ "Nuclei Templates"
command -v nuclei &>/dev/null && {
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>&1 | tail -2 || warn "Template update failed"
}

# ── GF patterns ───────────────────────────────────────────────────────
head_ "GF Patterns"
if command -v gf &>/dev/null && [[ ! -d ~/.gf ]]; then
    info "Installing gf patterns..."
    git clone --quiet --depth=1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gfp 2>/dev/null || true
    mkdir -p ~/.gf && cp /tmp/gfp/*.json ~/.gf/ 2>/dev/null || true
    rm -rf /tmp/gfp
fi

# ── Ollama (optional) ─────────────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
    info "Installing Ollama (optional local AI)..."
    curl -fsSL https://ollama.ai/install.sh | bash 2>&1 | tail -3 || warn "Ollama install failed (optional)"
fi

# ── Secure vault dir ──────────────────────────────────────────────────
mkdir -p ~/.m7hunter && chmod 700 ~/.m7hunter

# ── Verify ────────────────────────────────────────────────────────────
head_ "Verification"
REQUIRED=(nmap httpx subfinder nuclei dnsx dalfox)
MISSING=()
for tool in "${REQUIRED[@]}"; do
    command -v "$tool" &>/dev/null || MISSING+=("$tool")
done
[[ ${#MISSING[@]} -gt 0 ]] && warn "Missing: ${MISSING[*]}" || info "All core tools OK ✓"

# Verify Python packages
info "Verifying Python 3.13 packages..."
"$VENV_PY" -c "
import sys
print(f'  Python: {sys.version}')
pkgs = ['pydantic','httpx','cryptography','lxml','aiohttp','playwright']
for p in pkgs:
    try:
        m = __import__(p.split('[')[0].replace('-','_'))
        v = getattr(m,'__version__','?')
        print(f'  ✓ {p}: {v}')
    except ImportError as e:
        print(f'  ✗ {p}: {e}')
" 2>&1

echo ""
echo -e "${GRN}═══════════════════════════════════════════════${NC}"
echo -e "${GRN}  M7Hunter V7 — Installation Complete${NC}"
echo -e "${GRN}  sudo m7hunter -u target.com --edrp --deep${NC}"
echo -e "${GRN}  sudo m7hunter -u target.com --edrp --resume${NC}"
echo -e "${GRN}  Venv: source ${VENV_DIR}/bin/activate${NC}"
echo -e "${GRN}═══════════════════════════════════════════════${NC}"
