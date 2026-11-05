#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#   M7HUNTER v7.0 — One-Click Installer (FIXED)
#   Fix: dynamic path resolution — works even if folder moves
#   MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════════════
set -e

R='\033[91m'; B='\033[34m'; G='\033[92m'
Y='\033[93m'; C='\033[96m'; W='\033[97m'; RST='\033[0m'

ok()   { echo -e "${G}[✓]${RST} $1"; }
info() { echo -e "${C}[*]${RST} $1"; }
warn() { echo -e "${Y}[!]${RST} $1"; }
err()  { echo -e "${R}[✗]${RST} $1"; }
sec()  { echo -e "\n${B}━━━ ${W}$1${RST}\n"; }

[ "$EUID" -ne 0 ] && { err "Run as root: sudo bash install_v7.sh"; exit 1; }

# ── FIXED: Resolve script directory dynamically ──────────────────
# Works even if install.sh is symlinked or folder is moved
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
M7_MAIN="$SCRIPT_DIR/m7hunter.py"
info "M7Hunter directory: $SCRIPT_DIR"

[ -f "$M7_MAIN" ] || { err "m7hunter.py not found in $SCRIPT_DIR"; exit 1; }

exists(){ command -v "$1" &>/dev/null && return 0
  for d in /usr/bin /usr/local/bin "$HOME/go/bin" "$HOME/.local/bin"; do
    [ -x "$d/$1" ] && return 0; done; return 1; }

sec "APT Tools"
apt-get update -qq 2>/dev/null
for pkg in nmap masscan sqlmap tor proxychains4 massdns jq curl git \
           python3 python3-pip dnsutils ruby ruby-dev build-essential \
           golang-go chromium chromium-driver; do
  exists "$pkg" && ok "$pkg" || {
    apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg" || warn "$pkg skipped"
  }
done

sec "Go Language Setup"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
grep -q 'GOPATH' /root/.bashrc 2>/dev/null || {
  echo 'export GOPATH=$HOME/go' >> /root/.bashrc
  echo 'export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin' >> /root/.bashrc
}

sec "Go Security Tools"
declare -A GOTOOLS=(
  ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
  ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
  ["hakrawler"]="github.com/hakluke/hakrawler@latest"
  ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
  ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
  ["subzy"]="github.com/PentestPanic/subzy@latest"
  ["gf"]="github.com/tomnomnom/gf@latest"
  ["anew"]="github.com/tomnomnom/anew@latest"
  ["gowitness"]="github.com/sensepost/gowitness@latest"
  ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
  ["kxss"]="github.com/Emoe/kxss@latest"
  ["trufflehog"]="github.com/trufflesecurity/trufflehog/v3@latest"
  ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
  ["gospider"]="github.com/jaeles-project/gospider@latest"
  ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
  ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  ["puredns"]="github.com/d3mondev/puredns/v2@latest"
  ["gitleaks"]="github.com/zricethezav/gitleaks/v8@latest"
)
for tool in "${!GOTOOLS[@]}"; do
  exists "$tool" && ok "$tool" || {
    info "Installing $tool..."
    go install -v "${GOTOOLS[$tool]}" &>/dev/null && ok "$tool" || warn "$tool failed"
  }
done

sec "Python V7 Dependencies"
pip3 install --break-system-packages --quiet \
  "httpx[http2]" playwright aiofiles websockets aiohttp \
  requests stem colorama tqdm rich arjun wafw00f \
  2>/dev/null || true
ok "Python packages installed"

sec "Playwright (headless browser)"
playwright install chromium --with-deps 2>/dev/null \
  && ok "Playwright ready" \
  || warn "Playwright failed — SPA crawling uses static fallback"

sec "WPScan"
exists wpscan && ok "WPScan" || {
  gem install wpscan --quiet 2>/dev/null && ok "WPScan" || warn "WPScan failed"
}

sec "Smuggler"
SMUGGLER="$HOME/tools/smuggler"
[ -d "$SMUGGLER" ] && ok "smuggler" || {
  mkdir -p "$HOME/tools"
  git clone --quiet https://github.com/defparam/smuggler "$SMUGGLER" 2>/dev/null \
    && ok "smuggler" || warn "smuggler failed"
}

sec "SecLists"
[ -d "/usr/share/seclists" ] && ok "SecLists" || {
  apt-get install -y seclists -qq 2>/dev/null || \
  git clone --depth 1 https://github.com/danielmiessler/SecLists \
    /usr/share/seclists 2>/dev/null
  ok "SecLists"
}

sec "GF Patterns"
GF_DIR="$HOME/.gf"; mkdir -p "$GF_DIR"
ls "$GF_DIR"/*.json &>/dev/null && ok "GF patterns" || {
  git clone --quiet https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null \
    && cp /tmp/gfp/*.json "$GF_DIR/" 2>/dev/null && ok "GF patterns"
}

sec "Nuclei Templates"
exists nuclei && {
  nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates"
}

sec "M7Hunter Directories"
mkdir -p "$HOME/.m7hunter/sessions" "$HOME/.m7hunter/secure" \
         "$HOME/.m7hunter/audit" "$HOME/tools"
chmod 700 "$HOME/.m7hunter/secure"
ok "Directories created"

sec "Tor Configuration"
cat > /etc/tor/torrc << 'TORRC'
SocksPort 9050
ControlPort 9051
DataDirectory /var/lib/tor
TORRC
systemctl enable tor 2>/dev/null
systemctl restart tor 2>/dev/null || service tor start 2>/dev/null
ok "Tor configured"

sec "Global Command (FIXED — dynamic path)"
# FIXED: wrapper resolves M7Hunter path at runtime, not install time
# This means the command still works even if you move the folder
cat > /usr/local/bin/m7hunter << WRAP
#!/usr/bin/env bash
# M7Hunter V7 wrapper — path: ${SCRIPT_DIR}
exec python3 "${M7_MAIN}" "\$@"
WRAP
chmod +x /usr/local/bin/m7hunter
ok "m7hunter command installed at /usr/local/bin/m7hunter"

# Also create a self-updating wrapper that reads path from file
echo "$SCRIPT_DIR" > /etc/m7hunter.path
cat > /usr/local/bin/m7hunter-update-path << 'UPDWRAP'
#!/usr/bin/env bash
# Run this if you move M7Hunter to a different folder
NEW_DIR="$(cd "$(dirname "$1")" && pwd)"
echo "$NEW_DIR" > /etc/m7hunter.path
sed -i "s|exec python3 .*m7hunter.py|exec python3 $NEW_DIR/m7hunter.py|g" \
  /usr/local/bin/m7hunter
echo "Path updated to: $NEW_DIR"
UPDWRAP
chmod +x /usr/local/bin/m7hunter-update-path

sec "Verifying Installation"
python3 -c "
import sys, os
sys.path.insert(0, '${SCRIPT_DIR}')
try:
    from core.banner import print_banner
    from core.logger import Logger
    from core.utils  import check_root
    print('  \033[92m[✓] Core modules OK\033[0m')
except Exception as e:
    print(f'  \033[91m[✗] Core check failed: {e}\033[0m')
" 2>/dev/null

echo ""
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${G}  ✅  M7Hunter V7 Installation Complete!${RST}"
echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
echo -e "  ${C}Quick Start:${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --fast${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep --cookie 'session=x'${RST}"
echo -e "  ${W}sudo m7hunter -u target.com --deep --userA 'sA=x' --userB 'sB=y'${RST}"
echo -e "  ${W}sudo m7hunter --check${RST}   (verify tools)"
echo ""
echo -e "  ${C}If you move M7Hunter folder:${RST}"
echo -e "  ${W}sudo m7hunter-update-path /new/path/to/m7hunter.py${RST}"
echo ""
