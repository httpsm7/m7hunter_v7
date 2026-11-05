#!/usr/bin/env python3
# core/installer.py — Tool Installer + Pre-flight Check
# MilkyWay Intelligence | Author: Sharlix

import os, shutil, subprocess

EXTRA_PATHS = [
    "/usr/bin", "/usr/local/bin", "/usr/local/go/bin",
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/snap/bin",
]

TOOLS = {
    # Go tools
    "subfinder"     : ("subfinder",      "go",  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx"         : ("httpx",          "go",  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "nuclei"        : ("nuclei",         "go",  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "naabu"         : ("naabu",          "go",  "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "dnsx"          : ("dnsx",           "go",  "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "katana"        : ("katana",         "go",  "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    "dalfox"        : ("dalfox",         "go",  "go install github.com/hahwul/dalfox/v2@latest"),
    "hakrawler"     : ("hakrawler",      "go",  "go install github.com/hakluke/hakrawler@latest"),
    "waybackurls"   : ("waybackurls",    "go",  "go install github.com/tomnomnom/waybackurls@latest"),
    "gau"           : ("gau",            "go",  "go install github.com/lc/gau/v2/cmd/gau@latest"),
    "subzy"         : ("subzy",          "go",  "go install github.com/PentestPanic/subzy@latest"),
    "gf"            : ("gf",             "go",  "go install github.com/tomnomnom/gf@latest"),
    "anew"          : ("anew",           "go",  "go install github.com/tomnomnom/anew@latest"),
    "gowitness"     : ("gowitness",      "go",  "go install github.com/sensepost/gowitness@latest"),
    "ffuf"          : ("ffuf",           "go",  "go install github.com/ffuf/ffuf/v2@latest"),
    "kxss"          : ("kxss",           "go",  "go install github.com/Emoe/kxss@latest"),
    "trufflehog"    : ("trufflehog",     "go",  "go install github.com/trufflesecurity/trufflehog/v3@latest"),
    "qsreplace"     : ("qsreplace",      "go",  "go install github.com/tomnomnom/qsreplace@latest"),
    "gospider"      : ("gospider",       "go",  "go install github.com/jaeles-project/gospider@latest"),
    "notify"        : ("notify",         "go",  "go install github.com/projectdiscovery/notify/cmd/notify@latest"),
    "interactsh"    : ("interactsh-client","go","go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    # Python tools
    "arjun"         : ("arjun",          "pip", "pip3 install arjun --break-system-packages"),
    "cloud_enum"    : ("cloud_enum",     "pip", "pip3 install cloud-enum --break-system-packages"),
    "wafw00f"       : ("wafw00f",        "pip", "pip3 install wafw00f --break-system-packages"),
    # V7 Python extras
    "httpx_pkg"     : ("httpx",          "pip", "pip3 install 'httpx[http2]' --break-system-packages"),
    "websockets"    : ("websockets",     "pip", "pip3 install websockets --break-system-packages"),
    "playwright"    : ("playwright",     "pip", "pip3 install playwright --break-system-packages && playwright install chromium --with-deps"),
    # APT tools
    "nmap"          : ("nmap",           "apt", "apt-get install -y nmap"),
    "masscan"       : ("masscan",        "apt", "apt-get install -y masscan"),
    "sqlmap"        : ("sqlmap",         "apt", "apt-get install -y sqlmap"),
    "amass"         : ("amass",          "apt", "apt-get install -y amass"),
    "tor"           : ("tor",            "apt", "apt-get install -y tor"),
    "proxychains4"  : ("proxychains4",   "apt", "apt-get install -y proxychains4"),
    "curl"          : ("curl",           "apt", "apt-get install -y curl"),
    "jq"            : ("jq",             "apt", "apt-get install -y jq"),
    "git"           : ("git",            "apt", "apt-get install -y git"),
    # Ruby
    "wpscan"        : ("wpscan",         "gem", "gem install wpscan"),
}

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"
C = "\033[96m"; W = "\033[97m"; RST = "\033[0m"

SKIP_CHECK = {"httpx_pkg", "websockets", "playwright"}


class ToolInstaller:
    def __init__(self, log):
        self.log = log

    def _found(self, cmd: str) -> bool:
        if shutil.which(cmd):
            return True
        for d in EXTRA_PATHS:
            full = os.path.join(d, cmd)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                return True
        return False

    def _run(self, cmd: str) -> bool:
        try:
            r = subprocess.run(
                cmd + " >/dev/null 2>&1", shell=True, timeout=300
            )
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def check_only(self):
        self.log.section("Pre-flight Tool Check")
        ok_list, miss_list = [], []
        for name, (binary, _, _) in TOOLS.items():
            if name in SKIP_CHECK:
                continue
            (ok_list if self._found(binary) else miss_list).append(name)
        print(f"  {G}Installed ({len(ok_list)}):{RST} {', '.join(ok_list)}")
        if miss_list:
            print(f"  {Y}Missing  ({len(miss_list)}):{RST} {', '.join(miss_list)}")
            print(f"\n  {C}Run: sudo m7hunter --install{RST}\n")
        else:
            print(f"  {G}All tools ready!{RST}\n")

    def install_all(self):
        self.log.section("M7Hunter V7 — Full Install")
        self._run("apt-get update -qq")
        gobin = os.path.expanduser("~/go/bin")
        os.environ["GOPATH"] = os.path.expanduser("~/go")
        os.environ["PATH"]   = gobin + ":/usr/local/go/bin:" + os.environ.get("PATH", "")
        for name, (binary, method, cmd) in TOOLS.items():
            if name in SKIP_CHECK:
                print(f"  {C}[→]{RST} {name:22s}", end=" ", flush=True)
                ok = self._run(cmd)
                print(f"{G}done{RST}" if ok else f"{Y}skipped{RST}")
                continue
            if self._found(binary):
                print(f"  {G}[✓]{RST} {name:22s} already installed")
                continue
            print(f"  {Y}[↓]{RST} {name:22s}", end=" ", flush=True)
            ok = self._run(cmd)
            print(f"{G}done{RST}" if ok else f"{R}FAILED{RST}")
        self._install_command()
        self.log.success("Done! Run: sudo m7hunter --check")

    def update_all(self):
        self.log.section("Updating Go Tools")
        gobin = os.path.expanduser("~/go/bin")
        os.environ["GOPATH"] = os.path.expanduser("~/go")
        os.environ["PATH"]   = gobin + ":/usr/local/go/bin:" + os.environ.get("PATH", "")
        for name, (binary, method, cmd) in TOOLS.items():
            if method == "go":
                print(f"  {C}[↑]{RST} {name:22s}", end=" ", flush=True)
                ok = self._run(cmd)
                print(f"{G}done{RST}" if ok else f"{R}FAILED{RST}")
        self.log.success("Update complete!")

    def _install_command(self):
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            with open("/usr/local/bin/m7hunter", "w") as f:
                f.write(
                    f'#!/usr/bin/env bash\n'
                    f'exec python3 "{script_dir}/m7hunter.py" "$@"\n'
                )
            os.chmod("/usr/local/bin/m7hunter", 0o755)
            self.log.success("Global command installed: m7hunter")
        except Exception as e:
            self.log.warn(f"Global command failed: {e}")
