#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   M7HUNTER v7.0 — Bug Bounty Automation Framework
#   NEW CLI: -s (session) -a (auth) -j (jwt) -o (scope)
#   MilkyWay Intelligence | Author: Sharlix
# ═══════════════════════════════════════════════════════════

import os, sys, argparse, time, signal

M7_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, M7_DIR)

def _sigint(sig, frame):
    print("\n\033[93m[!] Interrupted — saving checkpoint...\033[0m")
    sys.exit(0)
signal.signal(signal.SIGINT, _sigint)

try:
    from core.banner import print_banner
    from core.logger import Logger
    from core.utils  import check_root
except ImportError as e:
    print(f"\033[91m[✗] Core import failed: {e}\033[0m")
    print(f"\033[93m    cd {M7_DIR} && sudo python3 m7hunter.py --install\033[0m")
    sys.exit(1)


# ══════════════════════════════════════════════════════════
# NEW CLEAN CLI
# ══════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        prog="m7hunter",
        description="M7HUNTER v7.0 — Bug Bounty Automation Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
━━━ EXAMPLES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # Basic deep scan
  sudo m7hunter -u target.com --deep

  # With session cookie
  sudo m7hunter -u target.com --deep -s "session=abc123"

  # With Bearer token (authorization header)
  sudo m7hunter -u target.com --deep -a "eyJhbGciOiJSUzI1NiJ9..."

  # With JWT token (tested separately for JWT attacks)
  sudo m7hunter -u target.com --deep -j "eyJhbGciOiJSUzI1NiJ9..."

  # With session + auth + scope to single domain
  sudo m7hunter -u target.com --deep -s "session=abc" -a "Bearer xyz" -o target.com

  # Multi-session IDOR testing (attacker + victim)
  sudo m7hunter -u target.com --deep --user-a "sA=x" --user-b "sB=y"

  # Fast scan
  sudo m7hunter -u target.com --fast

  # Multiple targets
  sudo m7hunter -f targets.txt --deep -s "session=abc"

  # Check tools
  sudo m7hunter --check

  # Install tools
  sudo m7hunter --install
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # ── Target ───────────────────────────────────────────────────
    inp = p.add_mutually_exclusive_group()
    inp.add_argument("-u", metavar="TARGET",
                     help="Target domain or URL  (e.g. target.com)")
    inp.add_argument("-f", metavar="FILE",
                     help="File with targets, one per line")

    # ── Scan mode ────────────────────────────────────────────────
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--deep",    action="store_true",
                       help="Full scan — all 30 steps (default)")
    modes.add_argument("--fast",    action="store_true",
                       help="Fast scan — recon + nuclei + xss + cors + ssrf")
    modes.add_argument("--stealth", action="store_true",
                       help="Stealth — slow delays + Tor + limited steps")
    modes.add_argument("--custom",  action="store_true",
                       help="Custom — pick steps manually (see step flags)")

    # ── NEW AUTH FLAGS ───────────────────────────────────────────
    auth = p.add_argument_group("Authentication (NEW)")
    auth.add_argument(
        "-s", metavar="COOKIE", dest="session",
        help="Session cookie  e.g. -s 'session=abc123; csrf=xyz'"
    )
    auth.add_argument(
        "-a", metavar="TOKEN", dest="auth",
        help="Authorization token  e.g. -a 'Bearer eyJ...' or just the token"
    )
    auth.add_argument(
        "-j", metavar="JWT", dest="jwt",
        help="JWT token (tested separately for JWT attacks)  e.g. -j 'eyJ...'"
    )
    auth.add_argument(
        "-o", metavar="DOMAIN", dest="scope",
        help="Scope — only test this domain  e.g. -o target.com"
    )

    # ── Multi-session (IDOR) ─────────────────────────────────────
    multi = p.add_argument_group("Multi-Session (IDOR Testing)")
    multi.add_argument("--user-a", metavar="COOKIE", dest="user_a",
                       help="Attacker session cookie")
    multi.add_argument("--user-b", metavar="COOKIE", dest="user_b",
                       help="Victim session cookie")

    # ── Output ───────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("--output", metavar="DIR", default="results",
                     help="Output directory (default: results/)")
    out.add_argument("--no-color", action="store_true",
                     help="Disable colored output")

    # ── Performance ───────────────────────────────────────────────
    perf = p.add_argument_group("Performance")
    perf.add_argument("--threads", metavar="N", type=int, default=50,
                      help="Thread count (default: 50)")
    perf.add_argument("--rate", metavar="N", type=int, default=1000,
                      help="Requests/sec limit (default: 1000)")
    perf.add_argument("--proxy", metavar="URL",
                      help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    perf.add_argument("--tor", action="store_true",
                      help="Route through Tor")
    perf.add_argument("--resume", action="store_true",
                      help="Resume from checkpoint")

    # ── V7 Features ───────────────────────────────────────────────
    v7 = p.add_argument_group("V7 Features")
    v7.add_argument("--confidence", metavar="0.0-1.0",
                    type=float, default=0.8,
                    help="AI confidence threshold (default: 0.8)")
    v7.add_argument("--no-double-verify", action="store_true",
                    dest="no_double_verify",
                    help="Skip double-verification (faster)")
    v7.add_argument("--ollama-model", metavar="MODEL",
                    dest="ollama_model", default="llama3",
                    help="Ollama model (default: llama3)")
    v7.add_argument("--ollama-host", metavar="URL",
                    dest="ollama_host", default="http://localhost:11434",
                    help="Ollama server URL")

    # ── API Keys ──────────────────────────────────────────────────
    keys = p.add_argument_group("API Keys")
    keys.add_argument("--github-token", metavar="TOKEN",
                      dest="github_token",
                      help="GitHub token for secret dorking")
    keys.add_argument("--wpscan-token", metavar="TOKEN",
                      dest="wpscan_token",
                      help="WPScan API token")
    keys.add_argument("--interactsh-url", metavar="URL",
                      dest="interactsh_url",
                      help="Custom Interactsh URL for OOB")

    # ── Notifications ─────────────────────────────────────────────
    notif = p.add_argument_group("Notifications")
    notif.add_argument("--telegram-token", metavar="TOKEN",
                       dest="telegram_token")
    notif.add_argument("--telegram-chat", metavar="ID",
                       dest="telegram_chat")

    # ── Step flags (custom mode) ──────────────────────────────────
    step_grp = p.add_argument_group("Step Flags (use with --custom)")
    STEPS = [
        "subdomain","dns","probe","ports","crawl","nuclei",
        "xss","sqli","cors","lfi","ssrf","redirect","takeover",
        "screenshot","wpscan","github","cloud","ssti","jwt",
        "graphql","host_header","idor","xxe","smuggling","csrf",
        "race","nosql","clickjacking","oauth","open_redirect",
        "ws","proto_pollution","deserialization","param_pollution","file_upload","content","hashcrack","recon_deep","twofa_bypass","business_logic","session_fixation","xss_advanced","password_spray","dep_confusion","cve_exploit","api_security","sop_bypass",
    ]
    for step in STEPS:
        step_grp.add_argument(f"--{step.replace('_','-')}",
                              action="store_true", dest=step)

    # ── Maintenance ───────────────────────────────────────────────
    maint = p.add_argument_group("Maintenance")
    maint.add_argument("--install",   action="store_true",
                       help="Install all required tools")
    maint.add_argument("--update",    action="store_true",
                       help="Update tools to latest")
    maint.add_argument("--check",     action="store_true",
                       help="Check installed tools")
    maint.add_argument("--dashboard", action="store_true",
                       help="Launch web dashboard at localhost:8719")

    return p.parse_args()


# ══════════════════════════════════════════════════════════
# AUTH RESOLVER — unifies -s -a -j into pipeline args
# ══════════════════════════════════════════════════════════
def resolve_auth(args):
    """
    Resolve new auth flags into pipeline-compatible attributes.
    Pipeline reads: args.cookie, args.authorization, args.jwt
    """
    # Multi-session IDOR
    if getattr(args,"user_a",None) and getattr(args,"user_b",None):
        args.cookie   = args.user_a
        args.cookie_b = args.user_b
        args._idor_multi = True
    elif getattr(args,"user_a",None):
        args.cookie = args.user_a

    # -s → cookie (primary session)
    if getattr(args,"session",None) and not getattr(args,"cookie",None):
        args.cookie = args.session

    # -a → authorization header
    if getattr(args,"auth",None):
        tok = args.auth.strip()
        if not tok.lower().startswith("bearer "):
            tok = f"Bearer {tok}"
        args.authorization = tok

    # -j → JWT (stored separately for JWT attack module)
    if getattr(args,"jwt",None):
        args._jwt_token = args.jwt
        # If no auth set, also use JWT as Bearer
        if not getattr(args,"authorization",None):
            args.authorization = f"Bearer {args.jwt}"

    # -o → scope list
    if getattr(args,"scope",None):
        args._scope_domain = args.scope

    return args


# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════
def main():
    check_root()
    print_banner()
    args = parse_args()
    log  = Logger(no_color=getattr(args,"no_color",False))

    # ── Maintenance ───────────────────────────────────────
    if args.install:
        try:
            from core.installer import ToolInstaller
            ToolInstaller(log).install_all()
        except Exception as e:
            log.error(f"Install error: {e}")
        sys.exit(0)

    if args.update:
        try:
            from core.installer import ToolInstaller
            ToolInstaller(log).update_all()
        except Exception as e:
            log.error(f"Update error: {e}")
        sys.exit(0)

    if args.check:
        try:
            from core.installer import ToolInstaller
            ToolInstaller(log).check_only()
        except Exception as e:
            log.error(f"Check error: {e}")
        sys.exit(0)

    if args.dashboard and not args.u and not args.f:
        try:
            from web.dashboard import Dashboard
            Dashboard(log=log, port=8719,
                      results_dir=args.output).start(blocking=True)
        except ImportError:
            log.warn("Dashboard module not available")
        sys.exit(0)

    # ── Validate target ───────────────────────────────────
    if not args.u and not args.f:
        log.error("No target specified!")
        log.info("Usage: sudo m7hunter -u target.com --deep")
        log.info("       sudo m7hunter -u target.com --deep -s 'session=abc'")
        log.info("Help:  sudo m7hunter --help")
        sys.exit(1)

    # ── Resolve auth ──────────────────────────────────────
    args = resolve_auth(args)

    # Log auth state
    auth_parts = []
    if getattr(args,"cookie",None):     auth_parts.append("Cookie/Session ✅")
    if getattr(args,"authorization",None): auth_parts.append("Authorization ✅")
    if getattr(args,"_jwt_token",None): auth_parts.append("JWT ✅")
    if auth_parts:
        log.success(f"Auth: {' | '.join(auth_parts)}")
    else:
        log.warn("No auth provided — unauthenticated scan only")
        log.warn("Use -s 'session=...' for authenticated testing")

    # ── Stealth implies Tor ───────────────────────────────
    if getattr(args,"stealth",False):
        args.tor = True

    # ── CEO rules ─────────────────────────────────────────
    ceo_rules = {}
    if getattr(args,"no_double_verify",False):
        ceo_rules["double_verify"] = False
    if getattr(args,"stealth",False):
        ceo_rules["stealth_min_delay_ms"] = 5000

    # ── Ollama env ────────────────────────────────────────
    if getattr(args,"ollama_host",None):
        os.environ["OLLAMA_HOST"] = args.ollama_host
    if getattr(args,"ollama_model",None):
        os.environ["M7_OLLAMA_MODEL"] = args.ollama_model

    # ── Tool check (non-blocking) ─────────────────────────
    try:
        from core.installer import ToolInstaller
        ToolInstaller(log).check_only()
    except Exception:
        pass

    # ── Optional components ───────────────────────────────
    tor = None
    if getattr(args,"tor",False):
        try:
            from core.tor_manager import TorManager
            tor = TorManager(log); tor.start()
        except Exception as e:
            log.warn(f"Tor unavailable: {e}")

    oob = None
    try:
        from engines.interactsh import InteractshClient
        oob = InteractshClient(
            custom_url=getattr(args,"interactsh_url",None), log=log)
        oob.start()
    except Exception:
        pass

    offline_ai = None
    try:
        from ai.offline_ai import OfflineAI
        offline_ai = OfflineAI(log=log)
    except Exception:
        pass

    notifier = None
    tg_tok  = getattr(args,"telegram_token",None)
    tg_chat = getattr(args,"telegram_chat",None)
    if tg_tok and tg_chat:
        try:
            from core.notifier import Notifier
            notifier = Notifier(telegram_token=tg_tok,
                                telegram_chat=tg_chat, log=log)
        except Exception:
            pass

    # ── Load targets ──────────────────────────────────────
    targets = []
    if args.u:
        raw = args.u.strip()
        if not raw.startswith(("http://","https://")):
            raw = "https://" + raw
        targets = [raw]
    elif args.f:
        if not os.path.isfile(args.f):
            log.error(f"File not found: {args.f}"); sys.exit(1)
        with open(args.f) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith(("http://","https://")):
                        line = "https://" + line
                    targets.append(line)

    if not targets:
        log.error("No valid targets found"); sys.exit(1)

    # ── Scope list ────────────────────────────────────────
    scope_list = []
    scope_domain = getattr(args,"_scope_domain",None)
    if scope_domain:
        scope_list = [scope_domain]
        log.info(f"Scope restricted to: {scope_domain}")

    log.success(f"Loaded {len(targets)} target(s)")

    # ── Run pipeline ──────────────────────────────────────
    def run_targets():
        try:
            from core.pipeline_v7 import PipelineV7
        except ImportError as e:
            log.error(f"Pipeline import failed: {e}")
            log.error("Run: sudo m7hunter --install")
            sys.exit(1)

        reports = []
        for i, target in enumerate(targets, 1):
            log.section(f"TARGET {i}/{len(targets)}: {target}")
            try:
                pipeline = PipelineV7(
                    target=target, args=args,
                    tor=tor, oob=oob, notifier=notifier,
                    log=log, scope_list=scope_list,
                    offline_ai=offline_ai,
                    confidence_threshold=args.confidence,
                    ceo_rules=ceo_rules,
                )
                report = pipeline.run()
                if report: reports.append(report)
            except KeyboardInterrupt:
                log.warn(f"[{target}] Interrupted"); break
            except Exception as e:
                log.error(f"[{target}] Error: {e}")
                import traceback; traceback.print_exc()
        return reports

    reports = run_targets()

    # ── Cleanup ───────────────────────────────────────────
    log.section("COMPLETE")
    for r in reports:
        log.success(f"Report → {r}")
    try:
        if oob: oob.stop()
        if tor: tor.stop()
    except Exception:
        pass


if __name__ == "__main__":
    main()
