#!/usr/bin/env python3
# modules/step42_dependency_confusion.py — Dependency Confusion Attack Detection
# NEW MODULE — Cycle 9
# Source: Bug Hunter Methodology — supply chain attack detection
# Detects private package names that could be squatted on public registries
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, json, urllib.request, urllib.error, urllib.parse
from core.utils import safe_read

# Package registry APIs
NPM_REGISTRY    = "https://registry.npmjs.org/{package}"
PYPI_REGISTRY   = "https://pypi.org/pypi/{package}/json"
RUBYGEMS_API    = "https://rubygems.org/api/v1/gems/{package}.json"
NUGET_API       = "https://api.nuget.org/v3/registration5/{package}/index.json"

# Common private package name patterns
PRIVATE_INDICATORS = [
    re.compile(r'@[a-z0-9_\-]+/[a-z0-9_\-]+'),         # @scope/package
    re.compile(r'internal[-_]?[a-z0-9_\-]+'),            # internal-utils
    re.compile(r'private[-_]?[a-z0-9_\-]+'),             # private-lib
    re.compile(r'[a-z0-9_\-]+-internal'),                 # app-internal
    re.compile(r'[a-z0-9_\-]+-private'),                  # app-private
    re.compile(r'corp[-_]?[a-z0-9_\-]+'),                # corp-tools
    re.compile(r'[a-z0-9_\-]+-corp'),                     # utils-corp
]

# Files that reveal package dependencies
PACKAGE_FILES = [
    "/package.json",        "/package-lock.json",
    "/yarn.lock",           "/requirements.txt",
    "/Pipfile",             "/Pipfile.lock",
    "/Gemfile",             "/Gemfile.lock",
    "/.npmrc",              "/setup.py",
    "/pyproject.toml",      "/composer.json",
    "/pom.xml",             "/.packages.config",
    "/go.mod",              "/go.sum",
    "/.github/workflows/",  "/Makefile",
    "/docker-compose.yml",  "/Dockerfile",
]

# Source map files (reveal package names)
SOURCE_MAPS = [
    "/static/js/main.js.map",
    "/assets/js/app.js.map",
    "/bundle.js.map",
    "/js/main.js.map",
    "/dist/bundle.js.map",
]


class Step42DependencyConfusion:
    """
    Dependency Confusion Detection.
    Bug Hunter Methodology — supply chain attack:
    1. Find package.json / requirements.txt exposed on target
    2. Extract private package names
    3. Check if same name exists on public registry (npm/pypi/gems)
    4. If NOT on public registry → can be squatted → dependency confusion
    5. Check source maps for internal package names
    """

    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files.get("depcf_results",
                             f"{p.out}/{p.prefix}_dep_confusion.txt")
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("DepConfusion: no live hosts"); return

        p.log.info(f"Dependency Confusion V7: {len(live)} hosts")

        for host in live[:5]:
            host = host.rstrip("/")

            # Phase 1: Find exposed package files
            r = self._find_package_files(host, out)
            found += r

            # Phase 2: Check source maps
            r = self._check_source_maps(host, out)
            found += r

            # Phase 3: Check GitHub actions / CI files
            r = self._check_ci_files(host, out)
            found += r

            self.p.bypass.jitter()

        # Phase 4: Analyze any found package names from JS files
        js_f = p.files.get("js_files","")
        r = self._analyze_js_imports(js_f, out)
        found += r

        p.log.success(f"Dependency Confusion V7: {found} findings")

    # ── Phase 1: Exposed package files ────────────────────────────────────────
    def _find_package_files(self, host: str, out: str) -> int:
        found = 0
        for path in PACKAGE_FILES:
            url  = host + path
            resp = self._fetch(url)
            if not resp or resp.get("status",0) != 200:
                continue
            body = resp.get("body","")
            if len(body) < 10: continue

            # Parse packages
            packages = self._extract_packages(body, path)
            if not packages: continue

            p.log.info = self.p.log.info
            self.p.log.info(f"  Package file: {url} ({len(packages)} deps)")

            # Check each package against public registries
            private_pkgs = []
            for pkg_name, pkg_version in packages[:30]:
                if self._is_private_name(pkg_name):
                    # Check if exists on public registry
                    exists = self._check_public_registry(pkg_name, path)
                    if not exists:
                        private_pkgs.append((pkg_name, pkg_version))
                        detail = (f"Dependency Confusion: '{pkg_name}@{pkg_version}' "
                                  f"appears private but NOT on public registry — "
                                  f"can be squatted! Source: {path}")
                        self._save(out,"critical","DEP_CONFUSION",url,detail)
                        found += 1

            if private_pkgs:
                self.p.log.info(
                    f"  ⚠️  {len(private_pkgs)} potentially injectable packages")

            # Even if not injectable, exposed package.json is info leak
            if packages and not private_pkgs:
                detail = (f"Package file exposed: {path} reveals "
                          f"{len(packages)} dependencies")
                self._save(out,"low","PACKAGE_FILE_EXPOSED",url,detail)
        return found

    # ── Phase 2: Source maps ──────────────────────────────────────────────────
    def _check_source_maps(self, host: str, out: str) -> int:
        found = 0
        for path in SOURCE_MAPS:
            url  = host + path
            resp = self._fetch(url)
            if not resp or resp.get("status",0) != 200:
                continue
            body = resp.get("body","")
            try:
                data    = json.loads(body)
                sources = data.get("sources",[])

                # Extract node_modules package names from sources
                pkg_re = re.compile(r'node_modules/([^/]+)')
                pkgs   = set()
                for src in sources:
                    m = pkg_re.search(src)
                    if m: pkgs.add(m.group(1))

                # Check private-looking packages
                for pkg in pkgs:
                    if self._is_private_name(pkg):
                        exists = self._check_public_registry(pkg, ".js.map")
                        if not exists:
                            detail = (f"Source map dep confusion: '{pkg}' "
                                      f"in {path} not on npm registry")
                            self._save(out,"critical","SOURCEMAP_DEP_CONFUSION",
                                       url, detail)
                            found += 1

                if sources:
                    detail = f"Source map exposed: {path} ({len(sources)} files)"
                    self._save(out,"medium","SOURCEMAP_EXPOSED",url,detail)
                    found += 1

            except Exception:
                pass
        return found

    # ── Phase 3: CI/GitHub Actions ────────────────────────────────────────────
    def _check_ci_files(self, host: str, out: str) -> int:
        found = 0
        ci_paths = [
            "/.github/workflows/deploy.yml",
            "/.github/workflows/ci.yml",
            "/Jenkinsfile",
            "/.circleci/config.yml",
            "/.gitlab-ci.yml",
        ]
        for path in ci_paths:
            url  = host + path
            resp = self._fetch(url)
            if not resp or resp.get("status",0) != 200: continue
            body = resp.get("body","")
            if len(body) < 20: continue

            detail = (f"CI/CD file exposed: {path} — "
                      f"reveals deployment process and secrets")
            self._save(out,"high","CI_FILE_EXPOSED",url,detail)
            found += 1

            # Check for secrets in CI file
            secret_re = re.compile(
                r'(?:password|secret|token|key|api_key)\s*[:=]\s*\S+',
                re.I)
            for m in secret_re.finditer(body):
                if "${{" not in m.group(0) and "env." not in m.group(0):
                    detail2 = f"Secret in CI file: {m.group(0)[:60]}"
                    self._save(out,"critical","CI_SECRET_EXPOSED",url,detail2)
                    found += 1
        return found

    # ── Phase 4: JS import analysis ───────────────────────────────────────────
    def _analyze_js_imports(self, js_file: str, out: str) -> int:
        if not js_file: return 0
        found  = 0
        js_urls = safe_read(js_file)[:15]

        import_re = re.compile(
            r'(?:require|import)\s*\(?["\']([^"\'./][^"\']*)["\']',re.I)

        for js_url in js_urls:
            try:
                req  = urllib.request.Request(
                    js_url, headers={"User-Agent": self.p.bypass.ua()})
                resp = urllib.request.urlopen(req, timeout=8)
                js   = resp.read(200000).decode("utf-8","ignore")
            except Exception:
                continue

            for m in import_re.finditer(js):
                pkg = m.group(1).split("/")[0]
                if self._is_private_name(pkg):
                    exists = self._check_public_registry(pkg, ".js")
                    if not exists:
                        detail = (f"JS import dep confusion: '{pkg}' "
                                  f"not on npm — injectable")
                        self._save(out,"critical","JS_DEP_CONFUSION",js_url,detail)
                        found += 1
        return found

    # ── Package extraction ────────────────────────────────────────────────────
    def _extract_packages(self, body: str, path: str) -> list:
        pkgs = []
        if "package.json" in path:
            try:
                data = json.loads(body)
                for section in ["dependencies","devDependencies",
                                 "peerDependencies","optionalDependencies"]:
                    for name, ver in data.get(section,{}).items():
                        pkgs.append((name, str(ver)))
            except Exception:
                pass
        elif "requirements.txt" in path:
            for line in body.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = re.split(r'[>=<!=~]', line, 1)
                    pkgs.append((parts[0].strip(), parts[1].strip() if len(parts)>1 else "*"))
        elif "Gemfile" in path:
            for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"]", body):
                pkgs.append((m.group(1), "*"))
        return pkgs

    def _is_private_name(self, pkg: str) -> bool:
        pkg_lower = pkg.lower()
        for pat in PRIVATE_INDICATORS:
            if pat.search(pkg_lower):
                return True
        # Also check for company/project specific naming
        domain_bare = self.p.target.replace("https://","").replace("http://","").split(".")[0]
        if domain_bare and len(domain_bare) > 2:
            if domain_bare in pkg_lower:
                return True
        return False

    def _check_public_registry(self, pkg: str, source: str) -> bool:
        """Check if package exists on public registry. Returns True if exists."""
        # Determine registry based on source type
        if any(x in source for x in [".js",".json","package"]):
            url = NPM_REGISTRY.format(package=urllib.parse.quote(pkg,safe="@/"))
        elif any(x in source for x in ["requirements","Pipfile",".py"]):
            url = PYPI_REGISTRY.format(package=urllib.parse.quote(pkg))
        elif "Gemfile" in source:
            url = RUBYGEMS_API.format(package=urllib.parse.quote(pkg))
        else:
            url = NPM_REGISTRY.format(package=urllib.parse.quote(pkg,safe="@/"))

        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/7.0"})
            resp = urllib.request.urlopen(req, timeout=8)
            return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code != 404
        except Exception:
            return True  # Assume exists on error (conservative)

    def _fetch(self, url: str) -> dict:
        try:
            req  = urllib.request.Request(
                url, headers={"User-Agent": self.p.bypass.ua()})
            resp = urllib.request.urlopen(req, timeout=8)
            return {"status": resp.status,
                    "body":   resp.read(100000).decode("utf-8","ignore")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "depcf-v7", response=response, payload=payload)
