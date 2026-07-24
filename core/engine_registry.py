#!/usr/bin/env python3
# core/engine_registry.py — Unified Engine Registry
# Blueprint: All engines declare metadata — name, deps, priority, RAM class, tools
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

from dataclasses import dataclass, field
from typing import List, Optional
from core.error_handler import get_handler

@dataclass
class EngineSpec:
    name          : str
    module_path   : str                # e.g. "modules.step01_subdomain"
    class_name    : str                # e.g. "Step01Subdomain"
    dependencies  : List[str] = field(default_factory=list)
    priority      : int   = 50        # 0=highest, 100=lowest
    ram_class     : str   = "medium"  # critical/high/medium/low/minimal
    required_tools: List[str] = field(default_factory=list)
    safe_to_skip  : bool  = False     # can be skipped if tool missing
    requires_lab  : bool  = False     # needs --lab flag
    description   : str   = ""
    stage_group   : str   = "vuln"    # recon/probe/crawl/vuln/report

# ── Default registry — all 27 steps declared ─────────────────────────
DEFAULT_ENGINES: List[EngineSpec] = [
    # Recon group
    EngineSpec("step01_subdomain", "modules.step01_subdomain", "Step01Subdomain",
               dependencies=[], priority=10, ram_class="medium",
               required_tools=["subfinder","dnsx"], stage_group="recon",
               description="Subdomain enumeration — subfinder, amass, alterx, crt.sh"),

    EngineSpec("step02_dns", "modules.step02_dns", "Step02Dns",
               dependencies=["step01_subdomain"], priority=11, ram_class="low",
               required_tools=["dnsx","dig"], stage_group="recon",
               description="DNS resolution, wildcard detect, zone transfer, CNAME chain"),

    EngineSpec("step03_probe", "modules.step03_probe", "Step03Probe",
               dependencies=["step02_dns"], priority=12, ram_class="low",
               required_tools=["httpx"], stage_group="probe",
               description="HTTP probing — live host fingerprinting"),

    EngineSpec("step04_ports", "modules.step04_ports", "Step04Ports",
               dependencies=["step02_dns"], priority=13, ram_class="medium",
               required_tools=["nmap","naabu"], stage_group="probe",
               description="Port/service discovery"),

    EngineSpec("step05_crawl", "modules.step05_crawl", "Step05Crawl",
               dependencies=["step03_probe"], priority=20, ram_class="high",
               required_tools=["katana","gau","waybackurls"], stage_group="crawl",
               description="URL crawling — JS/API endpoint discovery"),

    EngineSpec("step06_nuclei", "modules.step06_nuclei", "Step06Nuclei",
               dependencies=["step03_probe"], priority=25, ram_class="high",
               required_tools=["nuclei"], stage_group="vuln",
               description="Template-based vulnerability scanning"),

    # Vuln group
    EngineSpec("step07_xss", "modules.step07_xss", "Step07Xss",
               dependencies=["step05_crawl"], priority=30, ram_class="medium",
               required_tools=["dalfox","kxss"], stage_group="vuln",
               description="XSS — reflected, DOM, stored, blind"),

    EngineSpec("step08_sqli", "modules.step08_sqli", "SQLiStep",
               dependencies=["step05_crawl"], priority=30, ram_class="medium",
               required_tools=["gf"], stage_group="vuln",
               description="SQLi — internal time-based, union, error-based, OOB"),

    EngineSpec("step09_cors", "modules.step09_cors", "Step09Cors",
               dependencies=["step03_probe"], priority=32, ram_class="low",
               stage_group="vuln", description="CORS misconfiguration"),

    EngineSpec("step10_lfi", "modules.step10_lfi", "LFIStep",
               dependencies=["step05_crawl"], priority=31, ram_class="low",
               stage_group="vuln", description="LFI — 326 payloads, WAF bypass"),

    EngineSpec("step11_ssrf", "modules.step11_ssrf", "SSRFStep",
               dependencies=["step05_crawl"], priority=30, ram_class="medium",
               stage_group="vuln", description="SSRF — cloud metadata, blind OOB"),

    EngineSpec("step12_redirect", "modules.step12_redirect", "Step12Redirect",
               dependencies=["step05_crawl"], priority=35, ram_class="low",
               stage_group="vuln", description="Open redirect detection"),

    EngineSpec("step13_takeover", "modules.step13_takeover", "Step13Takeover",
               dependencies=["step02_dns"], priority=33, ram_class="low",
               required_tools=["subzy"], stage_group="vuln",
               description="Subdomain takeover"),

    EngineSpec("step14_screenshot", "modules.step14_screenshot", "Step14Screenshot",
               dependencies=["step03_probe"], priority=60, ram_class="critical",
               required_tools=["gowitness"], safe_to_skip=True, stage_group="report",
               description="Screenshots — Playwright/gowitness"),

    EngineSpec("step15_wpscan", "modules.step15_wpscan", "Step15Wpscan",
               dependencies=["step03_probe"], priority=40, ram_class="medium",
               required_tools=["wpscan"], safe_to_skip=True, stage_group="vuln",
               description="WordPress vulnerability scan"),

    EngineSpec("step16_github", "modules.step16_github", "GitHubDorkStep",
               dependencies=[], priority=15, ram_class="low",
               required_tools=["trufflehog"], stage_group="recon",
               description="GitHub secret scanning"),

    EngineSpec("step17_cloud", "modules.step17_cloud", "CloudEnumStep",
               dependencies=["step02_dns"], priority=28, ram_class="medium",
               stage_group="vuln", description="Cloud — S3, Lambda, K8s, Firebase"),

    EngineSpec("step18_ssti", "modules.step18_ssti", "Step18Ssti",
               dependencies=["step05_crawl"], priority=31, ram_class="low",
               stage_group="vuln", description="SSTI — math expression payloads"),

    EngineSpec("step19_jwt", "modules.step19_jwt", "Step19Jwt",
               dependencies=["step05_crawl"], priority=32, ram_class="low",
               stage_group="vuln", description="JWT — weak secret, none-algo, confusion"),

    EngineSpec("step20_graphql", "modules.step20_graphql", "Step20Graphql",
               dependencies=["step03_probe"], priority=33, ram_class="medium",
               stage_group="vuln", description="GraphQL — injection, batching, depth DoS"),

    EngineSpec("step21_host_header", "modules.step21_host_header", "Step21HostHeader",
               dependencies=["step03_probe"], priority=35, ram_class="low",
               stage_group="vuln", description="Host header injection"),

    EngineSpec("step22_idor", "modules.step22_idor", "IDORStep",
               dependencies=["step05_crawl"], priority=30, ram_class="medium",
               stage_group="vuln", description="IDOR/BOLA detection"),

    EngineSpec("step23_xxe", "modules.step23_xxe", "Step23Xxe",
               dependencies=["step05_crawl"], priority=32, ram_class="low",
               stage_group="vuln", description="XXE injection"),

    EngineSpec("step24_smuggling", "modules.step24_smuggling", "SmugglingStep",
               dependencies=["step03_probe"], priority=35, ram_class="medium",
               stage_group="vuln", description="HTTP smuggling — CL.TE, TE.CL, H2.CL, h2c"),

    EngineSpec("step25_csrf", "modules.step25_csrf", "CSRFStep",
               dependencies=["step05_crawl"], priority=36, ram_class="low",
               stage_group="vuln", description="CSRF — token check, SameSite audit"),

    EngineSpec("step26_race", "modules.step26_race", "Step26Race",
               dependencies=["step05_crawl"], priority=37, ram_class="medium",
               stage_group="vuln", description="Race condition — async HTTP/2 burst"),

    EngineSpec("step27_nosql", "modules.step27_nosql", "NoSQLStep",
               dependencies=["step05_crawl"], priority=31, ram_class="low",
               stage_group="vuln", description="NoSQL injection — Mongo, Redis, Couch"),

    # Plugin group (behind --lab)
    EngineSpec("plugin_2fa_bypass", "plugins.plugin_2fa_bypass", "Plugin2FABypass",
               dependencies=["step05_crawl"], priority=50, ram_class="low",
               requires_lab=True, stage_group="vuln",
               description="2FA bypass testing (--lab required)"),

    EngineSpec("plugin_saml_bypass", "plugins.plugin_saml_bypass", "PluginSAMLBypass",
               dependencies=["step03_probe"], priority=50, ram_class="low",
               requires_lab=True, stage_group="vuln",
               description="SAML bypass testing (--lab required)"),
]

class EngineRegistry:
    """
    Blueprint: Unified engine registry.
    All scanning logic lives behind a unified interface.
    Scheduler queries this to get dep graph, RAM cost, required tools.
    """

    def __init__(self):
        self._engines: dict[str, EngineSpec] = {}
        for spec in DEFAULT_ENGINES:
            self._engines[spec.name] = spec

    def register(self, spec: EngineSpec):
        self._engines[spec.name] = spec

    def get(self, name: str) -> Optional[EngineSpec]:
        return self._engines.get(name)

    def all(self) -> List[EngineSpec]:
        return list(self._engines.values())

    def get_by_group(self, group: str) -> List[EngineSpec]:
        return [e for e in self._engines.values() if e.stage_group == group]

    def dependency_graph(self) -> dict[str, List[str]]:
        """Return {name: [dep1, dep2]} for all registered engines."""
        return {name: spec.dependencies for name, spec in self._engines.items()}

    def topological_order(self, names: List[str] = None) -> List[str]:
        """
        Return engines in dependency-respecting execution order.
        Blueprint: DAG-based stage ordering.
        """
        nodes = names or list(self._engines.keys())
        graph = {n: [d for d in self._engines[n].dependencies if d in self._engines]
                 for n in nodes if n in self._engines}

        # Kahn's algorithm
        in_degree = {n: 0 for n in graph}
        for n, deps in graph.items():
            for d in deps:
                if d in in_degree:
                    in_degree[d] = in_degree.get(d, 0)
            in_degree[n] = len([d for d in deps if d in graph])

        queue  = sorted([n for n,d in in_degree.items() if d==0],
                        key=lambda x: self._engines[x].priority if x in self._engines else 50)
        result = []
        while queue:
            node = queue.pop(0)
            result.append(node)
            for n in graph:
                if node in graph[n]:
                    in_degree[n] -= 1
                    if in_degree[n] == 0:
                        queue.append(n)
                        queue.sort(key=lambda x: self._engines[x].priority if x in self._engines else 50)

        # Add any remaining (cycles or missed)
        for n in nodes:
            if n not in result:
                result.append(n)
        return result

    def check_tools(self, name: str) -> tuple[bool, List[str]]:
        """Check if all required tools for an engine are available."""
        import shutil
        spec = self._engines.get(name)
        if not spec: return True, []
        missing = [t for t in spec.required_tools if not shutil.which(t)]
        return len(missing) == 0, missing

    def available_engines(self, lab: bool = False) -> List[str]:
        """Return engines whose required tools are present."""
        result = []
        for name, spec in self._engines.items():
            if spec.requires_lab and not lab:
                continue
            ok, _ = self.check_tools(name)
            if ok or spec.safe_to_skip:
                result.append(name)
        return result

    def instantiate(self, name: str, pipeline) -> Optional[object]:
        """Dynamically import and instantiate an engine class."""
        spec = self._engines.get(name)
        if not spec: return None
        try:
            import importlib
            mod = importlib.import_module(spec.module_path)
            cls = getattr(mod, spec.class_name)
            return cls(pipeline)
        except Exception as e:
            get_handler().capture("engine_registry", e, f"instantiate:{name}")
            return None

# Module-level singleton
_registry: Optional[EngineRegistry] = None
def get_registry() -> EngineRegistry:
    global _registry
    if _registry is None:
        _registry = EngineRegistry()
    return _registry
