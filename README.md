<p align="center">
  <img src="Image/sentry.jpeg" alt="X5Sentry" width="600"/>
</p>

<h1 align="center">X5Sentry</h1>

<p align="center">
  Autonomous XSS Hunter — Maps attack surfaces, analyzes character survivability, and validates vulnerabilities through headless browser automation.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-4.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square"/>
</p>

---

## Installation

### Setup Environment

X5Sentry remains stable by running within an isolated virtual environment. The provided installer automates the setup of the venv, dependencies, and global command.

```bash
git clone https://github.com/project-hellhound/x5sentry.git
cd x5sentry
chmod +x install.sh
./install.sh
```

The installer creates a `.venv` and a global symbolic link in `/usr/local/bin/xssentry`. You can now run the tool from **any directory**:

```bash
xssentry https://target.com
```

### Update

To pull the latest changes and refresh your virtual environment:

```bash
./update.sh
```

---

## v4.0 — Tactical Enhancements

The v4.0 release transforms X5Sentry into a professional-grade XSS hunter with high-confidence validation:

1.  **Autonomous Recon**: Automatically invokes the [Hellhound Spider](https://github.com/project-hellhound-org/Hellhound-Spider) for deep reconnaissance, mapping traditional endpoints and SPA routes (Intercepting XHR/Fetch). No manual configuration needed — just provide a target.
2.  **Character Survivability (`FilterAnalyzer`)**: Probes WAF and sanitizer behavior before testing, identifying which characters (`<`, `>`, `'`, `"`, etc.) are blocked, encoded, or passed.
3.  **Runtime Validation (`PlaywrightValidator`)**: Executes high-confidence payloads in a headless Chromium instance. Confirmed triggers are automatically captured as screenshots.
4.  **Confidence Scorer**: A heuristic engine that evaluates findings (0-100) based on reflection quality, execution context, and browser-side signals.
5.  **Live Tactical HUD**: Real-time dashboard showing scan progress, requests sent, and confirmed vulnerabilities as they are found.

---

## What It Does

X5Sentry maps a web application's attack surface and systematically tests every input point for Cross-Site Scripting. It handles Reflected, Stored, DOM-based, Mutation (mXSS), Universal (uXSS), and Blind XSS vectors.

It prioritizes accuracy over noise by combining static analysis with real browser-side execution. For every high-confidence finding, it produces **visual evidence** in the `./evidence/` directory.

The recon phase is fully handled by the integrated [Hellhound Spider](https://github.com/l4zz3rj0d/Hellhound-Spider) — X5Sentry feeds directly from its output with no extra steps required.

---

## Usage

```bash
xssentry <target> [options]
```

**Testing Options**

| Flag | Default | Description |
|---|---|---|
| `-t`, `--threads` | `10` | Concurrent XSS test workers |
| `--timeout` | `8` | HTTP timeout per request (seconds) |
| `--delay` | `0.0` | Delay between requests in seconds |

**Auth Options**

| Flag | Description |
|---|---|
| `--cookie` | Session cookie or Authorization header for authenticated scans |
| `--cookie-port` | Port for the local cookie-catch listener (default: 8765) |
| `--cookie-catcher` | External cookie catcher URL (skips local server) |

**Feature Flags**

| Flag | Description |
|---|---|
| `--no-stored` | Skip stored XSS scan |
| `--no-dom` | Skip DOM XSS static analysis |
| `--no-blind` | Skip blind XSS scan |
| `--no-fuzz` | Skip wordlist parameter fuzzing |
| `--no-cookie-server` | Disable the local cookie-catch listener |

**Output**

| Flag | Description |
|---|---|
| `-o`, `--output` | Save full findings to a JSON report |
| `-v`, `--verbose` | Show verbose spider and test output |

---

## Examples

```bash
# Standard autonomous scan — spider runs automatically
xssentry https://target.com

# Increase concurrent test workers
xssentry https://target.com -t 20

# Authenticated scan
xssentry https://target.com --cookie "session=abc123; csrf=xyz"

# Save results to JSON
xssentry https://target.com -o report.json

# Skip DOM and blind scan for speed
xssentry https://target.com --no-dom --no-blind
```

---

## Recon Engine

X5Sentry integrates the [Hellhound Spider](https://github.com/l4zz3rj0d/Hellhound-Spider) as its sole reconnaissance engine. Crawl depth, concurrency, and JS extraction are managed entirely by the spider — X5Sentry picks up the discovered endpoints and moves straight into testing.

The spider discovery phase includes:
- `robots.txt` and `sitemap.xml` parsing.
- Deep JS extraction for SPA endpoint discovery (REST/XHR/Fetch).
- Automated parameter sniffing and wordlist discovery.

---

## Requirements

- Python 3.10+
- `playwright`, `aiohttp`, `beautifulsoup4`, `lxml`
- Chromium (installed automatically via `install.sh`)

---

For authorized security testing only. This software is licensed under the **GNU General Public License v3 (GPLv3)**.

---

## Authors

<a href="https://github.com/L33TxGH05T">
  <img src="https://img.shields.io/badge/Lead--Developer-L33TxGH05T-1a1a1a?style=for-the-badge" alt="L33TxGH05T"/>
</a>
<a href="https://l4zz3rj0d.github.io">
  <img src="https://img.shields.io/badge/Core--Developer-L4ZZ3RJ0D-c0392b?style=for-the-badge" alt="L4ZZ3RJ0D"/>
</a>
