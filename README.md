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
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
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

1.  **Autonomous Recon**: Automatically invokes the **Hellhound Spider** for deep reconnaissance, mapping traditional endpoints and SPA routes (Intercepting XHR/Fetch).
2.  **Character Survivability (`FilterAnalyzer`)**: Probes WAF and sanitizer behavior before testing, identifying which characters (`<`, `>`, `'`, `"`, etc.) are blocked, encoded, or passed.
3.  **Runtime Validation (`PlaywrightValidator`)**: Executes high-confidence payloads in a headless Chromium instance. Confirmed triggers are automatically captured as screenshots.
4.  **Confidence Scorer**: A heuristic engine that evaluates findings (0-100) based on reflection quality, execution context, and browser-side signals.

---

## What It Does

X5Sentry maps a web application's attack surface and systematically tests every input point for Cross-Site Scripting. It handles Reflected, Stored, DOM-based, Mutation (mXSS), and Blind XSS vectors.

It prioritizes accuracy over noise by combining static analysis with real browser-side execution. For every high-confidence finding, it produces **visual evidence** in the `./evidence/` directory.

---

## Usage

```bash
xssentry <target> [options]
```

**Testing Options**

| Flag | Default | Description |
|---|---|---|
| `--tier` | `5` | Payload intensity tier (1-6) |
| `--depth`, `-d` | `3` | Maximum crawl depth |
| `--threads`, `-t` | `15` | Concurrent threads |
| `--timeout` | `8` | HTTP timeout per request |
| `--fast` | off | Tier 2 cap, no wordlist fuzz, faster timeout |

**Recon Options**

| Flag | Description |
|---|---|
| `--spider` | Explicitly use Hellhound Spider (default) |
| `--no-spider` | Disable spider and use internal fallback crawler |
| `--spider-json` | Load targets from a previous spider JSON report |
| `--no-crawl` | Test only the provided URL |

**Feature Flags**

| Flag | Description |
|---|---|
| `--no-stored` | Skip stored XSS scan |
| `--no-dom` | Skip DOM XSS static analysis |
| `--no-blind` | Skip blind XSS scan |
| `--no-fuzz` | Skip wordlist parameter fuzzing |

---

## Examples

```bash
# Standard autonomous scan (Spider + XSS Hunt)
xssentry https://target.com

# High-intensity tier 6 scan
xssentry https://target.com --tier 6

# Load discovered endpoints from a spider report
xssentry https://target.com --spider-json report.json

# Fast scan with minimal noise
xssentry https://target.com --fast

# Authenticated scan
xssentry https://target.com --cookie "session=abc123; csrf=xyz"
```

---

## Fallback Engine

If the external spider is unavailable or fails to find endpoints, X5Sentry activates its **Internal Discovery Engine**. This engine has been upgraded in v4.0 to include:
- `robots.txt` and `sitemap.xml` parsing.
- Enhanced JS extraction regex for SPA endpoint discovery.
- Thread-safe parallelized crawling.

---

## Requirements

- Python 3.10+
- `playwright`, `aiohttp`, `beautifulsoup4`, `lxml`
- Chromium (installed automatically via `install.sh`)

---

## Legal

For authorized security testing only. The author is not responsible for misuse.

---

## Author

**Hellhound Security Team**

> Part of the [Hellhound Pentest Framework](https://github.com/project-hellhound).