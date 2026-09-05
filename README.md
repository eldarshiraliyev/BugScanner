<div align="center">

# 🐛 BugScanner

**An Advanced, Context-Aware Recon & Automated Web Vulnerability Assessment Framework**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![GitHub Stars](https://img.shields.io/github/stars/eldarshiraliyev/BugScanner?style=social)](https://github.com/eldarshiraliyev/BugScanner)

[Key Features](#-key-features) •
[Architecture](#-architecture) •
[Installation](#-installation) •
[Usage](#-usage) •
[Configuration](#%EF%B8%8F-configuration) •
[Roadmap](#-roadmap)

</div>

---

## 📌 Overview

**BugScanner** is a modular, high-performance web vulnerability scanner and reconnaissance framework engineered specifically for **Bug Bounty Hunters**, **Red Teams**, and **Penetration Testers**. 

Unlike standard passive scanners, BugScanner combines deep sub-domain discovery, active TCP service fingerprinting, and a **Context-Aware Vulnerability Verification Engine** designed to minimize false positives and bypass modern Web Application Firewalls (WAFs) through adaptive rate limiting and jitter control.

---

## 🔥 Key Features

### 🔍 Phase 1 — Reconnaissance & Discovery
* **Subdomain Enumeration:** Dual-engine discovery using **Certificate Transparency Logs (`crt.sh`)** for passive reconnaissance and **Async DNS Bruteforcing** (200+ wordlist) for active discovery.
* **TCP Port Scanner:** High-speed, asynchronous TCP connect scanning across custom ranges (`common`, `extended`, `full`). Features banner grabbing for service version extraction and security hints.
* **Technology Fingerprinting:** Identifies web servers, CMSs, backend frameworks, and frontend libraries via HTTP Response Headers, HTML DOM patterns, and Session Cookies.
* **Endpoint Discovery:** Async path discovery covering 200+ common administration, API (`/graphql`, `/swagger`), auth, debug, and backup endpoints (`.env`, `.git/HEAD`, `actuator/heapdump`).

### 🛡️ Phase 2 — Vulnerability Assessment Engine
* **Reflected XSS Scanner:** Evaluates parameter reflection in `text/html` contexts with execution-aware payload sets, lowering noise and false positives.
* **SQL Injection (SQLi) Verification:** Integrates Error-Based SQLi checks across 30+ database error patterns and **Time-Based Double-Check Verification** (`SLEEP(3)` vs `SLEEP(6)`) to eliminate network latency false positives.
* **CORS Misconfiguration Auditor:** Identifies wildcard origins, arbitrary origin reflection, and dangerous `Access-Control-Allow-Credentials: true` combinations with auto-generated PoC exploits.
* **SSRF & Open Redirect:** Tests for Cloud Metadata exposure (AWS, GCP) and protocol handler leaks (`file://`), along with location-header redirection validation.
* **JWT Security Auditor:** Automates `alg: none` bypass checks, signature verification, algorithm confusion (RS256 $\rightarrow$ HS256), and weak secret brute-forcing.
* **IDOR & Path Tampering:** Evaluates parameter/path numerical shifts and HTTP Method Swapping (e.g., `DELETE`/`PUT` verb tampering).
* **Sensitive Data Exposure:** Scans responses for leaked AWS keys, Private RSA keys, GitHub/Stripe/Slack tokens, `.git` repository exposures, and Directory Listing.
* **Nuclei Integration:** Seamlessly wraps ProjectDiscovery's `nuclei` engine (if installed) to execute 9000+ CVE and misconfiguration templates directly into the consolidated report.

### ⚡ Resilience & Evasion Capabilities
* **Adaptive Token-Bucket Rate Limiter:** Dynamically adjusts Request Per Second (RPS) upon receiving `429 Too Many Requests` or `503 Service Unavailable`, preventing WAF IP bans.
* **WAF Detection & Jitter Engine:** Detects Cloudflare, Akamai, and AWS WAF signatures to apply randomized delays and stealth payload reductions.
* **Dynamic Reporting:** Generates structured JSON outputs alongside interactive, dark-themed HTML reports featuring CVSS v3.1 severity scores, animated risk metrics, and ready-to-use exploit PoCs.

---

## 🏗 Architecture

BugScanner uses a modular, asynchronous architecture built on top of `asyncio` and `httpx`:

```text
cli.py ──> scanner.py (Orchestrator)
            ├── recon/
            │   ├── subdomain.py         # crt.sh + Async DNS
            │   ├── portscan.py          # TCP Connect & Banner Grab
            │   ├── fingerprint.py       # Headers, DOM & Cookies
            │   └── discovery.py         # Endpoint Bruteforce
            ├── vulns/
            │   ├── xss.py               # Reflected XSS Engine
            │   ├── sqli.py              # Error & Double-Check Time-Based
            │   ├── cors.py              # Origin Reflection & Credentials
            │   ├── ssrf.py              # Metadata & Protocol Leaks
            │   ├── redirect.py          # Open Redirect Auditor
            │   ├── jwt.py               # Alg None, Confusion & Weak Secret
            │   ├── idor.py              # Parameter & Verb Tampering
            │   ├── disclosure.py        # Token & Key RegEx Extractor
            │   └── nuclei_wrapper.py    # Native Nuclei CLI Wrapper
            └── core/
                ├── rate_limiter.py      # Adaptive RPS & Jitter
                ├── http_client.py       # Async HTTP Wrapper
                ├── models.py            # Dataclasses & CVSS Scoring
                └── reporter.py          # JSON & Jinja2 HTML Generator
