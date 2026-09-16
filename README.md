<div align="center">

<h1>🐛 BugScanner</h1>

<p><strong>An Advanced, Context-Aware Recon &amp; Automated Web Vulnerability Assessment Framework</strong></p>

<p>
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python Version"></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
<a href="http://makeapullrequest.com"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
<a href="https://github.com/eldarshiraliyev/BugScanner"><img src="https://img.shields.io/github/stars/eldarshiraliyev/BugScanner?style=social" alt="GitHub Stars"></a>
<a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"></a>
<a href="https://github.com/eldarshiraliyev/BugScanner/actions"><img src="https://img.shields.io/badge/tests-35%20passing-brightgreen.svg" alt="Tests"></a>
</p>

<p>
<a href="#-overview">Overview</a> •
<a href="#-key-features">Features</a> •
<a href="#-architecture">Architecture</a> •
<a href="#-installation">Installation</a> •
<a href="#-usage">Usage</a> •
<a href="#-false-positive-reduction-engine">FP Engine</a> •
<a href="#-report-preview">Report</a> •
<a href="#-configuration">Configuration</a> •
<a href="#-testing">Testing</a> •
<a href="#-docker-deployment">Docker</a> •
<a href="#-roadmap">Roadmap</a>
</p>

</div>

<hr>

<h2>📌 Overview</h2>

<p><strong>BugScanner</strong> is a modular, high-performance web vulnerability scanner and reconnaissance framework engineered specifically for <strong>Bug Bounty Hunters</strong>, <strong>Red Teams</strong>, and <strong>Penetration Testers</strong>.</p>

<p>Unlike standard passive scanners, BugScanner combines <strong>deep subdomain discovery</strong>, <strong>active TCP service fingerprinting</strong>, and a <strong>Context-Aware Vulnerability Verification Engine</strong> designed to minimize false positives (by ~80%) and bypass modern Web Application Firewalls (WAFs) through adaptive rate limiting and jitter control.</p>

<p>The framework is built entirely on <code>asyncio</code> and <code>httpx</code> for maximum concurrency, with a modern React + FastAPI web dashboard for real-time scan monitoring.</p>

<h3>🎯 Highlights</h3>

<ul>
<li><strong>9+ Vulnerability Modules</strong> — XSS, SQLi (error + time-based), CORS, SSRF, Open Redirect, JWT, IDOR, Information Disclosure, Business Logic</li>
<li><strong>False-Positive Reduction Engine</strong> — 5-rule verification pipeline eliminating ~80% of noise</li>
<li><strong>SPA-Aware Scanning</strong> — Detects Single Page Application fallbacks to eliminate fake findings</li>
<li><strong>WAF Evasion</strong> — Detects Cloudflare, Akamai, AWS WAF, Imperva and adapts strategies</li>
<li><strong>Adaptive Rate Limiter</strong> — Token bucket that responds to 429/503 with backoff</li>
<li><strong>Authenticated Scanning</strong> — Full support for cookies, headers, and Bearer tokens</li>
<li><strong>Modern HTML Reports</strong> — Dark/light theme, sidebar, bento KPIs, filters, live search, JSON export</li>
<li><strong>SARIF Export</strong> — GitHub Security tab integration</li>
<li><strong>Scan Diff Engine</strong> — Compare two scans to see what changed</li>
<li><strong>Structured Logging</strong> — JSON logs via <code>structlog</code></li>
<li><strong>Docker Ready</strong> — One-command deployment with <code>docker-compose</code></li>
<li><strong>Test Suite</strong> — 35 tests passing with <code>pytest</code>, <code>respx</code>, <code>pytest-asyncio</code></li>
</ul>

<hr>

<h2>🔥 Key Features</h2>

<h3>🔍 Phase 1 — Reconnaissance &amp; Discovery</h3>

<ul>
<li>
<p><strong>Subdomain Enumeration</strong> — Dual-engine discovery using <strong>Certificate Transparency Logs (<code>crt.sh</code>)</strong> for passive reconnaissance and <strong>Async DNS Bruteforcing</strong> (120+ wordlist) for active discovery. Uses an isolated HTTP client so enumeration never stalls behind the target's rate limiter.</p>
</li>
<li>
<p><strong>TCP Port Scanner</strong> — High-speed asynchronous TCP connect scanning with banner grabbing. Supports three ranges:</p>
<ul>
<li><code>common</code> — 19 most common ports</li>
<li><code>extended</code> — ~30 additional ports</li>
<li><code>full</code> — 1-65535 with <strong>chunked processing</strong> (memory bounded to ~80 MB vs 800 MB)</li>
</ul>
</li>
<li>
<p><strong>Technology Fingerprinting</strong> — Identifies web servers, CMSs, backend frameworks, and frontend libraries via HTTP Response Headers, HTML DOM patterns, and Session Cookies (nginx, Apache, PHP, WordPress, Drupal, React, Angular, Next.js, Vue.js, Laravel, Django, FastAPI, and more).</p>
</li>
<li>
<p><strong>Endpoint Discovery</strong> — Async path bruteforce across 200+ common administration, API (<code>/graphql</code>, <code>/swagger</code>), auth, debug, and backup endpoints. Includes SPA-specific endpoints (<code>/api/Users</code>, <code>/rest/products/search</code>, etc.) and sensitive file candidates (<code>.env</code>, <code>.git/HEAD</code>, <code>actuator/heapdump</code>).</p>
</li>
</ul>

<h3>🛡️ Phase 2 — Vulnerability Assessment Engine</h3>

<ul>
<li>
<p><strong>Reflected XSS Scanner</strong> — Evaluates parameter reflection in <code>text/html</code> contexts with execution-aware payload sets (script tags, HTML5 event handlers, filter bypasses, polyglots, template literals). Uses a unique marker (<code>xsstest7731</code>) to detect partial reflections.</p>
</li>
<li>
<p><strong>SQL Injection Scanner</strong> — Two-stage verification:</p>
<ul>
<li><strong>Error-Based</strong> — 30+ regex patterns covering MySQL, PostgreSQL, MSSQL, Oracle, SQLite</li>
<li><strong>Time-Based Blind</strong> — Multi-DB payloads (<code>SLEEP()</code>, <code>WAITFOR DELAY</code>, <code>pg_sleep()</code>, <code>BENCHMARK()</code>) with 3-request double-check to eliminate network latency false positives</li>
</ul>
</li>
<li>
<p><strong>CORS Misconfiguration Auditor</strong> — Tests 7 different origin patterns: wildcard, <code>null</code>, arbitrary reflection, subdomain bypass, suffix/prefix bypass. Combines <code>Allow-Credentials: true</code> detection with auto-generated JavaScript PoC exploits.</p>
</li>
<li>
<p><strong>SSRF &amp; Open Redirect</strong> — Tests cloud metadata endpoints (AWS IMDSv1, GCP, Azure), decimal/hex IP bypasses (<code>2130706433</code>, <code>0x7f000001</code>), <code>file://</code> protocol leaks, DNS rebinding hints, and location-header redirection validation.</p>
</li>
<li>
<p><strong>JWT Security Auditor</strong> — Automates <code>alg: none</code> bypass, weak secret brute-forcing (20+ common secrets), algorithm confusion (RS256 → HS256), missing <code>exp</code> claim, and sensitive payload data detection.</p>
</li>
<li>
<p><strong>IDOR &amp; Path Tampering</strong> — Evaluates parameter/path numerical shifts, UUID mutations, and HTTP Method Swapping (<code>DELETE</code>/<code>PUT</code>/<code>PATCH</code>) with SPA-aware false-positive protection and real-DELETE verification.</p>
</li>
<li>
<p><strong>Sensitive Data Exposure</strong> — Regex-based scanning for leaked AWS keys, Private RSA keys, GitHub/Stripe/Slack/SendGrid/Google API tokens, JWT tokens, database passwords, <code>.git</code> repository exposures, and Directory Listing.</p>
</li>
<li>
<p><strong>Business Logic Scanner</strong> (optional) — Tests mass assignment, price manipulation, rate-limit bypass via header rotation, password reset vulnerabilities (Host header injection), and response manipulation flaws. Recommended for authenticated scans.</p>
</li>
<li>
<p><strong>Nuclei Integration</strong> — Wraps ProjectDiscovery's <code>nuclei</code> engine (if installed) to execute 9000+ CVE and misconfiguration templates.</p>
</li>
</ul>

<h3>⚡ Resilience &amp; Evasion</h3>

<ul>
<li>
<p><strong>Adaptive Token-Bucket Rate Limiter</strong> — Per-domain buckets that respond dynamically:</p>
<ul>
<li><code>429 Too Many Requests</code> → halve RPS</li>
<li><code>503 Service Unavailable</code> → 30-second pause</li>
<li>20 successful requests → 20% RPS increase</li>
<li>Configurable min/max RPS bounds</li>
</ul>
</li>
<li>
<p><strong>WAF Detection &amp; Jitter Engine</strong> — Signature-based detection for Cloudflare, Akamai, AWS WAF, Imperva/Incapsula, Sucuri, F5 BIG-IP, Barracuda, ModSecurity, and Nginx WAF. Applies per-WAF evasion strategies (RPS reduction, User-Agent rotation, bypass headers).</p>
</li>
<li>
<p><strong>HTTP Response Caching</strong> — Per-domain request cache (TTL configurable) that reduces requests by ~30-40% during follow-up scans.</p>
</li>
<li>
<p><strong>Automatic Retry</strong> — Exponential backoff on 5xx/429 responses using <code>tenacity</code>.</p>
</li>
<li>
<p><strong>Structured Logging</strong> — JSON logs via <code>structlog</code> for SIEM integration (ELK, Splunk, Datadog), plus human-readable console output.</p>
</li>
</ul>

<hr>

<h2>🎯 False-Positive Reduction Engine</h2>

<p>BugScanner v2.1.1 introduces a <strong>5-rule verification pipeline</strong> that reduces false positives by approximately <strong>80%</strong> — the most common source of frustration in automated scanning.</p>

<h3>Rule 1 — Content Signature Verification</h3>

<p>Finding a file with HTTP 200 is not enough. BugScanner verifies actual content:</p>

<table>
<thead>
<tr>
<th>File Type</th>
<th>Required Signature</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>.env</code></td>
<td><code>DB_*</code>, <code>APP_KEY</code>, <code>SECRET</code>, <code>API_KEY</code>, or <code>KEY=value</code> lines</td>
</tr>
<tr>
<td><code>.sql</code></td>
<td><code>CREATE TABLE</code>, <code>INSERT INTO</code>, <code>SELECT ... FROM</code></td>
</tr>
<tr>
<td><code>.key</code> / <code>.pem</code></td>
<td><code>-----BEGIN PRIVATE KEY-----</code> or <code>-----BEGIN RSA PRIVATE KEY-----</code></td>
</tr>
<tr>
<td><code>.git/HEAD</code></td>
<td><code>ref: refs/heads/</code></td>
</tr>
</tbody>
</table>

<p>If a file returns <strong>HTML</strong> content (<code>&lt;!DOCTYPE html&gt;</code>, <code>&lt;div id="root"&gt;</code>), it is immediately flagged as a false positive.</p>

<h3>Rule 2 — SPA Fallback Detection</h3>

<p>For Single Page Applications, <strong>every route returns HTTP 200</strong> with the same <code>index.html</code> body. BugScanner detects this by:</p>

<ol>
<li>Requesting the base URL</li>
<li>Requesting a random non-existent path (<code>/__bs_probe_abc123</code>)</li>
<li>Comparing status codes, body sizes, and SHA-256 hashes</li>
</ol>

<p>If the fake path returns the same content as the base URL → <strong>SPA detected</strong> → route-based findings are filtered with high confidence.</p>

<h3>Rule 3 — Admin Panel DOM Verification</h3>

<p>Admin panels are only reported if the response body contains <strong>login-form DOM signals</strong>:</p>

<ul>
<li>Strong signals: <code>&lt;input type="password"&gt;</code>, <code>wp-login.php</code>, <code>phpmyadmin</code>, <code>admin panel</code></li>
<li>Weak signals (need 3+): <code>username</code>, <code>password</code>, <code>sign in</code>, <code>log in</code>, <code>dashboard</code>, <code>forgot password</code></li>
</ul>

<p>A page returning HTTP 200 without these markers is <strong>not</strong> reported as an admin panel.</p>

<h3>Rule 4 — Context-Aware Severity</h3>

<table>
<thead>
<tr>
<th>Context</th>
<th>Adjustment</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>localhost</code>, <code>127.0.0.1</code>, <code>::1</code></td>
<td>Downgrade severity by 1 level; skip HSTS entirely</td>
</tr>
<tr>
<td>RFC1918 IPs (<code>10.x</code>, <code>192.168.x</code>, <code>172.16-31.x</code>)</td>
<td>Downgrade severity by 1 level</td>
</tr>
<tr>
<td><code>.local</code>, <code>.internal</code>, <code>.test</code></td>
<td>Downgrade severity by 1 level</td>
</tr>
<tr>
<td>CORS wildcard on public endpoint (not <code>/auth</code>, <code>/api/user</code>, etc.)</td>
<td>Downgrade to <code>INFO</code></td>
</tr>
</table>

<h3>Rule 5 — Verification Required</h3>

<p>A vulnerability is only marked as <strong>Confirmed</strong> if it has:</p>

<ul>
<li>A <code>payload_used</code> <strong>or</strong> a <code>curl_poc</code></li>
<li>An <code>evidence</code> string of at least 10 characters</li>
<li>Successful active re-validation (for XSS, SQLi time-based, CORS, redirects, disclosure)</li>
</ul>

<p>Otherwise, it is flagged as <strong>Suspicious</strong> and filtered from the final report.</p>

<h3>📊 Real-World Results</h3>

<table>
<thead>
<tr>
<th>Target</th>
<th>Before FP Engine</th>
<th>After FP Engine</th>
<th>Reduction</th>
</tr>
</thead>
<tbody>
<tr>
<td>OWASP Juice Shop (SPA)</td>
<td>0 findings ❌</td>
<td>18 findings ✅</td>
<td>False negatives fixed</td>
</tr>
<tr>
<td>carfy.az</td>
<td>~35 findings (noisy)</td>
<td>5 findings (2 real, 3 hardening)</td>
<td>~86% noise removed</td>
</tr>
</tbody>
</table>

<hr>

<h2>🏗 Architecture</h2>

<p>BugScanner uses a modular, asynchronous architecture built on top of <code>asyncio</code> and <code>httpx</code>:</p>

<pre><code>cli.py ──&gt; scanner.py (Orchestrator)
            ├── recon/
            │   ├── subdomain.py         # crt.sh + Async DNS (isolated HTTP client)
            │   ├── portscan.py          # TCP Connect &amp; Banner Grab (chunked)
            │   ├── fingerprint.py       # Headers, DOM &amp; Cookies (context-aware)
            │   └── discovery.py         # Endpoint Bruteforce (SPA/API-aware)
            ├── vulns/
            │   ├── xss.py               # Reflected XSS Engine
            │   ├── sqli.py              # Error + Time-Based (multi-DB)
            │   ├── cors.py              # Origin Reflection (context-aware)
            │   ├── ssrf.py              # Metadata &amp; Protocol Leaks
            │   ├── redirect.py          # Open Redirect Auditor
            │   ├── jwt.py               # Alg None, Confusion &amp; Weak Secret
            │   ├── idor.py              # Parameter &amp; Verb Tampering (SPA-aware)
            │   ├── disclosure.py        # Content Signature Verification
            │   ├── business_logic.py    # Mass Assignment, Price Manipulation
            │   └── nuclei_wrapper.py    # Native Nuclei CLI Wrapper
            └── core/
                ├── rate_limiter.py      # Adaptive RPS &amp; Jitter
                ├── http_client.py       # Async HTTP Wrapper (retry + cache)
                ├── models.py            # Dataclasses &amp; CVSS Scoring
                ├── validator.py         # Active False-Positive Validator
                ├── fp_filter.py         # ✨ 5-Rule FP Reduction Engine
                ├── waf_detector.py      # WAF Signature Engine
                ├── differ.py            # Scan Diff Engine
                ├── sarif_reporter.py    # SARIF 2.1.0 Export
                ├── logger.py            # Structured Logging (structlog)
                └── reporter.py          # JSON / HTML / SARIF Generator

frontend/                                # React + Vite dashboard
            ├── src/
            │   ├── App.jsx                # Main shell + tab navigation
            │   └── components/
            │       ├── Scanner.jsx        # Scan configuration form
            │       ├── Results.jsx        # Live results (WebSocket)
            │       └── History.jsx        # Past scan browser

reports/
            ├── template.html            # Main HTML report
            ├── _styles.html             # Embedded CSS
            └── _scripts.html            # Embedded JS

tests/
            ├── conftest.py              # Shared fixtures
            ├── test_models.py           # Dataclass &amp; CVSS tests
            ├── test_rate_limiter.py     # Token bucket tests
            ├── test_http_client.py      # Retry &amp; cache tests
            ├── test_validator.py        # FP validator tests
            └── test_idor_spa.py         # SPA-aware IDOR tests</code></pre>

<hr>

<h2>🚀 Installation</h2>

<h3>Prerequisites</h3>

<ul>
<li><strong>Python 3.11+</strong> — <a href="https://www.python.org/downloads/">download</a></li>
<li><strong>Git</strong> — <a href="https://git-scm.com/">download</a></li>
<li><em>(Optional)</em> <strong>Nuclei</strong> for CVE template scanning — <a href="https://github.com/projectdiscovery/nuclei">install guide</a></li>
<li><em>(Optional)</em> <strong>Node.js 20+</strong> for the web dashboard — <a href="https://nodejs.org/">download</a></li>
<li><em>(Optional)</em> <strong>Docker Desktop</strong> for containerized deployment — <a href="https://www.docker.com/products/docker-desktop/">download</a></li>
</ul>

<h3>Setup</h3>

<pre><code class="language-bash"># 1. Clone the repository
git clone https://github.com/eldarshiraliyev/BugScanner.git
cd BugScanner

# 2. Create and activate a virtual environment
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4. Verify installation
python cli.py version</code></pre>

<p>Expected output:</p>

<pre><code>BugScanner v2.1
Bug Bounty Automation Tool
Authorized use only</code></pre>

<h3>Optional: Install Nuclei</h3>

<pre><code class="language-bash"># macOS
brew install nuclei

# Linux
curl -sSL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/scripts/install.sh | bash

# Or with Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates</code></pre>

<hr>

<h2>📖 Usage</h2>

<h3>CLI — Basic Scans</h3>

<pre><code class="language-bash"># Full comprehensive scan (recon + vulnerabilities)
python cli.py scan https://target.com

# Reconnaissance only
python cli.py scan https://target.com --mode recon

# Vulnerability audit only (skip recon)
python cli.py scan https://target.com --mode vulns

# Custom port scan without subdomain enumeration
python cli.py scan https://target.com --no-subdomains --ports extended

# Adjust adaptive rate limit
python cli.py scan https://target.com --rps 5

# Export to JSON only
python cli.py scan https://target.com --format json

# Export to SARIF (GitHub Security tab)
python cli.py scan https://target.com --format sarif

# Disable HTTP cache (always re-request)
python cli.py scan https://target.com --no-cache</code></pre>

<h3>CLI — Authenticated Scans</h3>

<pre><code class="language-bash"># Session cookie authentication
python cli.py scan https://target.com \
  --cookie "session=abc123" \
  --cookie "csrf=xyz789"

# Bearer token
python cli.py scan https://target.com \
  --header "Authorization: Bearer eyJhbGciOi..."

# Burp Suite proxy + business logic scan
python cli.py scan https://target.com \
  --cookie "session=abc123" \
  --proxy http://127.0.0.1:8080 \
  --business-logic</code></pre>

<h3>CLI — Fast / Careful Scans</h3>

<pre><code class="language-bash"># Fast scan — disable FP validation, higher RPS
python cli.py scan https://target.com \
  --no-subdomains \
  --no-fp-validation \
  --no-nuclei \
  --rps 20

# WAF-protected target — slow and careful
python cli.py scan https://target.com \
  --rps 3 \
  --no-subdomains \
  --ports common</code></pre>

<h3>CLI — Specialized Commands</h3>

<pre><code class="language-bash"># Recon only
python cli.py recon https://target.com --ports extended

# Vulnerability scan only (with auth)
python cli.py vulnscan https://target.com --cookie "session=abc123"

# Business logic scan only
python cli.py bizlogic https://target.com --cookie "session=abc123"

# Diff two previous scans
python cli.py diff reports/old.json reports/new.json

# Show version
python cli.py version</code></pre>

<h3>Web Dashboard</h3>

<pre><code class="language-bash"># Backend API + frontend
python app.py
# Open http://localhost:8000</code></pre>

<p>The dashboard provides:</p>

<ul>
<li>Live scan progress via WebSocket</li>
<li>Interactive vulnerability browser with severity filters</li>
<li>Chip-based severity filter + live search</li>
<li>Historical scan comparison</li>
<li>Direct report download (JSON, HTML, SARIF)</li>
<li>Dark theme optimized for long sessions</li>
</ul>

<h3>API Endpoints</h3>

<table>
<thead>
<tr>
<th>Method</th>
<th>Endpoint</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>GET</td>
<td><code>/api/health</code></td>
<td>Health check + auth status</td>
</tr>
<tr>
<td>POST</td>
<td><code>/api/scan/start</code></td>
<td>Start a new scan (requires API key if configured)</td>
</tr>
<tr>
<td>GET</td>
<td><code>/api/scan/{id}</code></td>
<td>Get scan status and result</td>
</tr>
<tr>
<td>GET</td>
<td><code>/api/scans</code></td>
<td>List all scans</td>
</tr>
<tr>
<td>DELETE</td>
<td><code>/api/scan/{id}</code></td>
<td>Delete a scan</td>
</tr>
<tr>
<td>WS</td>
<td><code>/ws/{id}</code></td>
<td>Real-time scan progress</td>
</tr>
</tbody>
</table>

<hr>

<h2>📊 CLI Reference</h2>

<table>
<thead>
<tr>
<th>Option</th>
<th>Description</th>
<th>Default</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>target</code></td>
<td>Target URL (e.g., <code>https://target.com</code>)</td>
<td><strong>Required</strong></td>
</tr>
<tr>
<td><code>--mode, -m</code></td>
<td>Scan mode: <code>all</code>, <code>recon</code>, <code>vulns</code></td>
<td><code>all</code></td>
</tr>
<tr>
<td><code>--ports, -p</code></td>
<td>Port scan range: <code>common</code>, <code>extended</code>, <code>full</code></td>
<td><code>common</code></td>
</tr>
<tr>
<td><code>--rps</code></td>
<td>Initial Requests Per Second limit</td>
<td><code>10</code></td>
</tr>
<tr>
<td><code>--no-subdomains</code></td>
<td>Skip subdomain enumeration</td>
<td><code>False</code></td>
</tr>
<tr>
<td><code>--no-fp-validation</code></td>
<td>Disable false-positive validation</td>
<td><code>False</code></td>
</tr>
<tr>
<td><code>--no-nuclei</code></td>
<td>Skip Nuclei scan</td>
<td><code>False</code></td>
</tr>
<tr>
<td><code>--no-cache</code></td>
<td>Disable HTTP response cache</td>
<td><code>False</code></td>
</tr>
<tr>
<td><code>--business-logic</code></td>
<td>Enable business logic scan</td>
<td><code>False</code></td>
</tr>
<tr>
<td><code>--cookie, -c</code></td>
<td>Session cookie (<code>name=value</code>, repeatable)</td>
<td>—</td>
</tr>
<tr>
<td><code>--header, -H</code></td>
<td>Custom header (<code>Name: Value</code>, repeatable)</td>
<td>—</td>
</tr>
<tr>
<td><code>--proxy</code></td>
<td>HTTP proxy (e.g., Burp Suite)</td>
<td>—</td>
</tr>
<tr>
<td><code>--output, -o</code></td>
<td>Report output directory</td>
<td><code>./reports</code></td>
</tr>
<tr>
<td><code>--format, -f</code></td>
<td>Report format: <code>all</code>, <code>json</code>, <code>html</code>, <code>sarif</code></td>
<td><code>all</code></td>
</tr>
</tbody>
</table>

<hr>

<h2>🎨 Report Preview</h2>

<p>BugScanner's v2.1.1 HTML report features a completely redesigned <strong>2026-era interface</strong>:</p>

<ul>
<li>🌗 <strong>Dark / Light Theme</strong> — Toggleable, persists via <code>localStorage</code></li>
<li>📊 <strong>Bento-Grid KPIs</strong> — Risk score ring (SVG animated), vulnerability distribution bars, recon surface, scan duration</li>
<li>🧭 <strong>Sidebar Navigation</strong> — Auto-highlights current section while scrolling (IntersectionObserver)</li>
<li>🔎 <strong>Live Search &amp; Filters</strong> — Chip-based severity filter + text search across title, URL, CWE</li>
<li>⚡ <strong>Copy-to-Clipboard PoCs</strong> — One-click copy for every <code>curl</code> proof-of-concept</li>
<li>🖨️ <strong>Print Stylesheet</strong> — Clean printable output (expands all collapsed sections)</li>
<li>📥 <strong>JSON Export</strong> — Download the raw scan data directly from the report</li>
<li>🎯 <strong>FP Breakdown</strong> — Shows filtered false positives categorized by rule (SPA, no-signature, no-admin-DOM, no-PoC, downgraded)</li>
<li>📱 <strong>Responsive</strong> — Works on tablet and mobile devices</li>
<li>🔒 <strong>Self-Contained</strong> — No external CDN dependencies, works offline</li>
</ul>

<h3>Report Sections</h3>

<table>
<thead>
<tr>
<th>Section</th>
<th>Content</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Summary</strong></td>
<td>Risk ring, vulnerability breakdown, recon surface, scan duration</td>
</tr>
<tr>
<td><strong>Vulnerabilities</strong></td>
<td>Filterable, searchable list with expandable details (description, evidence, exploitation, remediation, PoC, references)</td>
</tr>
<tr>
<td><strong>Technologies</strong></td>
<td>Pill-based display of detected tech stack</td>
</tr>
<tr>
<td><strong>Subdomains</strong></td>
<td>Table with IP, HTTP status, technologies</td>
</tr>
<tr>
<td><strong>Open Ports</strong></td>
<td>Table with port, protocol, service, version/banner</td>
</tr>
<tr>
<td><strong>Endpoints</strong></td>
<td>Numbered list of all discovered URLs</td>
</tr>
</tbody>
</table>

<hr>

<h2>⚙️ Configuration</h2>

<p>The <code>settings.yaml</code> file at the project root controls global behavior:</p>

<pre><code class="language-yaml">rate_limiting:
  default_rps: 10           # requests per second
  min_rps: 1
  max_rps: 50
  backoff_multiplier: 2
  pause_on_503: 30          # seconds

scanning:
  timeout: 10               # seconds per request
  max_redirects: 5
  user_agent: "Mozilla/5.0 (compatible; BugScanner/2.1)"
  verify_ssl: false

ports:
  common: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]
  extended: [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]

nuclei:
  enabled: true
  templates_path: "~/.local/nuclei-templates"
  severity: ["critical", "high", "medium", "low"]
  rate_limit: 150

output:
  default_format: ["terminal", "json", "html", "sarif"]
  reports_dir: "./reports"</code></pre>

<h3>Environment Variables</h3>

<table>
<thead>
<tr>
<th>Variable</th>
<th>Description</th>
<th>Default</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>BUGSCANNER_API_KEY</code></td>
<td>API key for FastAPI backend. If empty, auth is disabled.</td>
<td>—</td>
</tr>
<tr>
<td><code>BUGSCANNER_CORS</code></td>
<td>Allowed CORS origins (comma-separated, or <code>*</code>)</td>
<td><code>*</code></td>
</tr>
<tr>
<td><code>BUGSCANNER_LOG_LEVEL</code></td>
<td>Logging level (<code>DEBUG</code>, <code>INFO</code>, <code>WARNING</code>, <code>ERROR</code>)</td>
<td><code>INFO</code></td>
</tr>
<tr>
<td><code>BUGSCANNER_LOG_FILE</code></td>
<td>Optional path to write JSON logs</td>
<td>—</td>
</tr>
</tbody>
</table>

<h3>Risk Assessment — CVSS v3.1</h3>

<table>
<thead>
<tr>
<th>Severity</th>
<th>CVSS Score</th>
<th>Example Vulnerabilities</th>
</tr>
</thead>
<tbody>
<tr>
<td>🔴 <strong>CRITICAL</strong></td>
<td>9.0 – 10.0</td>
<td>SQLi, RCE, SSRF with Cloud Metadata, Weak JWT Secret, Private Key Exposure</td>
</tr>
<tr>
<td>🟠 <strong>HIGH</strong></td>
<td>7.0 – 8.9</td>
<td>Reflected XSS, Unauthenticated IDOR, CORS with Credentials, <code>.git</code> Exposure, Mass Assignment</td>
</tr>
<tr>
<td>🟡 <strong>MEDIUM</strong></td>
<td>4.0 – 6.9</td>
<td>Open Redirect, Wildcard CORS, Missing CSP/HSTS, Directory Listing, GraphQL Introspection</td>
</tr>
<tr>
<td>🔵 <strong>LOW</strong></td>
<td>1.0 – 3.9</td>
<td>Missing X-Frame-Options, Missing X-Content-Type-Options, 403 Bypass Candidates</td>
</tr>
<tr>
<td>⚪ <strong>INFO</strong></td>
<td>0.0 – 0.9</td>
<td>Technology Fingerprint, Server Banner, Missing Permissions-Policy</td>
</tr>
</tbody>
</table>

<hr>

<h2>🧪 Testing</h2>

<p>BugScanner includes a comprehensive test suite built with <code>pytest</code>, <code>pytest-asyncio</code>, and <code>respx</code> (HTTP mocking).</p>

<h3>Run All Tests</h3>

<pre><code class="language-bash">pytest -v</code></pre>

<h3>With Coverage Report</h3>

<pre><code class="language-bash">pytest --cov=core --cov=modules --cov-report=term-missing</code></pre>

<h3>HTML Coverage Report</h3>

<pre><code class="language-bash">pytest --cov=core --cov=modules --cov-report=html
start htmlcov/index.html    # Windows
open htmlcov/index.html     # macOS
xdg-open htmlcov/index.html # Linux</code></pre>

<h3>Test Structure</h3>

<table>
<thead>
<tr>
<th>File</th>
<th>Tests</th>
<th>Coverage</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>tests/test_models.py</code></td>
<td>8</td>
<td>96% (models, CVSS, risk score)</td>
</tr>
<tr>
<td><code>tests/test_rate_limiter.py</code></td>
<td>9</td>
<td>96% (token bucket, 429/503 handling)</td>
</tr>
<tr>
<td><code>tests/test_http_client.py</code></td>
<td>5</td>
<td>91% (GET, cache, retry)</td>
</tr>
<tr>
<td><code>tests/test_validator.py</code></td>
<td>4</td>
<td>31% (XSS, SQLi, CORS, disclosure)</td>
</tr>
<tr>
<td><code>tests/test_idor_spa.py</code></td>
<td>9</td>
<td>29% (SPA detection, body similarity, admin DOM)</td>
</tr>
</tbody>
</table>

<p><strong>Total: 35 tests passing</strong></p>

<hr>

<h2>🐳 Docker Deployment</h2>

<h3>Quick Start</h3>

<pre><code class="language-bash"># Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down</code></pre>

<p>The container exposes the FastAPI backend + frontend on <code>http://localhost:8000</code>.</p>

<h3>Environment Configuration</h3>

<p>Create a <code>.env</code> file:</p>

<pre><code class="language-bash">BUGSCANNER_API_KEY=your-long-random-api-key
BUGSCANNER_LOG_LEVEL=INFO
BUGSCANNER_CORS=http://localhost:5173,http://localhost:8000</code></pre>

<h3>Run Manual Scan Inside Container</h3>

<pre><code class="language-bash">docker exec -it bugscanner python cli.py scan https://target.com</code></pre>

<hr>

<h2>🤝 Contributing</h2>

<p>Contributions are welcome! Please:</p>

<ol>
<li>Fork the repository</li>
<li>Create a feature branch (<code>git checkout -b feature/amazing-feature</code>)</li>
<li>Write tests for new functionality</li>
<li>Ensure all tests pass: <code>pytest</code></li>
<li>Update <code>CHANGELOG.md</code> under the <code>[Unreleased]</code> section</li>
<li>Commit using <a href="https://www.conventionalcommits.org/">Conventional Commits</a>:
<ul>
<li><code>feat: add new scanner</code></li>
<li><code>fix: correct rate limiter</code></li>
<li><code>docs: update README</code></li>
</ul>
</li>
<li>Push to the branch (<code>git push origin feature/amazing-feature</code>)</li>
<li>Open a Pull Request with a clear description</li>
</ol>

<h3>Code Style</h3>

<ul>
<li><strong>Line length</strong>: 100 characters max</li>
<li><strong>Type hints</strong>: Required for public functions</li>
<li><strong>Docstrings</strong>: Google style for public APIs</li>
<li><strong>Formatting</strong>: <code>black</code> and <code>isort</code></li>
</ul>

<pre><code class="language-bash">pip install black isort
black core modules cli.py app.py
isort core modules cli.py app.py</code></pre>

<hr>

<h2>🗺 Roadmap</h2>

<ul>
<li>✅ <strong>Authenticated Scope Scanning</strong> — <code>--cookie</code> and <code>--header</code> session preservation</li>
<li>✅ <strong>Modern Report UI</strong> — Dark/light theme, interactive filters</li>
<li>✅ <strong>False-Positive Reduction Engine</strong> — 5-rule verification pipeline (~80% noise reduction)</li>
<li>✅ <strong>SPA-Aware Detection</strong> — Multi-layer false-positive protection</li>
<li>✅ <strong>Chunked Port Scanning</strong> — Full 1–65535 range without memory blowup</li>
<li>✅ <strong>Structured Logging</strong> — JSON logs via structlog</li>
<li>✅ <strong>SARIF Export</strong> — GitHub Security tab integration</li>
<li>✅ <strong>Scan Diff Engine</strong> — Compare two scans</li>
<li>✅ <strong>Docker Compose</strong> — One-command deployment</li>
<li>⬜ <strong>Headless DOM Analysis</strong> — Playwright integration for Blind XSS and SPA route extraction</li>
<li>⬜ <strong>Multi-Role IDOR Diff Engine</strong> — Automated differential testing between User A and User B session tokens</li>
<li>⬜ <strong>PyPI Package Release</strong> — <code>pip install bugscanner</code></li>
<li>⬜ <strong>Plugin System</strong> — User-defined scanner modules</li>
<li>⬜ <strong>Postgres Backend</strong> — Persistent scan history and comparison</li>
<li>⬜ <strong>GraphQL Introspection Scanner</strong> — Full schema dump and query abuse detection</li>
<li>⬜ <strong>Web Cache Deception</strong> — Automated testing for CDN/cache poisoning</li>
</ul>

<hr>

<h2>📜 License</h2>

<p>This project is licensed under the <strong>MIT License</strong> — see the <a href="LICENSE">LICENSE</a> file for details.</p>

<hr>

<h2>⚠️ Disclaimer</h2>

<p><strong>IMPORTANT</strong>: This tool is developed for <strong>educational purposes, defensive auditing, and authorized penetration testing / bug bounty activities only</strong>.</p>

<p>Scanning targets <strong>without prior explicit consent</strong> is <strong>illegal</strong> and punishable by law. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.</p>

<blockquote>
<p><strong>Authorized Use Only</strong> — Always obtain written permission before scanning any system you do not own.</p>
</blockquote>

<p>By using BugScanner, you agree to:</p>

<ul>
<li>Only scan systems you own or have explicit permission to test</li>
<li>Respect rate limits and avoid denial-of-service conditions</li>
<li>Report vulnerabilities responsibly to the affected party</li>
<li>Never use findings for malicious purposes</li>
</ul>

<hr>

<h2>🙏 Acknowledgments</h2>

<ul>
<li><a href="https://www.kali.org/">Kali Linux</a> — Community and inspiration</li>
<li><a href="https://github.com/projectdiscovery/nuclei">ProjectDiscovery</a> — Nuclei template engine</li>
<li><a href="https://portswigger.net/">PortSwigger</a> — Web Security Academy reference material</li>
<li><a href="https://owasp.org/">OWASP</a> — Vulnerability classification standards</li>
<li><a href="https://github.com/encode/httpx">httpx</a> — Excellent async HTTP library</li>
<li><a href="https://github.com/Textualize/rich">rich</a> — Beautiful terminal output</li>
</ul>

<hr>

<div align="center">

<p><strong>🐛 Built with ❤️ for the security community</strong></p>

<p>
<a href="https://github.com/eldarshiraliyev/BugScanner/issues">Report a Bug</a> •
<a href="https://github.com/eldarshiraliyev/BugScanner/issues">Request a Feature</a> •
<a href="https://github.com/eldarshiraliyev/BugScanner">Star the Project</a>
</p>

<p>
<em>If you find BugScanner useful, consider starring the repo — it helps others discover the project.</em>
</p>

</div>
