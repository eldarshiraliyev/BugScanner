<div align="center">

<h1>🐛 BugScanner</h1>

<p><strong>An Advanced, Context-Aware Recon &amp; Automated Web Vulnerability Assessment Framework</strong></p>

<p>
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python Version"></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
<a href="http://makeapullrequest.com"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
<a href="https://github.com/eldarshiraliyev/BugScanner"><img src="https://img.shields.io/github/stars/eldarshiraliyev/BugScanner?style=social" alt="GitHub Stars"></a>
<a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"></a>
</p>

<p>
<a href="#-key-features">Key Features</a> •
<a href="#-architecture">Architecture</a> •
<a href="#-installation">Installation</a> •
<a href="#-usage">Usage</a> •
<a href="#-report-preview">Report Preview</a> •
<a href="#%EF%B8%8F-configuration">Configuration</a> •
<a href="#-roadmap">Roadmap</a>
</p>

</div>

<hr>

<h2>📌 Overview</h2>

<p><strong>BugScanner</strong> is a modular, high-performance web vulnerability scanner and reconnaissance framework engineered specifically for <strong>Bug Bounty Hunters</strong>, <strong>Red Teams</strong>, and <strong>Penetration Testers</strong>.</p>

<p>Unlike standard passive scanners, BugScanner combines <strong>deep subdomain discovery</strong>, <strong>active TCP service fingerprinting</strong>, and a <strong>Context-Aware Vulnerability Verification Engine</strong> designed to minimize false positives and bypass modern Web Application Firewalls (WAFs) through adaptive rate limiting and jitter control.</p>

<h3>🎯 What's New in v2.0</h3>

<ul>
<li>🎨 <strong>Modern Report UI</strong> — Dark/light theme, sidebar navigation, bento-grid KPIs, interactive filters</li>
<li>🛡️ <strong>SPA-Aware Detection</strong> — Detects Single Page Application fallbacks to eliminate false positives</li>
<li>⚡ <strong>Chunked Port Scanning</strong> — Full-range scans with bounded memory (800 MB → 80 MB)</li>
<li>🔒 <strong>Authenticated Scanning</strong> — Native <code>--cookie</code> and <code>--header</code> session preservation</li>
<li>🧠 <strong>Business Logic Scanner</strong> — Mass assignment, price manipulation, rate-limit bypass</li>
<li>📊 <strong>CVSS v3.1 Scoring</strong> — Every finding rated with industry-standard severity</li>
<li>🌍 <strong>English Interface</strong> — Fully internationalized CLI and UI</li>
</ul>

<hr>

<h2>🔥 Key Features</h2>

<h3>🔍 Phase 1 — Reconnaissance &amp; Discovery</h3>

<ul>
<li><strong>Subdomain Enumeration</strong> — Dual-engine discovery using <strong>Certificate Transparency Logs (<code>crt.sh</code>)</strong> for passive reconnaissance and <strong>Async DNS Bruteforcing</strong> (120+ wordlist) for active discovery. Isolated HTTP client prevents the shared rate limiter from stalling enumeration.</li>
<li><strong>TCP Port Scanner</strong> — High-speed asynchronous TCP connect scanning across custom ranges (<code>common</code>, <code>extended</code>, <code>full</code>). <strong>Chunked processing</strong> keeps memory bounded even on 65K-port scans. Features banner grabbing for service version extraction and security hints.</li>
<li><strong>Technology Fingerprinting</strong> — Identifies web servers, CMSs, backend frameworks, and frontend libraries via HTTP Response Headers, HTML DOM patterns, and Session Cookies.</li>
<li><strong>Endpoint Discovery</strong> — Async path discovery covering <strong>200+ common administration, API (<code>/graphql</code>, <code>/swagger</code>), auth, debug, and backup endpoints</strong> (<code>.env</code>, <code>.git/HEAD</code>, <code>actuator/heapdump</code>).</li>
</ul>

<h3>🛡️ Phase 2 — Vulnerability Assessment Engine</h3>

<ul>
<li><strong>Reflected XSS Scanner</strong> — Evaluates parameter reflection in <code>text/html</code> contexts with execution-aware payload sets, lowering noise and false positives.</li>
<li><strong>SQL Injection (SQLi) Verification</strong> — Error-Based detection across <strong>30+ database error patterns</strong> (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) and <strong>Time-Based Double-Check Verification</strong> supporting <code>SLEEP()</code>, <code>WAITFOR DELAY</code>, <code>pg_sleep()</code>, and <code>BENCHMARK()</code> to eliminate network latency false positives.</li>
<li><strong>CORS Misconfiguration Auditor</strong> — Identifies wildcard origins, arbitrary origin reflection, <code>null</code> origin bypass, trusted subdomain bypass, and dangerous <code>Access-Control-Allow-Credentials: true</code> combinations with auto-generated PoC exploits.</li>
<li><strong>SSRF &amp; Open Redirect</strong> — Tests for Cloud Metadata exposure (AWS IMDSv1, GCP, Azure), protocol handler leaks (<code>file://</code>), decimal/hex IP bypasses, and location-header redirection validation.</li>
<li><strong>JWT Security Auditor</strong> — Automates <code>alg: none</code> bypass checks, signature verification, algorithm confusion (RS256 → HS256), weak secret brute-forcing, and payload sensitive-data analysis.</li>
<li><strong>IDOR &amp; Path Tampering</strong> — Evaluates parameter/path numerical shifts, UUID mutations, and HTTP Method Swapping (<code>DELETE</code>/<code>PUT</code> verb tampering) with <strong>SPA-aware false positive protection</strong>.</li>
<li><strong>Sensitive Data Exposure</strong> — Scans responses for leaked AWS keys, Private RSA keys, GitHub/Stripe/Slack tokens, <code>.git</code> repository exposures, and Directory Listing.</li>
<li><strong>Nuclei Integration</strong> — Seamlessly wraps ProjectDiscovery's <code>nuclei</code> engine (if installed) to execute <strong>9000+ CVE and misconfiguration templates</strong> directly into the consolidated report.</li>
</ul>

<h3>🎯 False-Positive Reduction Engine</h3>

<p>BugScanner v2.0 introduces a <strong>multi-layer verification pipeline</strong> to eliminate the most common source of false positives in automated scanning:</p>

<table>
<thead>
<tr>
<th>Layer</th>
<th>Technique</th>
<th>Problem Solved</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>SPA Fallback Detection</strong></td>
<td>Probe random nonexistent path; if <code>200 OK</code> with same body → SPA shell</td>
<td>Every route returns 200 in SPA apps</td>
</tr>
<tr>
<td><strong>Body Similarity Check</strong></td>
<td>Compare response bodies (length + prefix) against baseline</td>
<td>Static responses flagged as dynamic data</td>
</tr>
<tr>
<td><strong>Fake-404 Baseline</strong></td>
<td>Establish soft-404 fingerprint; filter matching responses</td>
<td>Custom error pages returning 200</td>
</tr>
<tr>
<td><strong>Content-Type Sanity</strong></td>
<td>Reject <code>text/html</code> on API endpoints expecting JSON</td>
<td>Fallback page served instead of API data</td>
</tr>
<tr>
<td><strong>Real DELETE Verification</strong></td>
<td>Re-fetch after <code>DELETE 200</code>; if resource still exists → false positive</td>
<td>Servers accepting DELETE but not acting</td>
</tr>
<tr>
<td><strong>Time-Based Double-Check</strong></td>
<td>3 baseline + 3 payload requests, averaged and threshold-checked</td>
<td>Network latency misread as SQLi delay</td>
</tr>
<tr>
<td><strong>Reflection Triple-Check</strong></td>
<td>3 XSS re-checks, minimum 2 must confirm</td>
<td>Cache/CDN inconsistencies</td>
</tr>
</tbody>
</table>

<h3>⚡ Resilience &amp; Evasion Capabilities</h3>

<ul>
<li><strong>Adaptive Token-Bucket Rate Limiter</strong> — Dynamically adjusts RPS upon receiving <code>429 Too Many Requests</code> or <code>503 Service Unavailable</code>, preventing WAF IP bans.</li>
<li><strong>WAF Detection &amp; Jitter Engine</strong> — Detects <strong>Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, F5 BIG-IP, Barracuda, ModSecurity</strong> signatures and applies per-WAF evasion strategies (RPS reduction, UA rotation, bypass headers).</li>
<li><strong>Dynamic Reporting</strong> — Generates structured JSON alongside <strong>interactive, dark/light-themed HTML reports</strong> featuring CVSS v3.1 severity scoring, animated risk metrics, and ready-to-use exploit PoCs.</li>
</ul>

<hr>

<h2>🏗 Architecture</h2>

<p>BugScanner uses a modular, asynchronous architecture built on top of <code>asyncio</code> and <code>httpx</code>:</p>

<pre><code>cli.py ──&gt; scanner.py (Orchestrator)
            ├── recon/
            │   ├── subdomain.py         # crt.sh + Async DNS (isolated HTTP client)
            │   ├── portscan.py          # TCP Connect &amp; Banner Grab (chunked)
            │   ├── fingerprint.py       # Headers, DOM &amp; Cookies
            │   └── discovery.py         # Endpoint Bruteforce
            ├── vulns/
            │   ├── xss.py               # Reflected XSS Engine
            │   ├── sqli.py              # Error + Time-Based (multi-DB)
            │   ├── cors.py              # Origin Reflection &amp; Credentials
            │   ├── ssrf.py              # Metadata &amp; Protocol Leaks
            │   ├── redirect.py          # Open Redirect Auditor
            │   ├── jwt.py               # Alg None, Confusion &amp; Weak Secret
            │   ├── idor.py              # Parameter &amp; Verb Tampering (SPA-aware)
            │   ├── disclosure.py        # Token &amp; Key RegEx Extractor
            │   ├── business_logic.py    # Mass Assignment, Price Manipulation
            │   └── nuclei_wrapper.py    # Native Nuclei CLI Wrapper
            └── core/
                ├── rate_limiter.py      # Adaptive RPS &amp; Jitter
                ├── http_client.py       # Async HTTP Wrapper (auth + proxy)
                ├── models.py            # Dataclasses &amp; CVSS Scoring
                ├── validator.py         # False-Positive Validator
                ├── waf_detector.py      # WAF Signature Engine
                └── reporter.py          # JSON &amp; Jinja2 HTML Generator

frontend/                            # React + Vite dashboard
            ├── src/
            │   ├── App.jsx              # Main shell + tab navigation
            │   └── components/
            │       ├── Scanner.jsx      # Scan configuration form
            │       ├── Results.jsx      # Live results with WebSocket
            │       └── History.jsx      # Past scan browser

reports/
            ├── template.html            # Main HTML report
            ├── _styles.html             # Embedded CSS
            └── _scripts.html            # Embedded JS</code></pre>

<hr>

<h2>🚀 Installation</h2>

<h3>Prerequisites</h3>

<ul>
<li><strong>Python 3.11+</strong> — <a href="https://www.python.org/downloads/">download</a></li>
<li><strong>Git</strong> — <a href="https://git-scm.com/">download</a></li>
<li><em>(Optional)</em> <strong>Nuclei</strong> for CVE template scanning — <a href="https://github.com/projectdiscovery/nuclei">install guide</a></li>
<li><em>(Optional)</em> <strong>Node.js 20+</strong> for the web dashboard — <a href="https://nodejs.org/">download</a></li>
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

<pre><code>BugScanner v2.0
Bug Bounty Automation Tool
Authorized use only</code></pre>

<hr>

<h2>🚀 Usage</h2>

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
python cli.py scan https://target.com --format json</code></pre>

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
<li>Historical scan comparison</li>
<li>Direct report download</li>
</ul>

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
<td>Report format: <code>all</code>, <code>json</code>, <code>html</code></td>
<td><code>all</code></td>
</tr>
</tbody>
</table>

<hr>

<h2>🎨 Report Preview</h2>

<p>The v2.0 HTML report features a completely redesigned <strong>2026-era interface</strong>:</p>

<ul>
<li>🌗 <strong>Dark / Light Theme</strong> — Toggleable, persists via <code>localStorage</code></li>
<li>📊 <strong>Bento-Grid KPIs</strong> — Risk score ring, vulnerability bars, recon surface, scan duration</li>
<li>🧭 <strong>Sidebar Navigation</strong> — Auto-highlights current section while scrolling</li>
<li>🔎 <strong>Live Search &amp; Filters</strong> — Chip-based severity filter + text search across title, URL, CWE</li>
<li>⚡ <strong>Copy-to-Clipboard PoCs</strong> — One-click copy for every <code>curl</code> proof-of-concept</li>
<li>🖨️ <strong>Print Stylesheet</strong> — Clean printable output (expands all collapsed sections)</li>
<li>📥 <strong>JSON Export</strong> — Download the raw scan data directly from the report</li>
</ul>

<p>The report is <strong>fully self-contained</strong> — no external CDN dependencies, works completely offline.</p>

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
  user_agent: "Mozilla/5.0 (compatible; BugScanner/2.0)"
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
  default_format: ["terminal", "json", "html"]
  reports_dir: "./reports"</code></pre>

<h3>Risk Assessment</h3>

<p>Findings are rated using the <strong>CVSS v3.1</strong> framework:</p>

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
<td>SQLi, RCE, SSRF with Cloud Metadata, Weak JWT Secret</td>
</tr>
<tr>
<td>🟠 <strong>HIGH</strong></td>
<td>7.0 – 8.9</td>
<td>Reflected XSS, Unauthenticated IDOR, CORS with Credentials, <code>.git</code> Exposure</td>
</tr>
<tr>
<td>🟡 <strong>MEDIUM</strong></td>
<td>4.0 – 6.9</td>
<td>Reflected XSS (Restricted), Open Redirect, Wildcard CORS</td>
</tr>
<tr>
<td>🔵 <strong>LOW</strong></td>
<td>1.0 – 3.9</td>
<td>Missing Security Headers, Server Version Disclosure</td>
</tr>
<tr>
<td>⚪ <strong>INFO</strong></td>
<td>0.0 – 0.9</td>
<td>Technology Fingerprint, Port Banner Discovery</td>
</tr>
</tbody>
</table>

<hr>

<h2>🗺 Roadmap</h2>

<ul>
<li>✅ <strong>Authenticated Scope Scanning</strong> — <code>--cookie</code> and <code>--header</code> session preservation</li>
<li>✅ <strong>Modern Report UI</strong> — Dark/light theme, interactive filters</li>
<li>✅ <strong>SPA-Aware IDOR Detection</strong> — Multi-layer false-positive reduction</li>
<li>✅ <strong>Chunked Port Scanning</strong> — Full 1–65535 range without memory blowup</li>
<li>⬜ <strong>Multi-Role IDOR Diff Engine</strong> — Automated differential testing between User A and User B session tokens</li>
<li>⬜ <strong>Headless DOM Analysis</strong> — Playwright integration for Blind XSS and SPA route extraction</li>
<li>⬜ <strong>PyPI Package Release</strong> — <code>pip install bugscanner</code></li>
<li>⬜ <strong>Docker Compose</strong> — One-command deployment with optional Nuclei bundled</li>
<li>⬜ <strong>SARIF Export</strong> — GitHub Security tab integration</li>
<li>⬜ <strong>Plugin System</strong> — User-defined scanner modules</li>
</ul>

<hr>

<h2>🤝 Contributing</h2>

<p>Contributions are welcome! Please:</p>

<ol>
<li>Fork the repository</li>
<li>Create a feature branch (<code>git checkout -b feature/amazing-feature</code>)</li>
<li>Commit your changes (<code>git commit -m 'feat: add amazing feature'</code>)</li>
<li>Push to the branch (<code>git push origin feature/amazing-feature</code>)</li>
<li>Open a Pull Request</li>
</ol>

<p>Please follow the existing code style and include tests for new features.</p>

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

<hr>

<div align="center">

<p><strong>🐛 Built with ❤️ for the security community</strong></p>

<p>
<a href="https://github.com/eldarshiraliyev/BugScanner/issues">Report a Bug</a> •
<a href="https://github.com/eldarshiraliyev/BugScanner/issues">Request a Feature</a> •
<a href="https://github.com/eldarshiraliyev/BugScanner">Star the Project</a>
</p>

</div>
