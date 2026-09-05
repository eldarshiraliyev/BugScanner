🛡️ BugScanner
Passive Web Security Scanner for Bug Bounty Hunters

BugScanner is a modular web security reconnaissance and vulnerability assessment tool designed for bug bounty hunters and authorized security testing.

It combines attack-surface discovery, technology fingerprinting, endpoint enumeration and automated vulnerability checks into a single CLI workflow.

⚠️ Important: BugScanner is intended for authorized security testing, bug bounty programs and lab environments only. Always verify that you have permission to test a target.

🚀 What is BugScanner?

BugScanner takes a target URL and automatically builds a security profile of the application.

Target URL
    │
    ▼
┌─────────────────────┐
│      Recon          │
├─────────────────────┤
│ Subdomains          │
│ Ports               │
│ Technologies        │
│ Endpoints           │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Vulnerability Scan  │
├─────────────────────┤
│ XSS                 │
│ SQL Injection       │
│ CORS                │
│ SSRF                │
│ Open Redirect       │
│ JWT                 │
│ IDOR                │
│ Information Leak    │
│ Security Headers    │
│ Nuclei              │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│     Reporting       │
├─────────────────────┤
│ JSON                │
│ HTML                │
│ CVSS                │
│ Evidence            │
│ Remediation         │
└─────────────────────┘

The scanner is designed to discover and report potential vulnerabilities rather than perform destructive exploitation.

✨ Features
🔎 Reconnaissance
Subdomain Enumeration

BugScanner combines:

Certificate Transparency via crt.sh
DNS-based enumeration
200+ common subdomain names
Parallel asynchronous DNS resolution
HTTP availability checks

For discovered subdomains, BugScanner records:

IP address
HTTP status
Availability
Host information
🔌 Port Scanning

Three scanning modes are available:

Mode	Ports	Purpose
common	23	Fast initial reconnaissance
extended	30+	Standard assessment
full	1–65535	Comprehensive audit

The scanner can identify services such as:

FTP
SSH
Telnet
SMTP
DNS
HTTP/HTTPS
POP3/IMAP
SMB
MySQL
PostgreSQL
Redis
MongoDB
Elasticsearch
RDP
VNC

Open ports may also receive contextual security hints.

🧬 Technology Fingerprinting

BugScanner identifies technologies using multiple signals.

HTTP Headers

Detects technologies through headers such as:

Server
X-Powered-By
X-Generator
X-Drupal-Cache
X-WordPress
HTML Analysis

Looks for fingerprints associated with:

WordPress
Drupal
Joomla
React
Angular
Next.js
Nuxt.js
Laravel
Rails
Cookies

Examples include:

PHPSESSID
JSESSIONID
ASP.NET_SessionId
csrftoken
connect.sid
🌐 Endpoint Discovery

BugScanner checks common application paths across several categories.

Administration
/admin
/administrator
/wp-admin
/dashboard
/panel
/backend
/manage
APIs
/api
/api/v1
/api/v2
/graphql
/graphiql
/swagger
/api/docs
Authentication
/login
/signin
/signup
/register
/auth
/oauth/token
/forgot-password
Development / Debug
/debug
/test
/console
/phpinfo.php
/info.php
Configuration / Sensitive Files
/.env
/config.php
/.git/HEAD
/backup.zip
/backup.sql
Monitoring
/health
/status
/metrics
/actuator
/actuator/env
/actuator/heapdump
Build / CI Files
/package.json
/composer.json
/Dockerfile
/.travis.yml

Interesting responses such as 200, 401 and 403 are collected for further analysis.

🐞 Vulnerability Detection
Cross-Site Scripting — Reflected XSS

BugScanner identifies URL parameters and evaluates whether controlled input is reflected into HTML responses.

The scanner considers:

Parameter reflection
Response content type
Reflection context
Multiple test inputs
Potential execution context
Severity
Severity	Example
HIGH	Potential executable reflection
MEDIUM	Reflection requiring manual verification

XSS findings should be manually validated because encoding, browser context and WAF behavior can produce false positives.

💉 SQL Injection

BugScanner performs two primary forms of SQL injection detection:

Error-Based Detection

Looks for database-specific error signatures associated with:

MySQL
PostgreSQL
MSSQL
Oracle
SQLite
Time-Based Detection

The scanner establishes baseline response times and compares them against controlled timing tests.

Database-specific behavior can then be inferred from the response characteristics.

⚠️ Time-based SQLi detection is inherently susceptible to network latency, server load and infrastructure instability. Such findings should be treated as potential SQLi until manually verified.

🔀 CORS Misconfiguration

Tests CORS behavior using different origins and evaluates:

Wildcard origins
Arbitrary origin reflection
null origin handling
Subdomain edge cases
Credentialed CORS configurations

Potentially dangerous combinations such as:

Access-Control-Allow-Credentials: true

combined with unsafe origin handling are prioritized.

🌐 SSRF Detection

BugScanner identifies parameters that may potentially influence server-side requests.

Examples include parameters named:

url
uri
link
src
redirect
fetch
proxy
target
host
endpoint
callback
image
feed

The scanner evaluates server responses for indicators suggesting access to internal or metadata resources.

Potential SSRF findings require manual validation in an authorized environment.

↪️ Open Redirect

Detects redirect-oriented parameters such as:

redirect
url
next
goto
return
returnurl
continue
destination
target
to

The scanner examines redirect behavior without automatically following the redirect.

Potential open redirects are reported with supporting evidence.

🔐 JWT Security Analysis

BugScanner can locate JWT-like tokens from:

Authorization headers
Response bodies
Set-Cookie headers

It analyzes token structure and configuration for issues such as:

Unsafe algorithm configuration
Weak signing secrets
Algorithm confusion indicators
Sensitive claims
Missing expiration claims

JWT findings are presented as security indicators requiring appropriate authorization and manual confirmation.

🆔 IDOR Detection

BugScanner attempts to identify object-reference patterns in:

Query Parameters
?id=123
?user_id=123
?order_id=123
?file_id=123
?invoice_id=123
URL Paths
/users/123/profile
/orders/123
/files/123

It compares responses between the original and modified references.

Analysis can include:

HTTP status
Response size
Response structure
Content differences
HTTP method behavior

⚠️ IDOR detection is especially difficult without authenticated sessions. A response difference alone does not prove an authorization vulnerability.

📂 Information Disclosure

BugScanner searches for potentially exposed:

Environment files
Git repositories
Backups
Configuration files
Logs
Database backups
Admin panels
API documentation
CI/CD files
Private keys
Package manifests

It also checks responses for patterns associated with potentially exposed secrets and credentials.

🛡️ Security Headers

Analyzes common security headers including:

Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
Content-Security-Policy
Permissions-Policy

It can also identify potentially unnecessary server/version disclosure.

🧩 Nuclei Integration

If ProjectDiscovery Nuclei is installed, BugScanner can integrate Nuclei results into the main report.

This provides access to a much broader collection of security templates covering areas such as:

CVEs
Exposed panels
Misconfigurations
Default configurations
Subdomain takeover indicators
Technology detection

Nuclei findings are automatically incorporated into the final report.

⚡ Adaptive Rate Limiting

BugScanner uses a per-domain adaptive token bucket.

Default:

10 requests / second

Behavior:

429 response
    ↓
RPS / 2
503 response
    ↓
30 second domain pause

After sustained successful requests:

RPS × 1.2

up to:

50 RPS

This is designed to reduce unnecessary load and adapt scanning speed to target behavior.

📊 Severity System

BugScanner uses a CVSS v3.1-oriented severity model.

Severity	CVSS	Examples
🔴 CRITICAL	9.0–10.0	Critical injection / authentication-impact findings
🟠 HIGH	7.0–8.9	IDOR, serious XSS, sensitive exposure
🟡 MEDIUM	4.0–6.9	Reflected XSS, open redirect, some CORS issues
🔵 LOW	1.0–3.9	Missing security headers
⚪ INFO	0.0–0.9	Technology / banner information

The project also calculates an aggregated risk score based on weighted findings.

Important: Automated severity is an initial prioritization mechanism, not a replacement for manual vulnerability assessment.

📑 Reporting
JSON

Structured JSON output is available for:

Automation
CI pipelines
Custom dashboards
Security tooling integrations

Example:

python cli.py scan https://target.com --format json
HTML

BugScanner generates a modern security report containing:

Overall risk score
Severity statistics
Subdomains
Open ports
Technologies
Endpoints
Vulnerability findings
Evidence
Remediation guidance
References
CVSS information
Search and filtering
Printable/PDF-friendly output
🖥️ Usage
Full Scan
python cli.py scan https://target.com
Recon Only
python cli.py scan https://target.com --mode recon
Vulnerability Scan Only
python cli.py scan https://target.com --mode vulns
Extended Port Scan Without Subdomain Enumeration
python cli.py scan https://target.com --no-subdomains --ports extended
Custom Request Rate
python cli.py scan https://target.com --rps 5
JSON Output
python cli.py scan https://target.com --format json
🏗️ Architecture
BugScanner
│
├── cli.py
│
├── scanner.py
│
├── recon/
│   ├── subdomain.py
│   ├── portscan.py
│   ├── fingerprint.py
│   └── discovery.py
│
├── vulns/
│   ├── xss.py
│   ├── sqli.py
│   ├── cors.py
│   ├── ssrf.py
│   ├── redirect.py
│   ├── jwt.py
│   ├── idor.py
│   ├── disclosure.py
│   └── nuclei_wrapper.py
│
└── core/
    ├── rate_limiter.py
    ├── http_client.py
    ├── models.py
    └── reporter.py

The architecture is intentionally modular so individual reconnaissance and vulnerability modules can evolve independently.

🔄 Scan Pipeline
                    Target URL
                        │
                        ▼
                Domain Normalization
                        │
                        ▼
                 ┌─────────────┐
                 │    RECON    │
                 └──────┬──────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   Subdomains        Ports        Fingerprinting
        │               │               │
        └───────────────┼───────────────┘
                        ▼
                Endpoint Discovery
                        │
                        ▼
              ┌──────────────────┐
              │ Vulnerability    │
              │ Assessment       │
              └────────┬─────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
       XSS            SQLi           SSRF
       CORS           IDOR           JWT
       Redirect       Disclosure     Headers
                       │
                       ▼
                 Nuclei (optional)
                       │
                       ▼
                  CVSS Ranking
                       │
                 ┌─────┴─────┐
                 ▼           ▼
               JSON         HTML
⚠️ Known Limitations

BugScanner is intentionally transparent about what it cannot reliably solve yet.

1. Deep Logical Bugs & Authenticated Scope

The current architecture primarily operates without authenticated user sessions.

This creates a major blind spot for vulnerabilities involving:

Business Logic
Complex IDOR
Privilege Escalation
Multi-user authorization flaws
Account-to-account access
Authenticated API abuse
Workflow manipulation

These vulnerabilities frequently require multiple accounts, application state and a deep understanding of business workflows.

Planned Direction

Future versions may introduce:

Session Management
        ↓
Authenticated Crawling
        ↓
Multi-Role Testing
        ↓
Authorization Mapping
        ↓
Business Logic Analysis
2. False Positives / Blind Scanning

Automated vulnerability detection cannot replace manual validation.

Particularly challenging areas include:

Time-Based SQLi

Network latency and server load can produce misleading timing differences.

Reflected XSS

Detection can be affected by:

JavaScript execution context
HTML encoding
Input sanitization
CSP
WAF filtering
Browser parsing behavior
IDOR

A different HTTP response does not automatically indicate unauthorized access.

Therefore:

BugScanner findings should be treated as candidates for investigation, not guaranteed vulnerabilities.

3. WAF Detection & Rate Restrictions

Modern applications may use:

Cloudflare
Akamai
AWS WAF
Other reverse proxies and security systems

Aggressive automated scanning can result in:

403 Forbidden
429 Too Many Requests
Temporary IP blocking
Challenge pages
Incomplete endpoint discovery

BugScanner's adaptive rate limiter attempts to reduce this problem, but it cannot guarantee that a protected target will allow automated testing.

🚫 What BugScanner Does NOT Do

BugScanner is not designed to perform destructive exploitation.

It does not:

Brute-force login credentials
Perform DoS/flood attacks
Attempt destructive actions
Automatically compromise accounts
Bypass authentication in an uncontrolled manner
Claim automated findings are guaranteed vulnerabilities

Authenticated scanning is currently not implemented and remains a planned area of development.

📦 Requirements
Python 3.11+
httpx
dnspython
beautifulsoup4
jinja2
pyyaml
aiofiles
tldextract
click
rich

Optional:

FastAPI
Nuclei

Example installation:

pip install httpx dnspython beautifulsoup4 jinja2 pyyaml aiofiles tldextract click rich
🎯 Designed For

BugScanner is particularly useful for:

Bug bounty reconnaissance
Web application security assessments
Authorized penetration testing
Security research
CTF/lab environments
Attack-surface mapping
Automated first-pass assessments

It is best used as a recon + vulnerability triage layer, followed by manual verification.

🗺️ Roadmap
Current

Subdomain enumeration

Port scanning

Technology fingerprinting

Endpoint discovery

Reflected XSS detection

SQLi detection

CORS analysis

SSRF indicators

Open Redirect detection

JWT analysis

IDOR heuristics

Information disclosure detection

Security headers

Nuclei integration

Adaptive rate limiting

JSON reporting

HTML reporting

Future

Authenticated scanning

Session/cookie import

Multi-account authorization testing

Role-based access analysis

Deeper business-logic detection

Improved IDOR verification

False-positive reduction engine

WAF-aware scanning

Stateful crawling

JavaScript endpoint extraction

API schema analysis

GraphQL security analysis

Scan history

Diff-based security assessment

CI/CD integration

🔬 Philosophy

BugScanner is built around a simple principle:

Automate the repetitive work. Let the researcher focus on the interesting bugs.

A bug bounty hunter should not have to manually perform the same initial reconnaissance against every target.

BugScanner attempts to automate the first layer:

Discover
   ↓
Map
   ↓
Fingerprint
   ↓
Prioritize
   ↓
Detect
   ↓
Report
   ↓
Manual Verification

The goal is not to replace the researcher.

The goal is to give the researcher a better starting point.

⚖️ Responsible Use

BugScanner must only be used against:

Assets you own
Authorized penetration-testing targets
Bug bounty targets within their defined scope
CTF/lab environments

Always respect the target's:

Scope
Rate limits
Testing policy
Safe-harbor requirements
Prohibited testing rules

The user is responsible for ensuring that their use of BugScanner is authorized.

⭐ Why BugScanner?

Unlike a single-purpose scanner, BugScanner attempts to connect multiple stages of the bug bounty workflow:

Recon
  +
Attack Surface Mapping
  +
Technology Detection
  +
Endpoint Discovery
  +
Vulnerability Detection
  +
Risk Prioritization
  +
Reporting

The long-term goal is to evolve BugScanner from a conventional vulnerability scanner into a research-assistance platform capable of understanding an application's attack surface and guiding manual security investigation.

📜 License
MIT License
⚠️ Disclaimer

This project is provided for educational and authorized security testing purposes.

The developers are not responsible for unauthorized use, damage, data loss, service disruption or any consequences resulting from misuse of the tool.
