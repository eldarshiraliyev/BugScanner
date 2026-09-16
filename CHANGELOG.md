# Changelog

All notable changes to BugScanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.1.0] — 2026-09-15

### Added
- **Structured logging** via `structlog` (`core/logger.py`)
- **Retry logic** with exponential backoff (`tenacity`) in `HttpClient`
- **HTTP response caching** — 30–40% fewer requests on re-scans
- **Scan diff engine** (`core/differ.py`) — compare two scans and highlight deltas
- **SARIF 2.1.0 export** (`core/sarif_reporter.py`) — GitHub Security tab integration
- **API key authentication** for FastAPI backend (`BUGSCANNER_API_KEY`)
- **CLI `diff` command** — `python cli.py diff old.json new.json`
- **Test suite** with `pytest`, `pytest-asyncio`, `respx` — 40+ tests
- **Dockerfile** and **docker-compose.yml**
- **GitHub Actions CI** workflow
- **`pyproject.toml`** for modern packaging and `pip install -e .`
- **`.env.example`** for environment configuration

### Fixed
- **Rate limiter double-refill bug** — actual RPS was ~20% higher than configured
- **Nuclei template path** — now reads from `settings.yaml` instead of ignored
- **WAF evasion** now uses public API instead of mutating private state
- **False positives** — SPA fallback detection, body similarity, fake-404 baseline
- **IDOR HTTP method scanning** — now SPA-aware with 4-layer verification

### Changed
- `HttpClient` retries transient 5xx/429 responses automatically
- `BugScanner` accepts `enable_cache` parameter
- Report now includes SARIF alongside JSON/HTML

## [2.0.0] — 2026-09-01

### Added
- Modern report UI (dark/light theme, sidebar, bento grid)
- Chunked port scanning for full 1–65535 range
- Isolated subdomain HTTP client
- Multi-DB SQLi time-based verification (`WAITFOR`, `pg_sleep`, `BENCHMARK`)
- Business logic scanner (mass assignment, price manipulation, rate-limit bypass)
- `--cookie`, `--header`, `--proxy`, `--business-logic` CLI flags
- `false_positives_filtered` field in ScanResult

## [1.0.0] — 2026-08-01

### Added
- Initial public release
- Recon, vulnerability scanning, reporting