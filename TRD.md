# Technical Requirements Document (TRD): Cookie-Oracle

## 1. Architecture Overview
Cookie-Oracle will be a modular, CLI-based Python application with optional web dashboard.

Components:
1. Input Parser: Accepts cookie strings, files, or browser exports
2. Core Engine: Performs analysis and orchestration
3. Platform Detectors: Regex + signature-based identification
4. Session Validator: Lightweight HTTP probes (no full login required)
5. Report Generator: Outputs JSON/XML/CSV/HTML/Markdown
6. Risk Scorer: Weighted scoring system based on flags and behaviors

## 2. Tech Stack
Language: Python 3.10+
CLI Framework: Typer (fast, modern CLI builder)
HTTP Library: HTTPX (async support)
Browser Automation: Playwright (for live probing)
Data Storage: SQLite (local cache of known platforms/signatures)
Threat Feeds Integration:
 - PhishTank API
 - Google Safe Browsing API
 - Custom blocklist files

## 3. APIs Used
- Internal probing only (no external API calls by default)
- Optional integrations:
 - Shodan API (for domain reputation)
 - VirusTotal API (domain/malware checks)

## 4. Modules Breakdown
| Module | Purpose |
|--------------------|----------------------------------|
| cli.py | CLI entry point & argument parsing |
| core/engine.py | Main logic orchestrator |
| detectors/platform_detector.py | Detect owning platform |
| validators/session_validator.py | Check session validity |
| analyzers/risk_scorer.py | Calculate risk scores |
| reporters/report_generator.py | Format output |
| cache/signatures.db | Local database of signatures |

## 5. Non-functional Requirements
- Must run on Linux, macOS, Windows
- Single executable via PyInstaller/Nuitka
- No internet connection required (offline mode)
- Configurable via YAML config file