# Backend Schema: Cookie-Oracle

## Database: cookie_oracle.db (SQLite)
Used for caching platform signatures, storing user history.

Tables:
1. analyses
 - id INTEGER PRIMARY KEY AUTOINCREMENT
 - hash TEXT UNIQUE (fingerprint of cookie/platform combo)
 - platform TEXT
 - result_json TEXT (full JSON report)
 - created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

2. platform_signatures
 - id INTEGER PRIMARY KEY AUTOINCREMENT
 - domain_pattern TEXT (e.g., *.instagram.com)
 - cookie_name_patterns TEXT (e.g., sessionid, csrftoken)
 - platform_name TEXT (e.g., Instagram)
 - risk_profile TEXT (low/medium/high)

3. custom_rules
 - id INTEGER PRIMARY KEY AUTOINCREMENT
 - rule_name TEXT
 - pattern TEXT
 - action TEXT
 - enabled BOOLEAN DEFAULT TRUE

## Session Flow (CLI/Web)
1. On analyze request:
 - Hash incoming cookie
 - Check local cache first
 - If miss → perform live probe
 - Store result in DB
 - Return formatted output

## Authentication
- No backend auth needed (tool is fully offline)
- Optional password protection for web dashboard (future enhancement)