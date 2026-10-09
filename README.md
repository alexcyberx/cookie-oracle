# 🍪 Cookie-Oracle
**Advanced Session Intelligence Engine**

Cookie-Oracle ek powerful security tool hai jo session cookies ka analysis karta hai bina kisi login ki zaroorat ke. Ye detect karta hai:
- Platform (Instagram, GitHub, Google, etc.)
- Session validity (active/expired)
- Privilege level guess
- Exploitation possibilities (hijacking, CSRF, replay, fixation)
- Risk scoring (0-100)

---

## 🔧 Installation

### From Source
```bash
git clone https://github.com/yourusername/cookie-oracle.git
cd cookie-oracle
pip install -r requirements.txt
```

### Required Dependencies
Install all dependencies:
```bash
pip install typer httpx rich fastapi uvicorn python-multipart pyyaml tabulate beautifulsoup4 playwright
```

---

## 🚀 Usage

### CLI Mode

#### Single Cookie Analysis:
```bash
python -m cookie_oracle analyze --cookie "sessionid=abc123; csrftoken=xyz789" --domain instagram.com --privilege admin
```

#### Batch Processing:
```bash
python -m cookie_oracle batch --file cookies.txt --domain github.com --privilege user
```

#### Output Formats:
```bash
# JSON output
python -m cookie_oracle analyze --cookie "..." --output json

# CSV output (experimental)
python -m cookie_oracle analyze --cookie "..." --output csv
```

### Web Dashboard

Start the web server:
```bash
python -m cookie_oracle serve --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in browser.

Features:
- Paste cookie directly
- Upload .txt file for batch analysis
- History tracking
- Exploitation matrix visualization
- Dark terminal-themed UI

---

## 📋 Example Outputs

### Terminal Output
```
+-----------------------------------------------------------------------------+
| Platform: Instagram (60% confidence)                                        |
+-----------------------------------------------------------------------------+
Risk Score: 100 - High
Session Status: expired
                             Exploitation Matrix                              
+-----------------------------------------------------------------------------+
| Method            | Possible? | Notes                                       |
|-------------------+-----------+---------------------------------------------|
| Session Hijacking | No        | Cookie sent over HTTP can be intercepted    |
| Session Fixation  | No        | Cookie accessible via JavaScript            |
| CSRF              | Yes       | Weak SameSite policy                        |
| Replay Attack     | Yes       | Ensure server-side session expiry           |
+-----------------------------------------------------------------------------+
```

### JSON Output Structure
```json
{
  "platform": "Instagram",
  "confidence": 60,
  "risk_score": 100,
  "risk_level": "High",
  "session_status": {"status": "active", "confidence": 90},
  "exploitation_matrix": [...]
}
```

---

## 🛠️ Modules

| Module | Path | Purpose |
|--------|------|---------|
| Cookie Parser | `core/cookie_parser.py` | Parse cookie strings |
| Platform Detector | `detectors/platform_detector.py` | Identify platform from cookie names/domains |
| Session Validator | `validators/session_validator.py` | HTTP probing to check session validity |
| Risk Scorer | `analyzers/risk_scorer.py` | Calculate risk scores + exploitation matrix |
| Web Server | `web/server.py` | FastAPI web dashboard |

---

## ⚠️ Legal Disclaimer
This tool is for **educational purposes only**. Unauthorized access to systems is illegal. Only test on systems you own or have explicit permission to audit.

---

## 🤝 Contributing
Pull requests welcome! Open an issue if you find bugs or want new features.

## 📄 License
MIT License