import asyncio
import json
import uuid
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import os

from cookie_oracle.core.cookie_parser import parse_cookie_string, get_cookie_metadata
from cookie_oracle.detectors.platform_detector import detect_platform
from cookie_oracle.analyzers.risk_scorer import calculate_risk_score, get_risk_level, generate_exploitation_matrix
from cookie_oracle.validators.session_validator import SessionValidator

# In-memory history store (use Redis/db in production)
ANALYSIS_HISTORY = {}

app = FastAPI(title="Cookie-Oracle Web UI", version="1.0")

# Mount static files
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "static")), name="static")

class AnalysisRequest(BaseModel):
    cookie: str
    domain: Optional[str] = None
    privilege: Optional[str] = "unknown"

class FileUpload(BaseModel):
    domain: Optional[str] = None
    privilege: Optional[str] = "unknown"

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main dashboard."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Cookie-Oracle - Session Intelligence</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: 'JetBrains Mono', monospace; background: #0f0f0f; color: #00ff41; margin:0; padding:0; }
        .container { max-width: 800px; margin: 2rem auto; padding: 1rem; }
        h1 { color: #00ff41; text-align: center; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }
        textarea { width: 100%; height: 100px; background: #1a1a1a; color: #00ff41; border: 1px solid #333; resize: vertical; padding: 0.5rem; font-size: 0.9rem; }
        input, select { padding: 0.5rem; width: 100%; margin-bottom: 0.5rem; background: #1a1a1a; color: #00ff41; border: 1px solid #333; }
        button { padding: 0.7rem 1.5rem; background: #00ff41; color: #0f0f0f; border: none; cursor: pointer; font-weight: bold; width: 100%; }
        button:hover { background: #00cc33; }
        .result-card { background: #1a1a1a; border: 1px solid #333; padding: 1rem; margin: 1rem 0; border-radius: 4px; }
        .high { color: #ff073a; }
        .medium { color: #ffaa00; }
        .low { color: #00ff41; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { border: 1px solid #333; padding: 0.5rem; text-align: left; }
        th { background: #222; }
        .nav-tabs { display: flex; margin-bottom: 1rem; }
        .nav-tab { padding: 0.5rem 1rem; background: #1a1a1a; border: 1px solid #333; cursor: pointer; margin-right: 0.5rem; }
        .nav-tab.active { background: #00ff41; color: #0f0f0f; font-weight: bold; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
<div class="container">
    <h1>🍪 Cookie-Oracle</h1>
    <p style="text-align:center; color:#aaa;">Advanced Session Intelligence Engine</p>

    <div class="nav-tabs" id="navTabs">
        <div class="nav-tab active" onclick="switchTab('single')">Single Cookie</div>
        <div class="nav-tab" onclick="switchTab('batch')">Batch Upload</div>
        <div class="nav-tab" onclick="switchTab('history')">History</div>
    </div>

    <div id="single" class="tab-content active">
        <h2>Analyze Single Cookie</h2>
        <form id="analyzeForm">
            <label>Session Cookie:</label>
            <textarea id="cookieInput" placeholder="e.g. sessionid=abc123; csrftoken=xyz789"></textarea>
            <label>Domain:</label>
            <input type="text" id="domainInput" placeholder="e.g. instagram.com">
            <label>Privilege Level:</label>
            <select id="privilegeSelect">
                <option value="unknown">Unknown</option>
                <option value="guest">Guest</option>
                <option value="user">User</option>
                <option value="moderator">Moderator</option>
                <option value="admin">Admin</option>
                <option value="root">Root</option>
            </select>
            <button type="submit">🔍 Analyze</button>
        </form>
        <div id="singleResult"></div>
    </div>

    <div id="batch" class="tab-content">
        <h2>Upload Cookie File</h2>
        <form id="batchForm" enctype="multipart/form-data">
            <label>Upload .txt file (one cookie per line):</label>
            <input type="file" name="file" accept=".txt" />
            <label>Domain:</label>
            <input type="text" id="batchDomain" placeholder="Optional">
            <label>Privilege Level:</label>
            <select id="batchPrivilege">
                <option value="unknown">Unknown</option>
                <option value="admin">Admin</option>
                <option value="user">User</option>
            </select>
            <button type="submit">📊 Process Batch</button>
        </form>
        <div id="batchResult"></div>
    </div>

    <div id="history" class="tab-content">
        <h2>📂 Analysis History</h2>
        <div id="historyList">Loading...</div>
    </div>
</div>

<script>
const form = document.getElementById('analyzeForm');
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const cookie = document.getElementById('cookieInput').value;
    const domain = document.getElementById('domainInput').value;
    const privilege = document.getElementById('privilegeSelect').value;

    const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cookie, domain, privilege })
    });

    const data = await resp.json();
    let html = '<div class="result-card">';
    html += `<h3>Platform: ${data.platform} (${data.confidence}%)</h3>`;
    html += `<p>Risk Score: <strong class="${data.risk_level.toLowerCase()}">${data.risk_score} - ${data.risk_level}</strong></p>`;
    html += `<p>Session Status: ${data.session_status.status}</p>`;

    html += '<table><tr><th>Method</th><th>Possible</th><th>Notes</th></tr>';
    data.exploitation_matrix.forEach(m => {
        html += `<tr><td>${m.method}</td><td>${m.possible ? '✅' : '❌'}</td><td>${m.notes}</td></tr>`;
    });
    html += '</table></div>';

    document.getElementById('singleResult').innerHTML = html;
});

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    event.target.classList.add('active');
    if (tabId === 'history') loadHistory();
}

async function loadHistory() {
    const resp = await fetch('/api/history');
    const data = await resp.json();
    let html = '';
    if (data.length === 0) {
        html = 'No history available. Analyze some cookies first!';
    } else {
        html = '<table><tr><th>Date</th><th>Platform</th><th>Risk</th></tr>';
        data.slice().reverse().forEach(item => {
            html += `<tr><td>${new Date(item.timestamp).toLocaleString()}</td>`;
            html += `<td>${item.platform}</td>`;
            html += `<td class="${item.risk_level.toLowerCase()}">${item.risk_score} - ${item.risk_level}</td></tr>`;
        });
        html += '</table>';
    }
    document.getElementById('historyList').innerHTML = html;
}

// Load history on page load if history tab
document.addEventListener('DOMContentLoaded', () => {
    loadHistory();
});
</script>
</body>
</html>
"""

@app.post("/api/analyze")
async def api_analyze(request: AnalysisRequest):
    """API endpoint for single cookie analysis."""
    cookie_dict = parse_cookie_string(request.cookie)
    flags_list = get_cookie_metadata(cookie_dict)
    platform_result = detect_platform(cookie_dict, request.domain)
    primary_platform = platform_result[0]['platform']

    report = {
        "platform": primary_platform,
        "confidence": platform_result[0]['confidence'],
        "privilege_guess": request.privilege,
        "cookies": flags_list,
        "exploitation_matrix": [],
        "risk_score": 0,
        "risk_level": "",
        "session_status": {}
    }

    for flags in flags_list:
        risk_score = calculate_risk_score(primary_platform, flags, request.privilege)
        report["risk_score"] = risk_score
        report["risk_level"] = get_risk_level(risk_score)
        report["exploitation_matrix"] = generate_exploitation_matrix(flags)

    validator = SessionValidator()
    report["session_status"] = await validator.probe_session(cookie_dict, request.domain, primary_platform)

    # Save to history
    session_id = str(uuid.uuid4())
    ANALYSIS_HISTORY[session_id] = {
        **report,
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "cookie_preview": request.cookie[:50] + "..."
    }

    return JSONResponse(report)

@app.get("/api/history")
async def api_history():
    """Get analysis history."""
    return JSONResponse(list(ANALYSIS_HISTORY.values()))

@app.post("/api/batch")
async def api_batch(file: UploadFile = File(...), domain: str = None, privilege: str = "unknown"):
    """Handle batch cookie analysis via file upload."""
    content = await file.read()
    lines = content.decode('utf-8').split('\n')

    results = []
    validator = SessionValidator()
    for line in lines:
        line = line.strip()
        if line:
            cookie_dict = parse_cookie_string(line)
            platform_result = detect_platform(cookie_dict, domain)
            primary_platform = platform_result[0]['platform']
            flags_list = get_cookie_metadata(cookie_dict)
            session_status = await validator.probe_session(cookie_dict, domain, primary_platform)
            flags = flags_list[0] if flags_list else {}
            risk_score = calculate_risk_score(primary_platform, flags, privilege)
            results.append({
                "platform": primary_platform,
                "confidence": platform_result[0]['confidence'],
                "session_status": session_status.get("status", "unknown"),
                "risk_score": risk_score,
                "risk_level": get_risk_level(risk_score)
            })

    return JSONResponse(results)

@app.get("/api/docs")
async def docs():
    """API documentation placeholder."""
    return {"endpoints": ["/api/analyze", "/api/batch", "/api/history"]}