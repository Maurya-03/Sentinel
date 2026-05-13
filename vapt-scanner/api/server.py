# api/server.py — FastAPI REST API server for SENTINEL dashboard

from __future__ import annotations
import json
import uuid
import asyncio
import warnings
import urllib3
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl

# Keep scanner progress logging from crashing on Windows when stdout/stderr are
# redirected to files opened with the default ANSI code page.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# ── Bootstrap sys.path so imports from vapt-scanner root work ────────────
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.crawler         import async_collect_forms, async_crawl
from scanner.sqli_scanner    import async_scan_sqli
from scanner.xss_scanner     import async_scan_xss
from scanner.port_scanner    import scan_ports
from scanner.header_analyzer import async_analyze_headers
from scanner.async_http      import AsyncHTTPClient
from scanner.async_pipeline  import target_unreachable_finding
from ai_engine.analyzer      import analyze
from report.formatter        import format_report
from report.report_generator import save_report
from config import SCAN_WORKERS, TASK_QUEUE_SIZE


app = FastAPI(
    title="SENTINEL API",
    description="Automated Web Vulnerability Scanner with Explainable AI",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store  { job_id: { status, progress, report, error } }
_jobs: Dict[str, Dict[str, Any]] = {}
_job_queue: asyncio.Queue = asyncio.Queue(maxsize=TASK_QUEUE_SIZE)
_workers_started = False


# ── Request / Response Models ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    skip_ports: bool = False


class JobStatus(BaseModel):
    job_id:   str
    status:   str          # queued | running | done | error
    progress: int          # 0–100
    message:  str
    report:   Optional[dict] = None
    error:    Optional[str]  = None


# ── Helpers ───────────────────────────────────────────────────────────────

def _update_job(job_id: str, **kwargs):
    _jobs[job_id].update(kwargs)


async def _run_scan_job(job_id: str, target: str, skip_ports: bool) -> None:
    """Async scan pipeline with concurrent modules."""
    client = None
    try:
        client = AsyncHTTPClient()
        _update_job(job_id, status="running", progress=5, message="Crawling target…")
        urls = await async_crawl(target, client)
        forms_by_url = await async_collect_forms(urls, client)

        _update_job(job_id, progress=25, message=f"Crawled {len(urls)} URLs — scanning SQLi + XSS…")
        sqli_task = asyncio.create_task(async_scan_sqli(urls, client, forms_by_url))
        xss_task = asyncio.create_task(async_scan_xss(urls, client, forms_by_url))
        sqli, xss = await asyncio.gather(sqli_task, xss_task)
        all_findings = sqli + xss

        if not urls:
            all_findings.append(target_unreachable_finding(target))

        if not skip_ports:
            _update_job(job_id, progress=60, message="Running port scan…")
            ports = await asyncio.to_thread(scan_ports, target)
            all_findings.extend(ports)

        _update_job(job_id, progress=75, message="Analysing security headers…")
        headers = await async_analyze_headers(target, client)
        all_findings.extend(headers)

        _update_job(job_id, progress=88, message="Running XAI analysis…")
        enriched = analyze(all_findings)

        report = format_report(target, enriched)
        save_report(report)

        _update_job(job_id, status="done", progress=100, message="Scan complete", report=report)

    except Exception as exc:
        _update_job(job_id, status="error", progress=0, message="Scan failed", error=str(exc))
    finally:
        if client is not None:
            await client.close()


async def _worker() -> None:
    while True:
        job_id, target, skip_ports = await _job_queue.get()
        await _run_scan_job(job_id, target, skip_ports)
        _job_queue.task_done()


@app.on_event("startup")
async def _startup() -> None:
    global _workers_started
    if _workers_started:
        return
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception:
        pass
    for _ in range(SCAN_WORKERS):
        asyncio.create_task(_worker())
    _workers_started = True


# ── Routes ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "SENTINEL API", "version": "1.0.0"}


@app.post("/api/scan", response_model=JobStatus, status_code=202)
async def start_scan(req: ScanRequest):
    target = req.target
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id":   job_id,
        "status":   "queued",
        "progress": 0,
        "message":  "Scan queued",
        "report":   None,
        "error":    None,
        "target":   target,
        "created":  datetime.now(timezone.utc).isoformat(),
    }

    await _job_queue.put((job_id, target, req.skip_ports))
    return _jobs[job_id]


@app.get("/api/scan/{job_id}", response_model=JobStatus)
def get_scan_status(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return _jobs[job_id]


@app.get("/api/scans")
def list_scans():
    """Return all jobs (summary only — no full report body)."""
    return [
        {k: v for k, v in job.items() if k != "report"}
        for job in _jobs.values()
    ]


@app.delete("/api/scan/{job_id}")
def delete_scan(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    del _jobs[job_id]
    return {"deleted": job_id}


# ── SSE progress stream ───────────────────────────────────────────────────

@app.get("/api/scan/{job_id}/stream")
async def stream_progress(job_id: str):
    """Server-Sent Events endpoint for real-time progress updates."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        while True:
            job = _jobs.get(job_id, {})
            payload = json.dumps({
                "job_id":   job.get("job_id"),
                "status":   job.get("status"),
                "progress": job.get("progress"),
                "message":  job.get("message"),
            })
            yield f"data: {payload}\n\n"

            if job.get("status") in ("done", "error"):
                break
            await asyncio.sleep(1.2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Mock data endpoint for frontend development ───────────────────────────

@app.get("/api/mock")
def mock_report():
    """Return a realistic mock scan report for UI development."""
    return {
        "sentinel_version": "1.0.0",
        "scan_timestamp":   "2025-01-15T10:30:00Z",
        "target":           "http://testphp.vulnweb.com",
        "summary": {
            "total_vulnerabilities": 8,
            "severity_breakdown": {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 3, "LOW": 2, "INFO": 0},
            "overall_risk_score": 8.4,
            "risk_rating": "HIGH",
        },
        "vulnerabilities": [
            {
                "type": "SQL Injection", "url": "http://testphp.vulnweb.com/login.php",
                "method": "POST", "param": "uname", "payload": "' OR '1'='1",
                "severity": "CRITICAL", "numeric_score": 9.5,
                "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
                "evidence": "Warning: mysql_fetch_array() expects parameter 1 to be resource",
                "ai_analysis": {
                    "explanation": "The login form passes the uname parameter directly into a MySQL query without parameterization. The payload ' OR '1'='1 manipulates the WHERE clause to always evaluate as true, bypassing authentication.",
                    "impact": "Complete authentication bypass enabling access to any user account including administrators. Database contents extractable via UNION-based or error-based techniques.",
                    "mitigation": ["Use PDO with prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?')", "Never concatenate user input into SQL query strings", "Apply allowlist input validation on the username field", "Run the database user with SELECT-only permissions"],
                    "confidence": "92%", "source": "rule_based",
                },
            },
            {
                "type": "SQL Injection", "url": "http://testphp.vulnweb.com/search.php",
                "method": "GET", "param": "test", "payload": "1' ORDER BY 1--",
                "severity": "CRITICAL", "numeric_score": 9.2,
                "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
                "evidence": "You have an error in your SQL syntax near ORDER BY",
                "ai_analysis": {
                    "explanation": "The search parameter is interpolated directly into an ORDER BY clause, making it exploitable for column enumeration and UNION-based data extraction.",
                    "impact": "Full database enumeration possible. Attacker can extract schema, table names, and all user data.",
                    "mitigation": ["Use whitelisted column names for ORDER BY", "Never accept raw SQL fragments from user input", "Implement parameterized queries throughout"],
                    "confidence": "92%", "source": "rule_based",
                },
            },
            {
                "type": "Cross-Site Scripting (XSS)", "subtype": "Reflected",
                "url": "http://testphp.vulnweb.com/search.php", "method": "GET",
                "param": "searchFor", "payload": "<script>alert('XSS')</script>",
                "severity": "HIGH", "numeric_score": 7.5,
                "cwe": "CWE-79", "owasp": "A03:2021 - Injection",
                "evidence": "<script>alert('XSS')</script> reflected in response body",
                "ai_analysis": {
                    "explanation": "The searchFor parameter value is reflected directly into the HTML response without HTML entity encoding, allowing script injection.",
                    "impact": "Session cookie theft, credential harvesting, account takeover for any user who visits a crafted URL.",
                    "mitigation": ["Apply htmlspecialchars() with ENT_QUOTES on all reflected output", "Implement Content-Security-Policy: default-src 'self'", "Set HttpOnly flag on session cookies"],
                    "confidence": "95%", "source": "rule_based",
                },
            },
            {
                "type": "Missing Security Header", "header": "Content-Security-Policy",
                "url": "http://testphp.vulnweb.com", "severity": "MEDIUM", "numeric_score": 5.4,
                "cwe": "CWE-693", "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "CSP header missing — XSS protections not browser-enforced",
                "ai_analysis": {
                    "explanation": "No Content-Security-Policy header is present, so browsers will execute inline scripts and load resources from any origin.",
                    "impact": "Amplifies XSS risk. Any injected script executes without restriction.",
                    "mitigation": ["Add: Content-Security-Policy: default-src 'self'; script-src 'self'", "Use nonces for any legitimate inline scripts"],
                    "confidence": "99%", "source": "rule_based",
                },
            },
            {
                "type": "Missing Security Header", "header": "Strict-Transport-Security",
                "url": "http://testphp.vulnweb.com", "severity": "MEDIUM", "numeric_score": 5.9,
                "cwe": "CWE-319", "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "HSTS header absent — HTTP downgrade attacks possible",
                "ai_analysis": {
                    "explanation": "Without HSTS, a man-in-the-middle attacker can strip TLS and serve HTTP, intercepting all traffic.",
                    "impact": "Credential theft, session hijacking on untrusted networks.",
                    "mitigation": ["Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", "Submit to HSTS preload list"],
                    "confidence": "99%", "source": "rule_based",
                },
            },
            {
                "type": "Missing Security Header", "header": "X-Frame-Options",
                "url": "http://testphp.vulnweb.com", "severity": "MEDIUM", "numeric_score": 4.3,
                "cwe": "CWE-1021", "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "X-Frame-Options absent — clickjacking via iframe embedding possible",
                "ai_analysis": {
                    "explanation": "The page can be embedded in an iframe on any external domain, enabling UI redressing attacks.",
                    "impact": "Clickjacking — users tricked into clicking hidden, malicious UI elements.",
                    "mitigation": ["Add: X-Frame-Options: DENY", "Or use CSP: frame-ancestors 'none'"],
                    "confidence": "99%", "source": "rule_based",
                },
            },
            {
                "type": "Open Port", "host": "testphp.vulnweb.com",
                "port": 3306, "service": "MySQL",
                "severity": "MEDIUM", "numeric_score": 6.8,
                "cwe": "CWE-200", "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "TCP port 3306 (MySQL) is open and accepting connections from public internet",
                "ai_analysis": {
                    "explanation": "MySQL is exposed directly to the internet on port 3306. This allows direct brute-force attacks against database credentials from any IP.",
                    "impact": "Direct database access if credentials are weak or default. Complete data compromise.",
                    "mitigation": ["Firewall port 3306 to allow only application server IPs", "Never expose database ports to the public internet", "Use SSH tunneling or VPN for remote database access"],
                    "confidence": "99%", "source": "rule_based",
                },
            },
            {
                "type": "Information Disclosure", "header": "Server",
                "url": "http://testphp.vulnweb.com", "severity": "LOW", "numeric_score": 2.1,
                "cwe": "CWE-200", "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "Server: Apache/2.4.7 (Ubuntu) — version disclosed",
                "ai_analysis": {
                    "explanation": "The Server response header reveals the web server name and version, helping attackers identify relevant CVEs.",
                    "impact": "Allows targeted exploitation of known vulnerabilities in the disclosed software version.",
                    "mitigation": ["Set ServerTokens Prod in Apache config to suppress version", "Remove or spoof the Server header with a proxy"],
                    "confidence": "99%", "source": "rule_based",
                },
            },
        ],
    }


if __name__ == "__main__":
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
