# SENTINEL — Automated Web Vulnerability Scanner with Explainable AI

```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

A modular Python-based VAPT scanner with an **Explainable AI engine** that not only detects
vulnerabilities but explains *why* they exist, their real-world impact, and how to fix them.

---

## Architecture

```
Target URL
    │
    ▼
┌──────────────┐     ┌──────────────────────────────────────┐
│   Crawler    │────▶│  Scanner Modules                     │
│  (BFS crawl) │     │  SQLi · XSS · Ports · Headers        │
└──────────────┘     └──────────────┬───────────────────────┘
                                    │
                                    ▼
                     ┌──────────────────────────┐
                     │   Detection Engine       │
                     │  Payloads · Validator    │
                     └──────────────┬───────────┘
                                    │
                                    ▼
                     ┌──────────────────────────┐
                     │   XAI Engine             │
                     │  KB + Optional Ollama    │
                     │  Explanation · Mitigation│
                     │  Risk Scoring            │
                     └──────────────┬───────────┘
                                    │
                          ┌─────────┴──────────┐
                          ▼                    ▼
                    ┌──────────┐        ┌──────────────┐
                    │   JSON   │        │  FastAPI     │
                    │  Report  │        │  REST API    │
                    └──────────┘        └──────┬───────┘
                                               │
                                               ▼
                                       ┌───────────────┐
                                       │  Next.js      │
                                       │  Dashboard    │
                                       └───────────────┘
```

---

## Features

| Module              | Capability                                                   |
|---------------------|--------------------------------------------------------------|
| **Crawler**         | BFS link discovery, form extraction, relative URL handling   |
| **SQLi Scanner**    | Error-based + blind detection, GET/POST params & form fields |
| **XSS Scanner**     | Reflected XSS via GET params and HTML forms                  |
| **Port Scanner**    | Concurrent TCP scan of 19 common ports                       |
| **Header Analyser** | 7 security headers + info-disclosure detection               |
| **XAI Engine**      | Rule-based KB + optional local Ollama LLM enrichment        |
| **Risk Scoring**    | CVSS-informed 0–10 scoring with per-detection confidence    |
| **FastAPI Server**  | REST API + SSE live progress stream                          |
| **Next.js UI**      | Dark glassmorphism dashboard · Charts · OWASP map · Filters  |

---

## Quick Start — Python Scanner (CLI)

### 1. Install dependencies
```bash
cd vapt-scanner
pip install -r requirements.txt
```

### 2. Run a scan
```bash
# Basic scan
python main.py http://testphp.vulnweb.com

# Skip port scanning
python main.py http://testphp.vulnweb.com --no-ports

# Export raw JSON
python main.py http://testphp.vulnweb.com --json -o report.json
```

### 3. Start the API server (for dashboard)
```bash
python -m api.server
# → http://localhost:8000
```

---

## Quick Start — Next.js Dashboard

### 1. Install dependencies
```bash
cd sentinel-ui
npm install
```

### 2. Configure environment
```bash
cp .env.local.example .env.local
# Edit .env.local:
#   NEXT_PUBLIC_USE_MOCK=false   (use real backend)
#   — or —
#   NEXT_PUBLIC_USE_MOCK=true    (use embedded mock data, no backend needed)
```

### 3. Run dev server
```bash
npm run dev
# → http://localhost:3000
```

### 4. Demo mode (no backend)
Visit `http://localhost:3000` and click **Load Demo** to see the full dashboard
with pre-populated scan results — no backend required.

---

## Optional: Local LLM via Ollama

Ollama provides **context-aware AI explanations** beyond the static knowledge base.

```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull a model
ollama pull mistral   # or llama3, gemma2, etc.

# SENTINEL auto-detects Ollama at http://localhost:11434
# Disable LLM in config.py: USE_LLM = False
```

---

## API Reference

| Endpoint                         | Method | Description                        |
|----------------------------------|--------|------------------------------------|
| `POST /api/scan`                 | POST   | Start a scan, returns job ID       |
| `GET  /api/scan/{job_id}`        | GET    | Poll job status + report           |
| `GET  /api/scan/{job_id}/stream` | GET    | SSE live progress stream           |
| `GET  /api/scans`                | GET    | List all scan jobs                 |
| `DELETE /api/scan/{job_id}`      | DELETE | Delete a scan job                  |
| `GET  /api/mock`                 | GET    | Return mock report (dev/demo)      |
| `GET  /health`                   | GET    | Health check                       |

### Start a scan
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://testphp.vulnweb.com", "skip_ports": false}'
```

### Response
```json
{
  "job_id":   "a1b2c3...",
  "status":   "queued",
  "progress": 0,
  "message":  "Scan queued"
}
```

---

## Report Format

```json
{
  "sentinel_version": "1.0.0",
  "scan_timestamp": "2025-01-15T10:30:00Z",
  "target": "http://target.example.com",
  "summary": {
    "total_vulnerabilities": 8,
    "severity_breakdown": { "CRITICAL": 2, "HIGH": 1, "MEDIUM": 3, "LOW": 2, "INFO": 0 },
    "overall_risk_score": 8.4,
    "risk_rating": "HIGH"
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "url": "http://target.example.com/login.php",
      "method": "POST",
      "param": "uname",
      "payload": "' OR '1'='1",
      "severity": "CRITICAL",
      "numeric_score": 9.5,
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "evidence": "Warning: mysql_fetch_array()...",
      "ai_analysis": {
        "explanation": "The login form passes uname directly into a MySQL query...",
        "impact": "Complete authentication bypass...",
        "mitigation": ["Use PDO with prepared statements...", "..."],
        "confidence": "92%",
        "source": "rule_based"
      }
    }
  ]
}
```

---

## Safe Testing Targets

| Target                          | URL                               |
|---------------------------------|-----------------------------------|
| **DVWA**                        | Run via Docker: `docker run -d -p 80:80 vulnerables/web-dvwa` |
| **OWASP Juice Shop**            | `docker run -d -p 3000:3000 bkimminich/juice-shop`           |
| **testphp.vulnweb.com**         | `http://testphp.vulnweb.com` (Acunetix's public demo)        |
| **WebGoat**                     | `docker run -d -p 8080:8080 webgoat/webgoat`                 |

> ⚠️ **Legal Notice**: Only scan systems you own or have explicit written permission to test.
> Unauthorised scanning is illegal in most jurisdictions.

---

## Project Structure

```
vapt-scanner/
├── scanner/            # Core scanning engine
│   ├── crawler.py      # BFS web crawler
│   ├── sqli_scanner.py # SQL injection detection
│   ├── xss_scanner.py  # XSS detection
│   ├── port_scanner.py # TCP port scanner
│   ├── header_analyzer.py # HTTP header audit
│   └── utils.py        # HTTP session, URL helpers
├── detection_engine/   # Logic layer
│   ├── payloads.py     # Payload loader
│   ├── validator.py    # Response analysis
│   └── signatures.py   # Type → KB key mapping
├── report/             # Report generation
│   ├── formatter.py    # Risk scoring + formatting
│   └── report_generator.py # JSON output + CLI printer
├── ai_engine/          # Explainable AI layer
│   ├── analyzer.py     # Main XAI pipeline
│   ├── explanation.py  # Why-it-exists generation
│   ├── mitigation.py   # Fix recommendations
│   └── risk_scoring.py # CVSS-style scoring
├── api/
│   └── server.py       # FastAPI REST server
├── data/
│   ├── payloads.json           # Attack payloads
│   └── known_vulnerabilities.json  # XAI knowledge base
├── main.py             # CLI entry point
├── config.py           # Central configuration
└── requirements.txt

sentinel-ui/
├── src/
│   ├── app/
│   │   ├── page.tsx         # Scan launcher home
│   │   └── dashboard/
│   │       └── page.tsx     # Results dashboard
│   ├── components/
│   │   ├── dashboard/
│   │   │   ├── Navbar.tsx
│   │   │   ├── SummaryBar.tsx
│   │   │   ├── ChartsPanel.tsx
│   │   │   ├── OWASPMap.tsx
│   │   │   ├── FilterBar.tsx
│   │   │   └── VulnCard.tsx
│   │   └── ui/
│   │       ├── SeverityBadge.tsx
│   │       └── ScoreRing.tsx
│   ├── lib/
│   │   ├── api.ts         # API client + polling
│   │   ├── mock-data.ts   # Dev mock report
│   │   └── utils.ts       # cn, severity config
│   └── types/
│       └── scan.ts        # TypeScript types
└── tailwind.config.js
```
