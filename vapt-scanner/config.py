# config.py — Central configuration for SENTINEL VAPT Scanner

import os

# ── Target Settings ─────────────────────────────────────────────────────────
DEFAULT_TIMEOUT     = 8          # seconds per HTTP request
MAX_CRAWL_DEPTH     = 3          # how deep to follow links
MAX_PAGES           = 50         # max pages to crawl per target
USER_AGENT          = "SENTINEL/1.0 (Security Scanner; +https://sentinel.dev)"

# ── Async/Concurrency Settings ───────────────────────────────────────────
HTTP_MAX_CONCURRENCY = 20        # max in-flight HTTP requests
HTTP_RATE_LIMIT_RPS  = 6         # per-target requests per second
HTTP_RETRIES         = 2         # retry attempts for transient errors
HTTP_BACKOFF_BASE    = 0.4       # seconds (exponential backoff base)
DNS_CACHE_TTL        = 300       # seconds to cache DNS lookups
TASK_QUEUE_SIZE      = 500       # max queued crawl/scan tasks
SCAN_WORKERS         = 2         # concurrent scan jobs in API server

# ── Crawl Filtering ─────────────────────────────────────────────────────
EXCLUDED_EXTENSIONS  = {
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
}

# ── Scanner Settings ─────────────────────────────────────────────────────────
COMMON_PORTS        = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                       3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017]
PORT_TIMEOUT        = 1.5        # seconds per port probe

# ── AI Engine ────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL     = "http://localhost:11434"
OLLAMA_MODEL        = "mistral"   # or llama3, gemma, etc.
OLLAMA_TIMEOUT      = 20          # seconds to wait for local LLM
USE_LLM             = True        # set False to force rule-based only

# ── Report Settings ──────────────────────────────────────────────────────────
REPORT_OUTPUT_DIR   = "./reports"
REPORT_FORMAT       = "json"      # json | html

# ── Data Paths ───────────────────────────────────────────────────────────────
DATA_DIR            = os.path.join(os.path.dirname(__file__), "data")
PAYLOADS_FILE       = os.path.join(DATA_DIR, "payloads.json")
VULN_KB_FILE        = os.path.join(DATA_DIR, "known_vulnerabilities.json")

# ── Severity Levels ──────────────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

# ── HTTP Headers to Verify ───────────────────────────────────────────────────
REQUIRED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
