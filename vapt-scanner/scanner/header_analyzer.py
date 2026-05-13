# scanner/header_analyzer.py — HTTP security header analysis

from __future__ import annotations
from typing import List, Dict, Any

from scanner.utils import build_session, safe_get
from scanner.async_http import AsyncHTTPClient
from config import REQUIRED_SECURITY_HEADERS

# Per-header severity and detail map
HEADER_DETAILS = {
    "Content-Security-Policy": {
        "severity":    "MEDIUM",
        "vuln_key":    "MISSING_CSP",
        "description": "CSP header missing — XSS and data injection protections are not enforced by browser.",
    },
    "Strict-Transport-Security": {
        "severity":    "MEDIUM",
        "vuln_key":    "MISSING_HSTS",
        "description": "HSTS missing — connections may be downgraded from HTTPS to HTTP (SSL stripping).",
    },
    "X-Frame-Options": {
        "severity":    "MEDIUM",
        "vuln_key":    "MISSING_X_FRAME_OPTIONS",
        "description": "X-Frame-Options missing — page may be embedded in an iframe (clickjacking risk).",
    },
    "X-XSS-Protection": {
        "severity":    "LOW",
        "vuln_key":    "MISSING_XSS_PROTECTION",
        "description": "X-XSS-Protection missing — legacy browser XSS filter not enforced.",
    },
    "X-Content-Type-Options": {
        "severity":    "LOW",
        "vuln_key":    "MISSING_X_CONTENT_TYPE",
        "description": "X-Content-Type-Options missing — MIME sniffing attacks possible.",
    },
    "Referrer-Policy": {
        "severity":    "LOW",
        "vuln_key":    "MISSING_REFERRER_POLICY",
        "description": "Referrer-Policy missing — full URL may leak in Referer headers to third parties.",
    },
    "Permissions-Policy": {
        "severity":    "LOW",
        "vuln_key":    "MISSING_PERMISSIONS_POLICY",
        "description": "Permissions-Policy missing — browser feature access is not restricted.",
    },
}


def analyze_headers(target_url: str) -> List[Dict[str, Any]]:
    """
    Fetch the target URL and audit its HTTP response headers.
    Returns findings for each missing or misconfigured security header.
    """
    session  = build_session()
    response = safe_get(session, target_url)

    if response is None:
        print(f"[HEADERS] Could not fetch {target_url} ({client.last_error or 'unknown error'})")
        return []

    print(f"[HEADERS] Analysing security headers for {target_url}")
    findings = []
    headers  = {k.lower(): v for k, v in response.headers.items()}

    for header in REQUIRED_SECURITY_HEADERS:
        if header.lower() not in headers:
            detail = HEADER_DETAILS.get(header, {})
            finding = {
                "type":        "Missing Security Header",
                "header":      header,
                "url":         target_url,
                "severity":    detail.get("severity", "LOW"),
                "vuln_key":    detail.get("vuln_key", "MISSING_HEADER"),
                "evidence":    detail.get("description", f"{header} header is absent"),
            }
            findings.append(finding)
            print(f"[HEADERS] Missing: {header}")

    # ── Bonus: check for information disclosure ───────────────────────────
    for info_header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        val = headers.get(info_header.lower())
        if val:
            findings.append({
                "type":     "Information Disclosure",
                "header":   info_header,
                "url":      target_url,
                "severity": "LOW",
                "vuln_key": "INFO_DISCLOSURE",
                "evidence": f"{info_header}: {val} — technology stack revealed to attackers",
            })
            print(f"[HEADERS] Info disclosure: {info_header} = {val}")

    print(f"[HEADERS] Audit complete — {len(findings)} issues found")
    return findings


async def async_analyze_headers(target_url: str, client: AsyncHTTPClient) -> List[Dict[str, Any]]:
    """Async header analysis using a shared HTTP client."""
    response = await client.get(target_url)

    if response is None:
        print(f"[HEADERS] Could not fetch {target_url}")
        return []

    print(f"[HEADERS] Analysing security headers for {target_url}")
    findings: List[Dict[str, Any]] = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    for header in REQUIRED_SECURITY_HEADERS:
        if header.lower() not in headers:
            detail = HEADER_DETAILS.get(header, {})
            finding = {
                "type": "Missing Security Header",
                "header": header,
                "url": target_url,
                "severity": detail.get("severity", "LOW"),
                "vuln_key": detail.get("vuln_key", "MISSING_HEADER"),
                "evidence": detail.get("description", f"{header} header is absent"),
            }
            findings.append(finding)
            print(f"[HEADERS] Missing: {header}")

    for info_header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        val = headers.get(info_header.lower())
        if val:
            findings.append({
                "type": "Information Disclosure",
                "header": info_header,
                "url": target_url,
                "severity": "LOW",
                "vuln_key": "INFO_DISCLOSURE",
                "evidence": f"{info_header}: {val} — technology stack revealed to attackers",
            })
            print(f"[HEADERS] Info disclosure: {info_header} = {val}")

    print(f"[HEADERS] Audit complete — {len(findings)} issues found")
    return findings
