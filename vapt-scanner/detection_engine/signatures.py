# detection_engine/signatures.py — Vulnerability type classification and metadata

from __future__ import annotations
from typing import Optional


VULN_TYPE_KEYS = {
    "SQL Injection":                       "SQL_INJECTION",
    "Cross-Site Scripting (XSS)":          "XSS",
    "Open Port":                           "OPEN_PORT",
    "Missing Security Header":             None,  # resolved per-finding via vuln_key
    "Information Disclosure":              "INFO_DISCLOSURE",
    "Path Traversal":                      "PATH_TRAVERSAL",
    "Open Redirect":                       "OPEN_REDIRECT",
    "Target Unreachable":                  "TARGET_UNREACHABLE",
}

HEADER_VULN_KEYS = {
    "Content-Security-Policy":     "MISSING_CSP",
    "Strict-Transport-Security":   "MISSING_HSTS",
    "X-Frame-Options":             "MISSING_X_FRAME_OPTIONS",
    "X-Content-Type-Options":      "MISSING_X_CONTENT_TYPE",
    "X-XSS-Protection":            "MISSING_XSS_PROTECTION",
    "Referrer-Policy":             "MISSING_REFERRER_POLICY",
    "Permissions-Policy":          "MISSING_PERMISSIONS_POLICY",
}


def resolve_vuln_key(finding: dict) -> Optional[str]:
    """
    Given a raw finding dict, return the knowledge-base lookup key.
    Handles the special case of header findings that have per-header keys.
    """
    vuln_type = finding.get("type", "")

    if vuln_type == "Missing Security Header":
        header = finding.get("header", "")
        return HEADER_VULN_KEYS.get(header)

    return VULN_TYPE_KEYS.get(vuln_type)
