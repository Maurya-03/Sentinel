# ai_engine/risk_scoring.py — CVSS-informed risk scoring and confidence estimation

from __future__ import annotations
from typing import Tuple

# Base scores from knowledge base, adjusted by context
SEVERITY_BASE_SCORES = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0,  8.9),
    "MEDIUM":   (4.0,  6.9),
    "LOW":      (0.1,  3.9),
    "INFO":     (0.0,  0.0),
}

# Confidence levels by detection method
DETECTION_CONFIDENCE = {
    "error_based":   92,   # high — DB error confirms the injection
    "blind_time":    80,   # medium-high — timing is indicative
    "reflected_xss": 95,   # very high — payload confirmed in output
    "port_scan":     99,   # definitive — TCP handshake confirmed
    "header_check":  99,   # definitive — header absent/present is binary
    "rule_based":    75,   # medium — heuristic match
}


def score_finding(finding: dict, kb_entry: dict) -> dict:
    """
    Given a raw finding and its KB entry, compute:
      - numeric_score  (0–10 float)
      - severity       (string)
      - confidence     (percentage string)
    """
    severity = _resolve_severity(finding, kb_entry)
    score    = _compute_score(severity, finding)
    conf     = _compute_confidence(finding)

    return {
        "numeric_score": round(score, 1),
        "severity":      severity,
        "confidence":    f"{conf}%",
    }


def _resolve_severity(finding: dict, kb_entry: dict) -> str:
    # Finding-level severity takes precedence (set by port scanner etc.)
    if "severity" in finding and finding["severity"] in SEVERITY_BASE_SCORES:
        return finding["severity"]
    return kb_entry.get("severity", "MEDIUM")


def _compute_score(severity: str, finding: dict) -> float:
    lo, hi = SEVERITY_BASE_SCORES.get(severity, (0.0, 0.0))
    # Use midpoint + small variance based on finding specifics
    mid = (lo + hi) / 2
    # Slightly bump score for critical findings with working payloads
    if severity == "CRITICAL" and finding.get("payload"):
        mid = min(hi, mid + 0.3)
    return mid


def _compute_confidence(finding: dict) -> int:
    vector = finding.get("vector", "")
    vuln_type = finding.get("type", "")

    if vector == "error_based":
        return DETECTION_CONFIDENCE["error_based"]
    if vector == "blind_time":
        return DETECTION_CONFIDENCE["blind_time"]
    if "XSS" in vuln_type:
        return DETECTION_CONFIDENCE["reflected_xss"]
    if vuln_type == "Open Port":
        return DETECTION_CONFIDENCE["port_scan"]
    if "Header" in vuln_type or "Disclosure" in vuln_type:
        return DETECTION_CONFIDENCE["header_check"]
    return DETECTION_CONFIDENCE["rule_based"]
