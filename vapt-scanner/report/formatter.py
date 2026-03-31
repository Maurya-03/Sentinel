# report/formatter.py — Clean up and normalize the findings list before output

from __future__ import annotations
from typing import List, Dict, Any
from datetime import datetime, timezone
from config import SEVERITY


def format_report(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build the final structured report object from enriched findings.
    """
    severity_counts = _count_severities(findings)
    risk_score      = _overall_risk(severity_counts)

    return {
        "sentinel_version": "1.0.0",
        "scan_timestamp":   datetime.now(timezone.utc).isoformat(),
        "target":           target,
        "summary": {
            "total_vulnerabilities": len(findings),
            "severity_breakdown":    severity_counts,
            "overall_risk_score":    risk_score,
            "risk_rating":          _risk_label(risk_score),
        },
        "vulnerabilities": [_clean_finding(f) for f in findings],
    }


def _clean_finding(finding: dict) -> dict:
    """Remove internal fields not needed in the final report."""
    exclude = {"vector", "risky"}  # internal scanner fields
    return {k: v for k, v in finding.items() if k not in exclude}


def _count_severities(findings: List[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _overall_risk(counts: dict) -> float:
    """
    Weighted risk score 0–10.
    Critical issues dominate; low issues have minimal effect.
    """
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    raw = sum(weights[sev] * cnt for sev, cnt in counts.items())
    # Cap at 10, scale logarithmically for large finding counts
    if raw == 0:
        return 0.0
    import math
    score = min(10.0, math.log10(raw + 1) * 4.5)
    return round(score, 1)


def _risk_label(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"
