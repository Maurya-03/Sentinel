# ai_engine/analyzer.py — Orchestrates the full XAI analysis pipeline

from __future__ import annotations
import json
from typing import List, Dict, Any

from detection_engine.signatures import resolve_vuln_key
from ai_engine.explanation import get_explanation, get_impact
from ai_engine.mitigation import get_mitigation
from ai_engine.risk_scoring import score_finding
from config import VULN_KB_FILE

_OLLAMA_AVAILABLE = None


def _load_kb() -> dict:
    with open(VULN_KB_FILE, "r") as f:
        return json.load(f)


def analyze(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich each raw finding with XAI output:
      - explanation  (why it exists)
      - impact       (what could happen)
      - mitigation   (how to fix it)
      - confidence   (detection reliability %)
      - severity     (CRITICAL / HIGH / MEDIUM / LOW)
      - numeric_score (0–10 CVSS-style)
      - cwe / owasp  (from KB)

    Returns an enriched findings list sorted by numeric_score descending.
    """
    kb = _load_kb()
    enriched = []

    for finding in findings:
        vuln_key = resolve_vuln_key(finding) or finding.get("vuln_key")
        kb_entry = kb.get(vuln_key, {})

        scores   = score_finding(finding, kb_entry)
        expl     = get_explanation(vuln_key, finding) if vuln_key else _fallback_explanation(finding)
        impact   = get_impact(vuln_key, finding)      if vuln_key else _fallback_impact(finding)
        mitigations = get_mitigation(vuln_key, finding) if vuln_key else []

        enriched_finding = {
            **finding,
            "severity":      scores["severity"],
            "numeric_score": scores["numeric_score"],
            "cwe":           kb_entry.get("cwe", "N/A"),
            "owasp":         kb_entry.get("owasp", "N/A"),
            "ai_analysis": {
                "explanation": expl,
                "impact":      impact,
                "mitigation":  mitigations,
                "confidence":  scores["confidence"],
                "source":      "llm+kb" if _llm_available() else "rule_based",
            },
        }
        enriched.append(enriched_finding)

    # Sort by severity score — critical issues first
    enriched.sort(key=lambda x: x.get("numeric_score", 0), reverse=True)
    print(f"[AI] Analysis complete — {len(enriched)} findings enriched")
    return enriched


def _llm_available() -> bool:
    """Quick check if Ollama is reachable (no import of config at module level)."""
    global _OLLAMA_AVAILABLE
    if _OLLAMA_AVAILABLE is not None:
        return _OLLAMA_AVAILABLE
    from config import USE_LLM, OLLAMA_BASE_URL
    if not USE_LLM:
        _OLLAMA_AVAILABLE = False
        return False
    try:
        import requests
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
        _OLLAMA_AVAILABLE = r.status_code == 200
    except Exception:
        _OLLAMA_AVAILABLE = False
    return _OLLAMA_AVAILABLE


def _fallback_explanation(finding: dict) -> str:
    return (
        f"{finding.get('type', 'Vulnerability')} detected at {finding.get('url', 'target')}. "
        "Insufficient validation or misconfiguration allows this attack vector."
    )


def _fallback_impact(finding: dict) -> str:
    return "Potential security risk — consult OWASP guidelines for this vulnerability class."
