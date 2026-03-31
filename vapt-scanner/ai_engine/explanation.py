# ai_engine/explanation.py — Generate explanations from KB and optionally local LLM

from __future__ import annotations
import json
import requests
from typing import Optional

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, USE_LLM, VULN_KB_FILE


def _load_kb() -> dict:
    with open(VULN_KB_FILE, "r") as f:
        return json.load(f)


def get_explanation(vuln_key: str, finding: dict) -> str:
    """
    Return a plain-English explanation of why this vulnerability exists.
    Tries local LLM first (if enabled), falls back to KB.
    """
    kb = _load_kb()
    kb_entry = kb.get(vuln_key, {})
    base_explanation = kb_entry.get("explanation", _generic_explanation(finding))

    if USE_LLM:
        llm_result = _query_ollama_explanation(vuln_key, finding, base_explanation)
        if llm_result:
            return llm_result

    return base_explanation


def get_impact(vuln_key: str, finding: dict) -> str:
    """Return impact statement from KB."""
    kb = _load_kb()
    kb_entry = kb.get(vuln_key, {})
    return kb_entry.get("impact", _generic_impact(finding))


def _query_ollama_explanation(vuln_key: str, finding: dict, fallback: str) -> Optional[str]:
    """
    Query local Ollama LLM to generate a context-aware explanation.
    Returns None if Ollama is unavailable.
    """
    prompt = (
        f"You are a cybersecurity expert. A vulnerability scan found the following issue:\n"
        f"Type: {finding.get('type')}\n"
        f"URL: {finding.get('url', 'N/A')}\n"
        f"Parameter: {finding.get('param', 'N/A')}\n"
        f"Payload: {finding.get('payload', 'N/A')}\n"
        f"Evidence: {finding.get('evidence', 'N/A')}\n\n"
        f"In 2-3 sentences, explain WHY this vulnerability exists in plain English. "
        f"Focus on the root cause, not just the definition. Be specific to the context above."
    )

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT,
        )
        if resp.status_code == 200:
            text = resp.json().get("response", "").strip()
            return text if len(text) > 20 else None
    except Exception:
        pass

    return None


def _generic_explanation(finding: dict) -> str:
    return (
        f"The application at {finding.get('url', 'the target URL')} "
        f"was found to be vulnerable to {finding.get('type', 'an unclassified attack')}. "
        f"Insufficient input validation or missing security controls allow this attack vector."
    )


def _generic_impact(finding: dict) -> str:
    return (
        "Exploitation of this vulnerability could lead to data compromise, "
        "unauthorized access, or degraded security posture."
    )
