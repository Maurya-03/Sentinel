# ai_engine/mitigation.py — Generate structured mitigation steps from KB + optional LLM

from __future__ import annotations
import json
import requests
from typing import List, Optional

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, USE_LLM, VULN_KB_FILE


def _load_kb() -> dict:
    with open(VULN_KB_FILE, "r") as f:
        return json.load(f)


def get_mitigation(vuln_key: str, finding: dict) -> List[str]:
    """
    Return ordered list of mitigation steps.
    KB provides reliable baseline; LLM can add context-specific additions.
    """
    kb = _load_kb()
    kb_entry = kb.get(vuln_key, {})
    steps    = list(kb_entry.get("mitigation", []))

    if not steps:
        steps = _generic_mitigation(finding)

    if USE_LLM:
        llm_step = _query_ollama_mitigation(vuln_key, finding)
        if llm_step and llm_step not in steps:
            steps.insert(0, f"[AI Recommendation] {llm_step}")

    return steps


def _query_ollama_mitigation(vuln_key: str, finding: dict) -> Optional[str]:
    """
    Ask local Ollama for one concrete, context-specific fix recommendation.
    Returns None if unavailable.
    """
    prompt = (
        f"A web application has a {finding.get('type')} vulnerability at "
        f"{finding.get('url', 'an endpoint')} in the '{finding.get('param', 'a parameter')}' field.\n"
        f"Payload used: {finding.get('payload', 'N/A')}\n\n"
        f"Provide ONE specific, actionable fix recommendation in a single sentence. "
        f"Be concrete — name the function, library, or header to use."
    )

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT,
        )
        if resp.status_code == 200:
            text = resp.json().get("response", "").strip()
            # Only use if it looks like a real recommendation
            return text if 10 < len(text) < 400 else None
    except Exception:
        pass

    return None


def _generic_mitigation(finding: dict) -> List[str]:
    return [
        "Apply strict server-side input validation and output encoding",
        "Review application code for unsanitized data handling",
        "Implement security-focused code review and automated SAST scanning",
        "Apply the principle of least privilege across all application layers",
    ]
