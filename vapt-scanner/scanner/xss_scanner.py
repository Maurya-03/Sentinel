# scanner/xss_scanner.py — Reflected XSS detection

from __future__ import annotations
import urllib.parse
from typing import List, Dict, Any

from scanner.utils import build_session, safe_get, safe_post, inject_param, truncate
from scanner.crawler import extract_forms
from detection_engine.payloads import get_xss_payloads
from detection_engine.validator import is_xss_reflected


def scan_xss(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Probe each URL and form for reflected XSS.
    Injects payloads and checks if they appear unescaped in the response.
    """
    session  = build_session()
    findings = []
    payloads = get_xss_payloads()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # ── Test GET parameters ───────────────────────────────────────────
        for param in params:
            for payload in payloads:
                injected_url = inject_param(url, param, payload)
                response = safe_get(session, injected_url)

                if response and is_xss_reflected(response.text, payload):
                    findings.append({
                        "type":     "Cross-Site Scripting (XSS)",
                        "subtype":  "Reflected",
                        "url":      injected_url,
                        "method":   "GET",
                        "param":    param,
                        "payload":  payload,
                        "evidence": truncate(payload),
                    })
                    print(f"[XSS] ⚠  FOUND at {url} (param={param})")
                    break

        # ── Test POST forms ───────────────────────────────────────────────
        forms = extract_forms(url, session)
        for form in forms:
            action    = form["action"]
            method    = form["method"]
            base_data = dict(form["inputs"])

            for field in list(base_data.keys()):
                for payload in payloads:
                    test_data = dict(base_data)
                    test_data[field] = payload

                    if method == "post":
                        response = safe_post(session, action, data=test_data)
                    else:
                        response = safe_get(session, action, params=test_data)

                    if response and is_xss_reflected(response.text, payload):
                        findings.append({
                            "type":    "Cross-Site Scripting (XSS)",
                            "subtype": "Reflected",
                            "url":     action,
                            "method":  method.upper(),
                            "param":   field,
                            "payload": payload,
                            "evidence": truncate(payload),
                        })
                        print(f"[XSS] ⚠  FOUND at {action} (field={field})")
                        break

    _deduplicate(findings)
    print(f"[XSS] Scan complete — {len(findings)} vulnerabilities found")
    return findings


def _deduplicate(findings: List[Dict]) -> None:
    seen = set()
    i = 0
    while i < len(findings):
        key = (findings[i]["url"], findings[i]["param"])
        if key in seen:
            findings.pop(i)
        else:
            seen.add(key)
            i += 1
