# scanner/sqli_scanner.py — SQL Injection detection via error-based and response analysis

from __future__ import annotations
import urllib.parse
from typing import List, Dict, Any

from scanner.utils import build_session, safe_get, safe_post, inject_param, truncate
from scanner.crawler import extract_forms
from detection_engine.payloads import get_sqli_payloads
from detection_engine.validator import is_sqli_response


def scan_sqli(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Run SQL Injection probes across all discovered URLs.
    Tests both GET query parameters and POST form fields.
    """
    session  = build_session()
    findings = []
    payloads = get_sqli_payloads()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # ── Test GET parameters ───────────────────────────────────────────
        for param in params:
            for payload in payloads:
                injected_url = inject_param(url, param, payload)
                response = safe_get(session, injected_url)

                if response and is_sqli_response(response.text):
                    finding = {
                        "type":     "SQL Injection",
                        "url":      injected_url,
                        "method":   "GET",
                        "param":    param,
                        "payload":  payload,
                        "evidence": truncate(_extract_evidence(response.text)),
                        "vector":   "error_based",
                    }
                    findings.append(finding)
                    print(f"[SQLi] ⚠  FOUND at {url} (param={param})")
                    break  # one confirmed finding per param is sufficient

        # ── Test POST forms ───────────────────────────────────────────────
        forms = extract_forms(url, session)
        for form in forms:
            action = form["action"]
            method = form["method"]
            base_data = dict(form["inputs"])

            for field in list(base_data.keys()):
                for payload in payloads:
                    test_data = dict(base_data)
                    test_data[field] = payload

                    if method == "post":
                        response = safe_post(session, action, data=test_data)
                    else:
                        response = safe_get(session, action, params=test_data)

                    if response and is_sqli_response(response.text):
                        finding = {
                            "type":    "SQL Injection",
                            "url":     action,
                            "method":  method.upper(),
                            "param":   field,
                            "payload": payload,
                            "evidence": truncate(_extract_evidence(response.text)),
                            "vector":  "error_based",
                        }
                        findings.append(finding)
                        print(f"[SQLi] ⚠  FOUND at {action} (field={field})")
                        break

    _deduplicate(findings)
    print(f"[SQLi] Scan complete — {len(findings)} vulnerabilities found")
    return findings


def _extract_evidence(body: str) -> str:
    """Pull the most relevant snippet from the response body."""
    lower = body.lower()
    keywords = ["sql", "syntax", "warning", "error", "mysql", "ora-", "sqlite"]
    for kw in keywords:
        idx = lower.find(kw)
        if idx != -1:
            return body[max(0, idx - 30): idx + 120].strip()
    return body[:200]


def _deduplicate(findings: List[Dict]) -> None:
    """Remove duplicate (url, param) pairs in place."""
    seen = set()
    i = 0
    while i < len(findings):
        key = (findings[i]["url"], findings[i]["param"])
        if key in seen:
            findings.pop(i)
        else:
            seen.add(key)
            i += 1
