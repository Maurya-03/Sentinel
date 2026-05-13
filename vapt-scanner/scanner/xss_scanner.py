# scanner/xss_scanner.py — Reflected XSS detection

from __future__ import annotations
import asyncio
import urllib.parse
from typing import List, Dict, Any, Optional

from scanner.utils import build_session, safe_get, safe_post, inject_param, truncate
from scanner.crawler import extract_forms, async_extract_forms
from scanner.async_http import AsyncHTTPClient
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


async def async_scan_xss(
    urls: List[str],
    client: Optional[AsyncHTTPClient] = None,
    forms_by_url: Optional[Dict[str, List[dict]]] = None,
) -> List[Dict[str, Any]]:
    """
    Async reflected XSS probe across URLs and forms.
    Executes requests concurrently with early-stop per param/field.
    """
    owns_client = client is None
    client = client or AsyncHTTPClient()
    payloads = get_xss_payloads()
    findings: List[Dict[str, Any]] = []
    findings_lock = asyncio.Lock()

    async def check_get(url: str, param: str) -> None:
        for payload in payloads:
            injected_url = inject_param(url, param, payload)
            resp = await client.get(injected_url)
            if resp is None:
                continue
            if is_xss_reflected(resp.text, payload):
                finding = {
                    "type": "Cross-Site Scripting (XSS)",
                    "subtype": "Reflected",
                    "url": injected_url,
                    "method": "GET",
                    "param": param,
                    "payload": payload,
                    "evidence": truncate(payload),
                }
                async with findings_lock:
                    findings.append(finding)
                print(f"[XSS] ⚠  FOUND at {url} (param={param})")
                return

    async def check_form(url: str, form: dict, field: str) -> None:
        action = form["action"]
        method = form["method"]
        base_data = dict(form["inputs"])
        for payload in payloads:
            test_data = dict(base_data)
            test_data[field] = payload
            if method == "post":
                resp = await client.post(action, data=test_data)
            else:
                resp = await client.get(action, params=test_data)
            if resp is None:
                continue
            if is_xss_reflected(resp.text, payload):
                finding = {
                    "type": "Cross-Site Scripting (XSS)",
                    "subtype": "Reflected",
                    "url": action,
                    "method": method.upper(),
                    "param": field,
                    "payload": payload,
                    "evidence": truncate(payload),
                }
                async with findings_lock:
                    findings.append(finding)
                print(f"[XSS] ⚠  FOUND at {action} (field={field})")
                return

    tasks: List[asyncio.Task] = []
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            tasks.append(asyncio.create_task(check_get(url, param)))

        forms = forms_by_url.get(url, []) if forms_by_url is not None else await async_extract_forms(url, client)
        for form in forms:
            for field in list(form.get("inputs", {}).keys()):
                tasks.append(asyncio.create_task(check_form(url, form, field)))

    if tasks:
        await asyncio.gather(*tasks)

    if owns_client:
        await client.close()
    _deduplicate(findings)
    print(f"[XSS] Async scan complete — {len(findings)} vulnerabilities found")
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
