# scanner/async_pipeline.py - Async scan pipeline orchestration

from __future__ import annotations
import asyncio
from typing import Any, Dict, List

from scanner.crawler import async_collect_forms, async_crawl
from scanner.sqli_scanner import async_scan_sqli
from scanner.xss_scanner import async_scan_xss
from scanner.port_scanner import scan_ports
from scanner.header_analyzer import async_analyze_headers
from scanner.async_http import AsyncHTTPClient
from ai_engine.analyzer import analyze
from report.formatter import format_report
from report.report_generator import save_report


def target_unreachable_finding(target: str) -> Dict[str, Any]:
    return {
        "type": "Target Unreachable",
        "url": target,
        "severity": "INFO",
        "vuln_key": "TARGET_UNREACHABLE",
        "evidence": "The scanner could not fetch the target URL. Network access, DNS, firewall rules, target downtime, or an unsupported scheme may be blocking the scan.",
    }


async def async_run_scan(target: str, skip_ports: bool = False) -> Dict[str, Any]:
    """Run the full async SENTINEL pipeline and return the report dict."""
    client = AsyncHTTPClient()
    try:
        print("\n[1/6] Crawling target (async)...")
        urls = await async_crawl(target, client)
        print(f"      -> {len(urls)} URLs discovered\n")

        forms_by_url = await async_collect_forms(urls, client)

        print("[2/6] Running SQL Injection scanner (async)...")
        print("[3/6] Running XSS scanner (async)...")
        sqli_task = asyncio.create_task(async_scan_sqli(urls, client, forms_by_url))
        xss_task = asyncio.create_task(async_scan_xss(urls, client, forms_by_url))
        sqli_findings, xss_findings = await asyncio.gather(sqli_task, xss_task)
        print(f"      -> {len(sqli_findings)} SQLi issues found\n")
        print(f"      -> {len(xss_findings)} XSS issues found\n")

        all_findings: List[Dict[str, Any]] = []
        all_findings.extend(sqli_findings)
        all_findings.extend(xss_findings)

        if not urls:
            all_findings.append(target_unreachable_finding(target))

        if not skip_ports:
            print("[4/6] Running port scanner...")
            ports = await asyncio.to_thread(scan_ports, target)
            all_findings.extend(ports)
            print(f"      -> {len(ports)} open ports found\n")
        else:
            print("[4/6] Port scan skipped (--no-ports flag)\n")

        print("[5/6] Analysing security headers (async)...")
        headers = await async_analyze_headers(target, client)
        all_findings.extend(headers)
        print(f"      -> {len(headers)} header issues found\n")
    finally:
        await client.close()

    print("[6/6] Running Explainable AI analysis...")
    enriched = analyze(all_findings)
    print(f"      -> {len(enriched)} findings enriched\n")

    report = format_report(target, enriched)
    save_report(report)
    return report
