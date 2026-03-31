# report/report_generator.py — Serialize and save the final scan report

from __future__ import annotations
import json
import os
from typing import Dict, Any
from datetime import datetime

from config import REPORT_OUTPUT_DIR


def save_report(report: Dict[str, Any]) -> str:
    """
    Serialize report to JSON and save to the output directory.
    Returns the path to the saved file.
    """
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    host     = _safe_filename(report.get("target", "unknown"))
    filename = f"sentinel_{host}_{ts}.json"
    path     = os.path.join(REPORT_OUTPUT_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return path


def print_report(report: Dict[str, Any]) -> None:
    """Pretty-print the report summary to stdout."""
    summary = report.get("summary", {})
    vulns   = report.get("vulnerabilities", [])

    print("\n" + "═" * 60)
    print("  SENTINEL — SCAN REPORT")
    print("═" * 60)
    print(f"  Target      : {report.get('target')}")
    print(f"  Timestamp   : {report.get('scan_timestamp')}")
    print(f"  Total Vulns : {summary.get('total_vulnerabilities', 0)}")
    print(f"  Risk Rating : {summary.get('risk_rating')}  ({summary.get('overall_risk_score')}/10)")

    breakdown = summary.get("severity_breakdown", {})
    print(f"\n  Severity Breakdown:")
    for sev, cnt in breakdown.items():
        bar = "█" * cnt if cnt else "·"
        print(f"    {sev:<10} {cnt:>3}  {bar}")

    print("\n" + "─" * 60)
    for i, vuln in enumerate(vulns, 1):
        print(f"\n  [{i}] {vuln.get('type')}  [{vuln.get('severity')}]")
        print(f"      URL     : {vuln.get('url', 'N/A')}")
        if vuln.get("param"):
            print(f"      Param   : {vuln.get('param')}")
        if vuln.get("port"):
            print(f"      Port    : {vuln.get('port')} / {vuln.get('service')}")
        if vuln.get("header"):
            print(f"      Header  : {vuln.get('header')}")
        print(f"      Score   : {vuln.get('numeric_score')}/10  | Confidence: {vuln.get('ai_analysis', {}).get('confidence')}")
        print(f"      CWE     : {vuln.get('cwe')}  |  OWASP: {vuln.get('owasp')}")

        ai = vuln.get("ai_analysis", {})
        if ai.get("explanation"):
            _wrapped_print("Explain", ai["explanation"])
        if ai.get("impact"):
            _wrapped_print("Impact ", ai["impact"])
        if ai.get("mitigation"):
            print(f"      Fix     :")
            for step in ai["mitigation"][:3]:  # print top 3 steps
                print(f"        • {step}")

    print("\n" + "═" * 60)


def _safe_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:40]


def _wrapped_print(label: str, text: str, width: int = 70) -> None:
    words   = text.split()
    line    = f"      {label} : "
    pad     = " " * len(line)
    first   = True
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            print(line + current if first else pad + current)
            first   = False
            current = word
        else:
            current = current + " " + word if current else word
    if current:
        print(line + current if first else pad + current)
