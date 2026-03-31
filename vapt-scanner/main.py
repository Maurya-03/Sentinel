# main.py — SENTINEL VAPT Scanner — Main pipeline entry point

from __future__ import annotations
import sys
import json
import argparse
import warnings
import urllib3

# Suppress SSL warnings for self-signed certs on test targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

from scanner.crawler        import crawl
from scanner.sqli_scanner   import scan_sqli
from scanner.xss_scanner    import scan_xss
from scanner.port_scanner   import scan_ports
from scanner.header_analyzer import analyze_headers
from ai_engine.analyzer     import analyze
from report.formatter       import format_report
from report.report_generator import save_report, print_report


BANNER = r"""
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

  Automated Web Vulnerability Scanner · Explainable AI Engine
  ─────────────────────────────────────────────────────────────
"""


def run_scan(target: str, skip_ports: bool = False) -> dict:
    """
    Execute the full SENTINEL scan pipeline against target.
    Returns the final structured report dict.
    """
    print(BANNER)
    print(f"  [*] Target : {target}")
    print(f"  [*] Modules: Crawler · SQLi · XSS · Ports · Headers · XAI\n")
    print("─" * 60)

    all_findings = []

    # ── 1. Crawl ──────────────────────────────────────────────────────────
    print("\n[1/6] Crawling target…")
    urls = crawl(target)
    print(f"      → {len(urls)} URLs discovered\n")

    # ── 2. SQL Injection ──────────────────────────────────────────────────
    print("[2/6] Running SQL Injection scanner…")
    sqli_findings = scan_sqli(urls)
    all_findings.extend(sqli_findings)
    print(f"      → {len(sqli_findings)} SQLi issues found\n")

    # ── 3. XSS ────────────────────────────────────────────────────────────
    print("[3/6] Running XSS scanner…")
    xss_findings = scan_xss(urls)
    all_findings.extend(xss_findings)
    print(f"      → {len(xss_findings)} XSS issues found\n")

    # ── 4. Port Scan ──────────────────────────────────────────────────────
    if not skip_ports:
        print("[4/6] Running port scanner…")
        port_findings = scan_ports(target)
        all_findings.extend(port_findings)
        print(f"      → {len(port_findings)} open ports found\n")
    else:
        print("[4/6] Port scan skipped (--no-ports flag)\n")

    # ── 5. Header Analysis ───────────────────────────────────────────────
    print("[5/6] Analysing security headers…")
    header_findings = analyze_headers(target)
    all_findings.extend(header_findings)
    print(f"      → {len(header_findings)} header issues found\n")

    # ── 6. XAI Analysis ──────────────────────────────────────────────────
    print("[6/6] Running Explainable AI analysis…")
    enriched = analyze(all_findings)
    print(f"      → {len(enriched)} findings enriched\n")

    # ── Report ────────────────────────────────────────────────────────────
    report = format_report(target, enriched)
    path   = save_report(report)
    print_report(report)
    print(f"\n  [✓] Report saved → {path}\n")

    return report


def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL — Automated Web Vulnerability Scanner with XAI"
    )
    parser.add_argument("target",         help="Target URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("--no-ports",     action="store_true", help="Skip port scanning")
    parser.add_argument("--json",         action="store_true", help="Print raw JSON report to stdout")
    parser.add_argument("--output", "-o", type=str, default=None, help="Save JSON to specific file path")

    args = parser.parse_args()

    # Ensure scheme is present
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    report = run_scan(target, skip_ports=args.no_ports)

    if args.json:
        print(json.dumps(report, indent=2))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  [✓] JSON saved → {args.output}")


if __name__ == "__main__":
    main()
