# main.py — SENTINEL VAPT Scanner — Main pipeline entry point

from __future__ import annotations
import sys
import json
import argparse
import warnings
import urllib3
import asyncio

# Keep console output from crashing on Windows when redirected streams use the
# default ANSI code page.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# Suppress SSL warnings for self-signed certs on test targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

from scanner.async_pipeline  import async_run_scan
from report.report_generator import print_report


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

    report = asyncio.run(async_run_scan(target, skip_ports=skip_ports))
    print_report(report)
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
