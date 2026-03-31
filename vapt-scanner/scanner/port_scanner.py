# scanner/port_scanner.py — TCP port scanner using Python sockets

from __future__ import annotations
import socket
import concurrent.futures
from typing import List, Dict, Any
from urllib.parse import urlparse

from config import COMMON_PORTS, PORT_TIMEOUT

# Well-known port → service name mapping
PORT_SERVICE_MAP = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev",
    27017: "MongoDB",
}

# Ports that are unexpected on a public web server → flag as medium risk
RISKY_PORTS = {23, 1433, 3306, 3389, 5432, 5900, 6379, 27017}


def scan_ports(target_url: str) -> List[Dict[str, Any]]:
    """
    Scan COMMON_PORTS on the target host using concurrent TCP probes.
    Returns list of open port findings.
    """
    host = urlparse(target_url).hostname
    if not host:
        print("[PORTS] Could not extract hostname — skipping")
        return []

    print(f"[PORTS] Scanning {host} ({len(COMMON_PORTS)} ports)…")
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(_probe, host, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port   = futures[future]
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    print(f"[PORTS] Scan complete — {len(open_ports)} open ports")
    return open_ports


def _probe(host: str, port: int) -> Dict[str, Any] | None:
    """Attempt a TCP connect to host:port. Returns a finding dict or None."""
    try:
        with socket.create_connection((host, port), timeout=PORT_TIMEOUT):
            service = PORT_SERVICE_MAP.get(port, "Unknown")
            risky   = port in RISKY_PORTS

            print(f"[PORTS] Open: {host}:{port} ({service})")
            return {
                "type":     "Open Port",
                "host":     host,
                "port":     port,
                "service":  service,
                "severity": "MEDIUM" if risky else "LOW",
                "risky":    risky,
                "evidence": f"TCP port {port} ({service}) is open and accepting connections",
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
