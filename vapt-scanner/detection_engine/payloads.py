# detection_engine/payloads.py — Load and expose attack payloads from data/payloads.json

from __future__ import annotations
import json
from typing import List
from config import PAYLOADS_FILE


def _load() -> dict:
    with open(PAYLOADS_FILE, "r") as f:
        return json.load(f)


def get_sqli_payloads() -> List[str]:
    data = _load()
    return (
        data.get("sqli", {}).get("error_based", [])
        + data.get("sqli", {}).get("blind_time", [])
    )


def get_xss_payloads() -> List[str]:
    data = _load()
    return (
        data.get("xss", {}).get("reflected", [])
        + data.get("xss", {}).get("dom", [])
    )


def get_sqli_error_signatures() -> List[str]:
    data = _load()
    return data.get("sqli", {}).get("error_signatures", [])


def get_path_traversal_payloads() -> List[str]:
    data = _load()
    return data.get("path_traversal", [])
