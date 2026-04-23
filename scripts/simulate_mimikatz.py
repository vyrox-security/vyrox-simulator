#!/usr/bin/env python3
"""Send a signed Mimikatz fixture alert to the Vyrox webhook."""

import argparse
import hashlib
import hmac
import json
from pathlib import Path

import requests

DEFAULT_SECRET = "replace-with-64-hex-characters"


def build_signature(payload: bytes, secret: str) -> str:
    """Build a sha256= prefixed signature for the request body."""

    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def load_fixture() -> dict[str, object]:
    """Load the default CrowdStrike Mimikatz fixture from disk."""

    fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "crowdstrike_mimikatz.json"
    with fixture_path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def main() -> None:
    """Post fixture payload to ingestion endpoint and print status line."""

    parser = argparse.ArgumentParser(description="Simulate a Mimikatz alert")
    parser.add_argument("--url", default="http://localhost:8001/webhook")
    parser.add_argument("--secret", default=DEFAULT_SECRET)
    args = parser.parse_args()

    payload = load_fixture()
    body = json.dumps(payload).encode("utf-8")
    signature = build_signature(body, args.secret)

    response = requests.post(
        args.url,
        data=body,
        headers={"Content-Type": "application/json", "X-Vyrox-Signature": signature},
        timeout=10,
    )
    print(f"[vyrox-simulator] Alert sent -> HTTP {response.status_code}")


if __name__ == "__main__":
    main()
