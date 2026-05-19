#!/usr/bin/env python3
"""
Vyrox Attack Simulator - EDR Alert Generation for Testing

This script executes Lua-based attack scenario definitions and sends
the resulting alerts to the Vyrox ingestion service for testing.

Purpose:
- Test the complete Vyrox pipeline (ingestion -> triage -> Discord)
- Validate detection logic for various attack patterns
- Simulate real-world EDR alerts in a controlled way
- Support red team and adversary simulation exercises

Usage:
    python simulate.py mimikatz --url https://ingest.vyrox.dev
    python simulate.py lateral --secret <hmac-secret>

Scenarios:
    - mimikatz: Credential dumping attack simulation
    - lateral: Lateral movement with WMI/PowerShell
    - ransomware: File encryption behavior
    - sentinelone_lateral: SentinelOne format variant

The script loads scenario definitions from Lua files, executes them
to generate alert payloads, and POSTs to the appropriate webhook
with proper authentication (HMAC for CrowdStrike, Bearer for SentinelOne).
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
from lupa import LuaRuntime

# Default ingestion endpoint - can be overridden via --url flag
# In production, this would be the actual Vyrox ingestion service URL
DEFAULT_INGESTION_URL = "http://localhost:8001/webhook"

# Default HMAC secret for local development
# In production, this MUST be overridden via --secret or VYROX_HMAC_SECRET env var
DEFAULT_SECRET = "replace-with-64-hex-characters"


def build_signature(payload: bytes, secret: str) -> str:
    """
    Build HMAC-SHA256 signature for the request body.

    This function generates a signature that the Vyrox ingestion service
    can verify to ensure the request hasn't been tampered with and
    originated from an authorized source.

    Args:
        payload: Raw bytes of the JSON request body
        secret: Shared secret key for HMAC generation

    Returns:
        Signature string with "sha256=" prefix

    Example:
        >>> body = b'{"alert_id": "test-123"}'
        >>> sig = build_signature(body, "my-secret")
        >>> print(sig)
        sha256=a1b2c3d4e5f6...
    """
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def execute_scenario(lua_path: Path) -> dict[str, Any]:
    """
    Execute a Lua scenario file and return the generated alert payload.

    Lua scenarios define attack sequences that generate realistic EDR alerts.
    The Lua code returns a table with metadata (source, name) and the
    actual alert payload in a vendor-specific format.

    Args:
        lua_path: Path to the .lua scenario file

    Returns:
        Dictionary containing:
        - source: EDR vendor ("crowdstrike" or "sentinelone")
        - name: Human-readable scenario name
        - payload: The alert data to send to ingestion service

    Raises:
        Exception if Lua execution fails or scenario file cannot be read
    """
    # Initialize Lua runtime with tuple unpacking enabled
    # This makes it easier to work with Lua table returns
    lua = LuaRuntime(unpack_returned_tuples=True)

    # Read the Lua scenario code from file
    with open(lua_path, 'r') as f:
        lua_code = f.read()

    # Execute the Lua code which should return a scenario table
    # We wrap in a function to allow the Lua code to use return statements
    scenario_func = lua.eval(f"function() {lua_code} end")
    scenario_data = scenario_func()

    # Convert the Lua table to a Python dictionary
    # The lupa library returns LuaTable objects which we convert for easier handling
    return dict(scenario_data)


def main() -> None:
    """
    Main entry point for the simulator.

    This function:
    1. Parses command-line arguments
    2. Resolves the scenario file path
    3. Executes the Lua scenario to generate an alert
    4. Sends the alert to the Vyrox ingestion service with proper auth
    5. Reports the result to stdout
    """
    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description="Vyrox Lua Simulator - Generate EDR alerts for testing"
    )

    # Required positional argument: scenario name
    # This corresponds to a .lua file in the scenarios directory
    parser.add_argument(
        "scenario",
        help="Name of the scenario to run (e.g., mimikatz, lateral, ransomware)"
    )

    # Optional: Override the default ingestion URL
    parser.add_argument(
        "--url",
        default=DEFAULT_INGESTION_URL,
        help=f"Ingestion webhook URL (default: {DEFAULT_INGESTION_URL})"
    )

    # Optional: Override the default HMAC secret
    # This can also be set via VYROX_HMAC_SECRET environment variable
    parser.add_argument(
        "--secret",
        help="Webhook HMAC secret for request signing"
    )

    # Optional: Override the default scenarios directory
    # Useful for testing custom scenario files
    parser.add_argument(
        "--scenarios-dir",
        default=None,
        help="Directory containing Lua scenarios"
    )

    args = parser.parse_args()

    # Resolve the scenarios directory
    # Default to <script-dir>/../scenarios
    base_dir = Path(__file__).resolve().parents[1]
    scenarios_dir = Path(args.scenarios_dir) if args.scenarios_dir else base_dir / "scenarios"

    # Resolve the secret from args or environment variable
    # Priority: command-line arg > environment variable > default
    secret = args.secret or os.environ.get("VYROX_HMAC_SECRET", DEFAULT_SECRET)

    # Construct the full path to the scenario file
    scenario_path = scenarios_dir / f"{args.scenario}.lua"
    if not scenario_path.exists():
        print(f"Error: Scenario not found at {scenario_path}")
        sys.exit(1)

    # Execute the Lua scenario to generate the alert payload
    try:
        scenario = execute_scenario(scenario_path)
    except Exception as e:
        print(f"Error executing Lua scenario: {e}")
        sys.exit(1)

    # Extract source and payload from the scenario
    # Default to crowdstrike if not specified
    source = scenario.get("source", "crowdstrike")
    payload = dict(scenario.get("payload", {}))

    # Serialize the payload to JSON bytes for the HTTP request
    body = json.dumps(payload).encode("utf-8")

    # Build the target URL based on the source (appends vendor name)
    target_url = f"{args.url.rstrip('/')}/{source}"

    # Set up HTTP headers
    headers = {"Content-Type": "application/json"}

    # Add authentication headers based on the source vendor
    if source == "crowdstrike":
        # CrowdStrike uses HMAC-SHA256 signature
        signature = build_signature(body, secret)
        headers["X-Vyrox-Signature"] = signature
    elif source == "sentinelone":
        # SentinelOne uses Bearer token authentication
        headers["Authorization"] = f"Bearer {secret}"

    # Print diagnostic information
    print(f"--- Running Scenario: {scenario.get('name', args.scenario)} ---")
    print(f"Source: {source}")
    print(f"Target: {target_url}")

    # Send the alert to the ingestion service
    try:
        response = requests.post(target_url, data=body, headers=headers, timeout=10)
        print(f"Response: {response.status_code}")

        # Print error details if the request failed
        if response.status_code >= 400:
            print(f"Error Detail: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending alert: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()