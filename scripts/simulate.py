#!/usr/bin/env python3
"""
Vyrox Lua-based Attack Simulator.
Executes scenarios defined in Lua and posts them to the ingestion service.
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

# Constants
DEFAULT_INGESTION_URL = "http://localhost:8001/webhook"
DEFAULT_SECRET = "replace-with-64-hex-characters"

def build_signature(payload: bytes, secret: str) -> str:
    """Build a sha256= prefixed signature for the request body."""
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"

def execute_scenario(lua_path: Path) -> dict[str, Any]:
    """Execute a Lua scenario file and return the result as a dict."""
    lua = LuaRuntime(unpack_returned_tuples=True)
    with open(lua_path, 'r') as f:
        lua_code = f.read()
    
    # Run the Lua code
    scenario_func = lua.eval(f"function() {lua_code} end")
    scenario_data = scenario_func()
    
    # Convert Lua table to Python dict
    return dict(scenario_data)

def main() -> None:
    parser = argparse.ArgumentParser(description="Vyrox Lua Simulator")
    parser.add_argument("scenario", help="Name of the scenario to run (e.g., mimikatz)")
    parser.add_argument("--url", default=DEFAULT_INGESTION_URL, help="Ingestion webhook URL")
    parser.add_argument("--secret", help="Webhook HMAC secret")
    parser.add_argument("--scenarios-dir", default=None, help="Directory containing Lua scenarios")
    
    args = parser.parse_args()
    
    # Resolve scenarios dir
    base_dir = Path(__file__).resolve().parents[1]
    scenarios_dir = Path(args.scenarios_dir) if args.scenarios_dir else base_dir / "scenarios"
    
    # Resolve secret
    secret = args.secret or os.environ.get("VYROX_HMAC_SECRET", DEFAULT_SECRET)
    
    # Load scenario
    scenario_path = scenarios_dir / f"{args.scenario}.lua"
    if not scenario_path.exists():
        print(f"Error: Scenario not found at {scenario_path}")
        sys.exit(1)
    
    try:
        scenario = execute_scenario(scenario_path)
    except Exception as e:
        print(f"Error executing Lua scenario: {e}")
        sys.exit(1)
        
    source = scenario.get("source", "crowdstrike")
    payload = dict(scenario.get("payload", {}))
    
    # Convert payload to JSON
    body = json.dumps(payload).encode("utf-8")
    
    # Determine URL and headers based on source
    target_url = f"{args.url.rstrip('/')}/{source}"
    headers = {"Content-Type": "application/json"}
    
    if source == "crowdstrike":
        signature = build_signature(body, secret)
        headers["X-Vyrox-Signature"] = signature
    elif source == "sentinelone":
        headers["Authorization"] = f"Bearer {secret}"
        
    print(f"--- Running Scenario: {scenario.get('name', args.scenario)} ---")
    print(f"Source: {source}")
    print(f"Target: {target_url}")
    
    try:
        response = requests.post(target_url, data=body, headers=headers, timeout=10)
        print(f"Response: {response.status_code}")
        if response.status_code >= 400:
            print(f"Error Detail: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending alert: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
