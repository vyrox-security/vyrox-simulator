![Vyrox Simulator Banner](assets/vyrox-simulator-banner.png)

# Vyrox Simulator

![Licence](https://img.shields.io/badge/licence-MIT-green?style=flat-square)
![Build](https://img.shields.io/badge/build-alpha-6a737d?style=flat-square)
![Version](https://img.shields.io/badge/version-v0.2.0-005cc5?style=flat-square)
![Platform](https://img.shields.io/badge/platform-bash-4eaa25?style=flat-square)
![Funny](https://img.shields.io/badge/paging%20at%202am-simulate%20instead-6a737d?style=flat-square)

Vyrox Simulator provides deterministic, redacted alert payload generation for integration testing and demos of the Vyrox ingestion and triage pipeline without touching production tenants. Pure shell scripts -- no Python, no Lua, no dependencies beyond `bash`, `openssl`, and `curl`.

Website: vyrox.dev (coming soon)

## Why This Exists

You cannot run realistic SOC integration tests against a real production CrowdStrike tenant every time someone changes a parser or confidence threshold. At best you get inconsistent results. At worst you generate a real incident while trying to test a fake one.

The simulator solves that by producing stable payloads that match real-world alert structure closely enough to exercise normalization, heuristic pattern matching, queueing, and Discord routing. It is boring by design, which is ideal for regression testing.

## Architecture

```text
[Shell Scenario]
    | mimikatz.sh
    v
[simulate.sh]
    | sources scenario, builds JSON payload
    | signs with HMAC-SHA256
    v
[POST /webhook/<source>]
    | local ingestion endpoint
    v
[202 Accepted]
```

Simulated payload coverage includes both CrowdStrike and SentinelOne alerts, defined as pure shell scripts with `build_payload()` functions.

## Quickstart

Prerequisites:

1. bash 4+
2. openssl (for HMAC signing)
3. curl (for HTTP requests)
4. A local Vyrox ingestion service running on `http://localhost:8001`
5. Shared webhook secret matching your local ingestion config

Run a simulation scenario:

```bash
# Run the Mimikatz scenario
./simulate.sh mimikatz \
  --url http://localhost:8001/webhook \
  --secret replace-with-64-hex-characters

# Dry run - see the payload without sending
./simulate.sh mimikatz --dry-run

# Multi-stage attack - run all 8 stages
./simulate.sh lateral --all-stages

# Multi-stage attack - run a single stage
./simulate.sh lateral --stage 5

# Multi-tenancy testing
VYROX_TENANT_ID=acme-corp ./simulate.sh mimikatz
```

## Available Scenarios

| Scenario | Source | Severity | Description |
|----------|--------|----------|-------------|
| `mimikatz` | CrowdStrike | CRITICAL | Credential dumping via LSASS memory |
| `lateral` | CrowdStrike | Mixed | 8-stage attack chain: Initial Access through Exfiltration |
| `ransomware` | CrowdStrike | CRITICAL | File encryption behavior |
| `sentinelone_lateral` | SentinelOne | HIGH | Lateral movement via PsExec |
| `benign` | CrowdStrike | LOW | Scheduled backup job (false positive test) |
| `powershell_encoded` | CrowdStrike | HIGH | Encoded PowerShell download cradle |

## Adding Scenarios

New scenarios are shell scripts in `scenarios/` with a `.sh` extension. Each must:

1. Define `SCENARIO_NAME`, `SCENARIO_SOURCE`, `SCENARIO_SEVERITY`, `SCENARIO_TACTIC`, `SCENARIO_TECHNIQUE`
2. Implement a `build_payload()` function that takes `tenant_id` as its first argument
3. Output valid JSON to stdout

Multi-stage scenarios use the naming convention `<prefix>_stage<N>.sh` (e.g., `lateral_stage1.sh`).

Example:

```bash
#!/usr/bin/env bash
SCENARIO_NAME="my_scenario"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059"

build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "cs-$(date +%s)",
    "customer_id": "${tenant_id}",
    "timestamp": $(date +%s),
    "sensor": { "hostname": "test-host" },
    "process": {
        "user_name": "testuser",
        "file_name": "suspicious.exe",
        "command_line": "suspicious.exe --malicious",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VYROX_URL` | No | `http://localhost:8001/webhook` | Ingestion webhook base URL |
| `VYROX_HMAC_SECRET` | No | `replace-with-64-hex-characters` | HMAC signing secret |
| `VYROX_TENANT_ID` | No | `default-tenant` | Tenant identifier for multi-tenancy |

## Contributing

Contributions are welcome for new simulation scripts, edge-case payloads, and test scenarios. Reproducible false-positive and false-negative simulation cases are particularly useful.

Do not submit raw production customer payloads, unredacted host/user identifiers, or fixtures that cannot be legally shared. Do not add scripts that execute containment actions; this repo simulates alerts only.

See CONTRIBUTING.md for contribution workflow and required review expectations.

Security contact: sec.vyrox@proton.me

## License

This repository is released under the MIT License. See LICENSE for details.
