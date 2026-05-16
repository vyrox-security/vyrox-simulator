![Vyrox Simulator Banner](assets/vyrox-simulator-banner.png)

# Vyrox Simulator

![Licence](https://img.shields.io/badge/licence-MIT-green?style=flat-square)
![Build](https://img.shields.io/badge/build-alpha-6a737d?style=flat-square)
![Version](https://img.shields.io/badge/version-v0.1.0-005cc5?style=flat-square)
![Platform](https://img.shields.io/badge/platform-python-3776ab?style=flat-square)
![Funny](https://img.shields.io/badge/paging%20at%202am-simulate%20instead-6a737d?style=flat-square)

Vyrox Simulator provides deterministic, redacted alert payload generation for integration testing and demos of the Vyrox ingestion and triage pipeline without touching production tenants. It exists as a separate repository so engineers and design partners can test end-to-end behavior with realistic inputs while keeping the execution-critical open-core proxy auditable and isolated for zero-trust security review.

Website: vyrox.dev (coming soon)

## Why This Exists

You cannot run realistic SOC integration tests against a real production CrowdStrike tenant every time someone changes a parser or confidence threshold. At best you get inconsistent results. At worst you generate a real incident while trying to test a fake one.

The simulator solves that by producing stable payloads that match real-world alert structure closely enough to exercise normalization, heuristic pattern matching, queueing, and Discord routing. It is boring by design, which is ideal for regression testing.

Keeping this tooling separate also makes demo preparation less fragile. Product walkthroughs should depend on deterministic fixtures, not live threat telemetry and luck.

## Architecture

```text
[Lua Scenario]
	| mimikatz.lua
	v
[scripts/simulate.py]
	| executes Lua scenario
	| builds vendor-specific headers
	v
[POST /webhook/<source>]
	| local ingestion endpoint
	v
[202 Accepted]
```

Simulated payload coverage includes both CrowdStrike and SentinelOne alerts, defined as dynamic Lua scenarios.

## Quickstart

Prerequisites:

1. Python 3.11+
2. A local Vyrox ingestion service running on `http://localhost:8001`
3. Shared webhook secret matching your local ingestion config

1. Install dependencies.

```bash
# Install simulator runtime requirements
python -m pip install -r requirements.txt
```

2. Run a Lua simulation scenario.

```bash
# Run the Mimikatz scenario
python scripts/simulate.py mimikatz \
  --url http://localhost:8001/webhook \
  --secret replace-with-64-hex-characters
```

3. Verify the response indicates acceptance.

```bash
# Expected output includes: Response: 202
```

## Adding Scenarios

New scenarios should be added to the `scenarios/` directory as `.lua` files. A scenario must return a table containing:
- `name`: string
- `source`: "crowdstrike" or "sentinelone"
- `payload`: table matching the vendor's alert schema

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| N/A | No | N/A | This repository uses command-line flags, not environment variables. |

## Contributing

Contributions are welcome for new simulation scripts, fixture quality, edge-case payloads, and tests that ensure parser compatibility when vendor schemas drift. Reproducible false-positive and false-negative simulation cases are particularly useful.

Do not submit raw production customer payloads, unredacted host/user identifiers, or fixtures that cannot be legally shared. Do not add scripts that execute containment actions; this repo simulates alerts only.

See CONTRIBUTING.md for contribution workflow and required review expectations. External contributions are welcome in this repository because it is the safest place to improve coverage quickly.

Security contact: sec.vyrox@proton.me

## License

This repository is released under the MIT License. See LICENSE for details.