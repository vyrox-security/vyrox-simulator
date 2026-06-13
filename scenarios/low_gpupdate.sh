#!/usr/bin/env bash
# =============================================================================
# Scenario: Benign - Group Policy refresh
# =============================================================================
# MITRE ATT&CK: T1059
# Tactic:     Execution
# Severity:   LOW (vendor-reported; Vyrox re-triages independently)
#
# A scheduled Group Policy refresh on a managed workstation. No attack indicator.
#
# Expected Vyrox verdict: BENIGN/LOW (no malicious pattern -> heuristics return benign, skip LLM).
# =============================================================================

SCENARIO_NAME="low_gpupdate"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="LOW"
SCENARIO_TACTIC="Execution"
SCENARIO_TECHNIQUE="T1059"

# Unique per fire (timestamp + random): the pipeline dedupes on
# (tenant, source, raw_id), so a per-second id would collapse rapid back-to-back
# fires of the same scenario into one alert. The random suffix keeps each fire a
# distinct detection, the way a real EDR assigns a fresh detect_id each time.
TIMESTAMP=$(date +%s)
DETECT_ID="cs-${TIMESTAMP}-${RANDOM}${RANDOM}"

# build_payload - emit the CrowdStrike-format detection JSON for this scenario.
# Args: $1 tenant_id (default "default-tenant").
build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "${DETECT_ID}",
    "customer_id": "${tenant_id}",
    "timestamp": ${TIMESTAMP},
    "sensor": {
        "hostname": "win-workstation-12"
    },
    "process": {
        "user_name": "CORP\\\\svc_gpo",
        "file_name": "gpupdate.exe",
        "command_line": "gpupdate /force /wait:600",
        "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
