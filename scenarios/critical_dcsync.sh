#!/usr/bin/env bash
# =============================================================================
# Scenario: Credential access - DCSync
# =============================================================================
# MITRE ATT&CK: T1003.006
# Tactic:     Credential Access
# Severity:   CRITICAL (vendor-reported; Vyrox re-triages independently)
#
# DCSync replication of the domain Administrator's secrets from a non-DC host - full domain compromise.
#
# Expected Vyrox verdict: CRITICAL (keyword 'dcsync' weight 0.90).
# =============================================================================

SCENARIO_NAME="critical_dcsync"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Credential Access"
SCENARIO_TECHNIQUE="T1003.006"

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
        "hostname": "win-dc-01"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "SharpKatz.exe",
        "command_line": "SharpKatz.exe lsadump::dcsync /domain:corp.local /user:Administrator",
        "sha256": "5656565656565656565656565656565656565656565656565656565656565656"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
