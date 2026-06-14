#!/usr/bin/env bash
# =============================================================================
# Scenario: Impact - LockBit ransomware
# =============================================================================
# MITRE ATT&CK: T1486
# Tactic:     Impact
# Severity:   CRITICAL (vendor-reported; Vyrox re-triages independently)
#
# The LockBit ransomware encryptor launched against the file-share host.
#
# Expected Vyrox verdict: CRITICAL (keyword 'lockbit' weight 0.95).
# =============================================================================

SCENARIO_NAME="critical_lockbit"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Impact"
SCENARIO_TECHNIQUE="T1486"

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
        "hostname": "win-fileserver-02"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "lockbit.exe",
        "command_line": "lockbit.exe -path C:/Shares -threads 8",
        "sha256": "7878787878787878787878787878787878787878787878787878787878787878"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
