#!/usr/bin/env bash
# =============================================================================
# Scenario: Credential access - LSASS memory dump
# =============================================================================
# MITRE ATT&CK: T1003.001
# Tactic:     Credential Access
# Severity:   HIGH (vendor-reported; Vyrox re-triages independently)
#
# procdump taking a full memory dump of lsass.exe to harvest credentials.
#
# Expected Vyrox verdict: HIGH (keyword 'lsass' weight 0.85 -> heuristics accept, skip LLM).
# =============================================================================

SCENARIO_NAME="high_lsass_dump"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Credential Access"
SCENARIO_TECHNIQUE="T1003.001"

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
        "hostname": "win-workstation-04"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "procdump.exe",
        "command_line": "procdump.exe -accepteula -ma lsass.exe C:/Windows/Temp/l.dmp",
        "sha256": "abababababababababababababababababababababababababababababababab"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
