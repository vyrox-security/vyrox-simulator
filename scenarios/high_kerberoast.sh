#!/usr/bin/env bash
# =============================================================================
# Scenario: Credential access - Kerberoasting
# =============================================================================
# MITRE ATT&CK: T1558.003
# Tactic:     Credential Access
# Severity:   HIGH (vendor-reported; Vyrox re-triages independently)
#
# Rubeus requesting service tickets to crack offline (Kerberoasting).
#
# Expected Vyrox verdict: HIGH (keyword 'kerberoast' weight 0.85).
# =============================================================================

SCENARIO_NAME="high_kerberoast"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Credential Access"
SCENARIO_TECHNIQUE="T1558.003"

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
        "hostname": "win-workstation-29"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "Rubeus.exe",
        "command_line": "Rubeus.exe kerberoast /outfile:C:/Windows/Temp/hashes.txt",
        "sha256": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
