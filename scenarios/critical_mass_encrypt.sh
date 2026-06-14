#!/usr/bin/env bash
# =============================================================================
# Scenario: Impact - shadow deletion + mass file encryption
# =============================================================================
# MITRE ATT&CK: T1486
# Tactic:     Impact
# Severity:   CRITICAL (vendor-reported; Vyrox re-triages independently)
#
# Volume shadow copies deleted, then a mass file-encryption run begins - active ransomware impact.
#
# Expected Vyrox verdict: CRITICAL (keyword 'encrypt files' weight 0.90).
# =============================================================================

SCENARIO_NAME="critical_mass_encrypt"
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
        "hostname": "win-finance-05"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "encryptor.exe",
        "command_line": "cmd /c vssadmin delete shadows /all /quiet & encryptor.exe --encrypt files C:/Users",
        "sha256": "9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
