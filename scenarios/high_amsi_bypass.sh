#!/usr/bin/env bash
# =============================================================================
# Scenario: Defense evasion - AMSI bypass
# =============================================================================
# MITRE ATT&CK: T1562.001
# Tactic:     Defense Evasion
# Severity:   HIGH (vendor-reported; Vyrox re-triages independently)
#
# An in-memory AMSI bypass so later malicious script content evades scanning.
#
# Expected Vyrox verdict: HIGH (keyword 'amsi' weight 0.80).
# =============================================================================

SCENARIO_NAME="high_amsi_bypass"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Defense Evasion"
SCENARIO_TECHNIQUE="T1562.001"

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
        "hostname": "win-workstation-31"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "powershell.exe",
        "command_line": "powershell -nop -c [Ref].Assembly.GetType('...').amsiInitFailed amsi bypass",
        "sha256": "1212121212121212121212121212121212121212121212121212121212121212"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
