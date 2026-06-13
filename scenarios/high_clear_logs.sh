#!/usr/bin/env bash
# =============================================================================
# Scenario: Defense evasion - clearing event logs
# =============================================================================
# MITRE ATT&CK: T1070.001
# Tactic:     Defense Evasion
# Severity:   HIGH (vendor-reported; Vyrox re-triages independently)
#
# Clearing the Security/System/Application event logs to destroy forensic evidence.
#
# Expected Vyrox verdict: HIGH (keyword 'clear-eventlog' weight 0.75).
# =============================================================================

SCENARIO_NAME="high_clear_logs"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="HIGH"
SCENARIO_TACTIC="Defense Evasion"
SCENARIO_TECHNIQUE="T1070.001"

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
        "hostname": "win-fileserver-01"
    },
    "process": {
        "user_name": "CORP\\\\attacker",
        "file_name": "wevtutil.exe",
        "command_line": "powershell Clear-EventLog -LogName Security,System,Application",
        "sha256": "3434343434343434343434343434343434343434343434343434343434343434"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
