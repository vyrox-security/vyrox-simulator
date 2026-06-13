#!/usr/bin/env bash
# =============================================================================
# Scenario: Suspicious - new scheduled task
# =============================================================================
# MITRE ATT&CK: T1053
# Tactic:     Persistence
# Severity:   MEDIUM (vendor-reported; Vyrox re-triages independently)
#
# A new hourly SYSTEM scheduled task pointing at ProgramData - possible persistence, possible legit installer.
#
# Expected Vyrox verdict: MEDIUM (ambiguous -> LLM tier).
# =============================================================================

SCENARIO_NAME="medium_scheduled_task"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="MEDIUM"
SCENARIO_TACTIC="Persistence"
SCENARIO_TECHNIQUE="T1053"

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
        "hostname": "win-workstation-18"
    },
    "process": {
        "user_name": "CORP\\\\mbrown",
        "file_name": "schtasks.exe",
        "command_line": "schtasks /create /tn SystemUpdater /tr C:/ProgramData/upd.exe /sc hourly /ru SYSTEM",
        "sha256": "6666666666666666666666666666666666666666666666666666666666666666"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
