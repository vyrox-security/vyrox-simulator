#!/usr/bin/env bash
# =============================================================================
# Scenario: Suspicious - rundll32 proxy execution
# =============================================================================
# MITRE ATT&CK: T1218
# Tactic:     Defense Evasion
# Severity:   MEDIUM (vendor-reported; Vyrox re-triages independently)
#
# rundll32 invoking a control-panel applet from a user-writable path - a known proxy-exec technique.
#
# Expected Vyrox verdict: MEDIUM (ambiguous -> LLM tier).
# =============================================================================

SCENARIO_NAME="medium_rundll32"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="MEDIUM"
SCENARIO_TACTIC="Defense Evasion"
SCENARIO_TECHNIQUE="T1218"

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
        "hostname": "win-workstation-09"
    },
    "process": {
        "user_name": "CORP\\\\rlee",
        "file_name": "rundll32.exe",
        "command_line": "rundll32.exe shell32.dll,Control_RunDLL C:/Users/Public/x.cpl",
        "sha256": "7777777777777777777777777777777777777777777777777777777777777777"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
