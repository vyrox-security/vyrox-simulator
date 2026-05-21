#!/usr/bin/env bash
# Scenario: Lateral Movement to Exfiltration — Stage 4: Privilege Escalation
# MITRE ATT&CK: T1548 — Abuse Elevation Control Mechanism | Severity: CRITICAL
SCENARIO_NAME="lateral_to_exfil"
SCENARIO_STAGE=4
SCENARIO_STAGE_NAME="Privilege Escalation"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Privilege Escalation"
SCENARIO_TECHNIQUE="T1548"
TIMESTAMP=$(date +%s)
DETECT_ID="cs-stage4-${TIMESTAMP}"
build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{"detect_id":"${DETECT_ID}","customer_id":"${tenant_id}","timestamp":${TIMESTAMP},"sensor":{"hostname":"win-workstation-01"},"process":{"user_name":"CORP\\\\attacker","file_name":"whoami.exe","command_line":"whoami /priv","sha256":"0000000000000000000000000000000000000000000000000000000000000004"},"tactic":"${SCENARIO_TACTIC}","technique":"${SCENARIO_TECHNIQUE}","severity":"${SCENARIO_SEVERITY}"}
EOF
}
