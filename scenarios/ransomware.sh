#!/usr/bin/env bash
# =============================================================================
# Scenario: Ransomware File Encryption
# =============================================================================
# MITRE ATT&CK: T1486 — Data Encrypted for Impact
# Tactic:     Impact
# Severity:   CRITICAL
#
# What this simulates:
#   A ransomware encryptor targeting specific file types (.docx, .xlsx, .pdf,
#   .pst) with a ransom note. This is the "impact" stage of an attack — the
#   attacker has already gained access, moved laterally, and is now causing
#   damage.
#
# Detection signals:
#   - Command line: contains "--ransom-note" (explicit ransomware indicator)
#   - Command line: contains "--target" and "--extensions" (targeted encryption)
#   - MITRE technique: T1486 (Data Encrypted for Impact)
#
# Expected triage: CRITICAL verdict. This should trigger the ransomware
# playbook (enrich + notify, approval required for isolation).
# =============================================================================

SCENARIO_NAME="ransomware"
SCENARIO_SOURCE="crowdstrike"
SCENARIO_SEVERITY="CRITICAL"
SCENARIO_TACTIC="Impact"
SCENARIO_TECHNIQUE="T1486"

TIMESTAMP=$(date +%s)
DETECT_ID="cs-${TIMESTAMP}"

# build_payload — Generate the CrowdStrike-format ransomware alert payload.
# Args: $1: tenant_id (default: "default-tenant")
build_payload() {
    local tenant_id="${1:-default-tenant}"
    cat <<EOF
{
    "detect_id": "${DETECT_ID}",
    "customer_id": "${tenant_id}",
    "timestamp": ${TIMESTAMP},
    "sensor": {
        "hostname": "win-fileserver-02"
    },
    "process": {
        "user_name": "CORP\\\\svc_backup",
        "file_name": "encryptor.exe",
        "command_line": "encryptor.exe --target C:\\\\Data --extensions .docx,.xlsx,.pdf,.pst --ransom-note README.txt",
        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    },
    "tactic": "${SCENARIO_TACTIC}",
    "technique": "${SCENARIO_TECHNIQUE}",
    "severity": "${SCENARIO_SEVERITY}"
}
EOF
}
