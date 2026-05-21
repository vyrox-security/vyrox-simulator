#!/usr/bin/env bash
# =============================================================================
# Vyrox Attack Simulator — Pure Shell Script Edition
# =============================================================================
#
# Generates deterministic EDR alert payloads and sends them to the Vyrox
# ingestion service for integration testing. Zero Python/Lua dependencies —
# just bash, openssl (for HMAC), and curl (for HTTP).
#
# Why shell scripts?
#   - No venv to manage, no pip install, no lupa dependency
#   - Scenarios are sourceable .sh files with build_payload() functions
#   - Easy to read, easy to modify, easy to add new scenarios
#   - Works on any machine with bash + openssl + curl (which is most of them)
#
# How it works:
#   1. Source the scenario script (e.g., scenarios/mimikatz.sh)
#   2. Call build_payload(tenant_id) to get the JSON payload
#   3. Sign the payload with HMAC-SHA256 via openssl
#   4. POST to the ingestion webhook with the signature header
#   5. Report the HTTP response code
#
# Security note:
#   The default HMAC secret is a placeholder. For real testing, set
#   VYROX_HMAC_SECRET to match your ingestion service's config.
#   The default secret is "replace-with-64-hex-characters" — if your
#   ingestion service uses the same default, this will work out of the box.
#
# Usage:
#   ./simulate.sh mimikatz
#   ./simulate.sh lateral --stage 1
#   ./simulate.sh lateral --all-stages
#   VYROX_TENANT_ID=acme-corp ./simulate.sh mimikatz
#   ./simulate.sh mimikatz --dry-run
#
# Scenarios:
#   mimikatz              - Credential dumping (CRITICAL)
#   lateral               - Multi-stage lateral movement (8 stages)
#   ransomware            - File encryption behavior (CRITICAL)
#   sentinelone_lateral   - SentinelOne format lateral movement
#   benign                - Benign scheduled backup (LOW)
#   powershell_encoded    - Encoded PowerShell command (HIGH)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIOS_DIR="${SCRIPT_DIR}/scenarios"

# Configuration via environment variables with sensible defaults.
# In production testing, override these to match your deployment.
VYROX_URL="${VYROX_URL:-http://localhost:8001/webhook}"
VYROX_HMAC_SECRET="${VYROX_HMAC_SECRET:-replace-with-64-hex-characters}"
VYROX_TENANT_ID="${VYROX_TENANT_ID:-default-tenant}"

# Color output helpers — because even test tools deserve good UX.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# scenarios_list — Print available scenarios and usage examples
# ---------------------------------------------------------------------------
# Called when the user passes --help or provides an invalid scenario name.
# Lists all available scenarios with their severity levels and common options.
scenarios_list() {
    echo "Available scenarios:"
    echo ""
    echo "  mimikatz              Credential dumping attack (CRITICAL)"
    echo "  lateral               Multi-stage lateral movement (8 stages)"
    echo "  ransomware            File encryption behavior (CRITICAL)"
    echo "  sentinelone_lateral   SentinelOne format lateral movement"
    echo "  benign                Benign scheduled backup (LOW)"
    echo "  powershell_encoded    Encoded PowerShell command (HIGH)"
    echo ""
    echo "Options:"
    echo "  -u, --url URL       Webhook URL (default: ${VYROX_URL})"
    echo "  -s, --secret SEC    HMAC secret (default: from VYROX_HMAC_SECRET)"
    echo "  -t, --tenant ID     Tenant ID for multi-tenancy (default: ${VYROX_TENANT_ID})"
    echo "  --stage N           Run only stage N (for multi-stage scenarios)"
    echo "  --all-stages        Run all stages of multi-stage scenario"
    echo "  --dry-run           Print payload without sending"
    echo "  -h, --help          Show this help"
    echo ""
    echo "Examples:"
    echo "  ./simulate.sh mimikatz"
    echo "  ./simulate.sh lateral --stage 5"
    echo "  ./simulate.sh lateral --all-stages"
    echo "  VYROX_TENANT_ID=acme-corp ./simulate.sh mimikatz"
    echo "  ./simulate.sh mimikatz --dry-run"
}

# ---------------------------------------------------------------------------
# build_signature — Generate HMAC-SHA256 signature for a payload
# ---------------------------------------------------------------------------
# Uses openssl to compute HMAC-SHA256 of the payload with the shared secret.
# The output is the raw hex digest (no "sha256=" prefix — that's added by
# the caller when setting the X-Vyrox-Signature header).
#
# Args:
#   $1: JSON payload string to sign
#   $2: HMAC shared secret (must match the ingestion service's config)
#
# Output:
#   64-character hex digest to stdout
build_signature() {
    local payload="$1"
    local secret="$2"
    echo -n "$payload" | openssl dgst -sha256 -hmac "$secret" | sed 's/^.* //'
}

# ---------------------------------------------------------------------------
# send_alert — POST a signed payload to the ingestion webhook
# ---------------------------------------------------------------------------
# Sends the JSON payload to the appropriate webhook endpoint (/webhook/crowdstrike
# or /webhook/sentinelone) with HMAC-SHA256 signature in the X-Vyrox-Signature
# header. Reports the HTTP response code via colored output.
#
# Args:
#   $1: JSON payload string
#   $2: EDR source ("crowdstrike" or "sentinelone")
#   $3: Webhook base URL
#   $4: HMAC secret for signing
#   $5: Scenario name (for logging)
#   $6: Tenant ID (for logging)
#
# Returns:
#   0 on success (2xx response), 1 on failure (4xx/5xx)
send_alert() {
    local payload="$1"
    local source="$2"
    local url="$3"
    local secret="$4"
    local scenario_name="$5"
    local tenant_id="$6"

    local target_url="${url}/${source}"
    local signature
    signature=$(build_signature "$payload" "$secret")

    info "Target: ${target_url}"
    info "Tenant: ${tenant_id}"
    info "Scenario: ${scenario_name}"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$target_url" \
        -H "Content-Type: application/json" \
        -H "X-Vyrox-Signature: sha256=${signature}" \
        -d "$payload")

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        success "Response: HTTP ${http_code}"
    else
        error "Response: HTTP ${http_code}"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# run_scenario — Source a scenario script and send its payload
# ---------------------------------------------------------------------------
# Sources the scenario .sh file (which defines build_payload and metadata
# variables), calls build_payload(tenant_id) to get the JSON, and sends it
# via send_alert. For multi-stage scenarios, use run_multi_stage instead.
#
# Args:
#   $1: Scenario name (must match a .sh file in scenarios/)
#   $2: Webhook base URL
#   $3: HMAC secret
#   $4: Tenant ID
#   $5: Dry run flag ("true" to print payload without sending)
run_scenario() {
    local scenario_name="$1"
    local url="$2"
    local secret="$3"
    local tenant_id="$4"
    local dry_run="${5:-false}"

    local scenario_script="${SCENARIOS_DIR}/${scenario_name}.sh"

    if [[ ! -f "$scenario_script" ]]; then
        error "Scenario '${scenario_name}' not found at ${scenario_script}"
        echo ""
        scenarios_list
        exit 1
    fi

    # Source the scenario script to get build_payload function
    # shellcheck source=/dev/null
    source "$scenario_script"

    local payload
    payload=$(build_payload "$tenant_id")

    if [[ "$dry_run" == "true" ]]; then
        info "Dry run - payload for scenario: ${SCENARIO_NAME}"
        echo "$payload" | python3 -m json.tool 2>/dev/null || echo "$payload"
        return 0
    fi

    send_alert "$payload" "$SCENARIO_SOURCE" "$url" "$secret" "$SCENARIO_NAME" "$tenant_id"
}

# ---------------------------------------------------------------------------
# run_multi_stage — Execute a multi-stage attack scenario
# ---------------------------------------------------------------------------
# Handles the "lateral" scenario which has 8 stages (initial access through
# exfiltration). Each stage is a separate .sh file (lateral_stage1.sh through
# lateral_stage8.sh). Supports running a single stage (--stage N) or all
# stages (--all-stages) with sequential timing.
#
# Args:
#   $1: Scenario prefix (e.g., "lateral" for lateral_stage*.sh)
#   $2: Webhook base URL
#   $3: HMAC secret
#   $4: Tenant ID
#   $5: Stage number (empty for --all-stages mode)
#   $6: Run all stages flag ("true" or "false")
#   $7: Dry run flag ("true" to print without sending)
run_multi_stage() {
    local scenario_prefix="$1"
    local url="$2"
    local secret="$3"
    local tenant_id="$4"
    local stage_num="${5:-}"
    local run_all="${6:-false}"
    local dry_run="${7:-false}"

    local max_stage=8

    if [[ -n "$stage_num" ]]; then
        local stage_script="${SCENARIOS_DIR}/${scenario_prefix}_stage${stage_num}.sh"
        if [[ ! -f "$stage_script" ]]; then
            error "Stage ${stage_num} not found for scenario '${scenario_prefix}'"
            exit 1
        fi
        run_single_stage "$scenario_prefix" "$stage_num" "$url" "$secret" "$tenant_id" "$dry_run"
    elif [[ "$run_all" == "true" ]]; then
        info "Running all ${max_stage} stages of '${scenario_prefix}'..."
        for i in $(seq 1 "$max_stage"); do
            local stage_script="${SCENARIOS_DIR}/${scenario_prefix}_stage${i}.sh"
            if [[ -f "$stage_script" ]]; then
                echo ""
                info "--- Stage ${i}/${max_stage} ---"
                run_single_stage "$scenario_prefix" "$i" "$url" "$secret" "$tenant_id" "$dry_run"
            fi
        done
    else
        error "Multi-stage scenario '${scenario_prefix}' requires --stage N or --all-stages"
        echo ""
        echo "Available stages: 1-${max_stage}"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# run_single_stage — Execute a single stage of a multi-stage scenario
# ---------------------------------------------------------------------------
# Sources the specific stage script, builds the payload, and sends it.
# Called by run_multi_stage for each stage. Can also be called directly
# for single-stage testing.
#
# Args:
#   $1: Scenario prefix (e.g., "lateral")
#   $2: Stage number (1-8)
#   $3: Webhook base URL
#   $4: HMAC secret
#   $5: Tenant ID
#   $6: Dry run flag ("true" to print without sending)
run_single_stage() {
    local scenario_prefix="$1"
    local stage_num="$2"
    local url="$3"
    local secret="$4"
    local tenant_id="$5"
    local dry_run="${6:-false}"

    local stage_script="${SCENARIOS_DIR}/${scenario_prefix}_stage${stage_num}.sh"

    if [[ ! -f "$stage_script" ]]; then
        error "Stage ${stage_num} not found at ${stage_script}"
        exit 1
    fi

    # shellcheck source=/dev/null
    source "$stage_script"

    local payload
    payload=$(build_payload "$tenant_id")

    if [[ "$dry_run" == "true" ]]; then
        info "Dry run - Stage ${stage_num}: ${SCENARIO_STAGE_NAME}"
        echo "$payload" | python3 -m json.tool 2>/dev/null || echo "$payload"
        return 0
    fi

    info "Stage ${stage_num}: ${SCENARIO_STAGE_NAME} (${SCENARIO_SEVERITY})"
    send_alert "$payload" "$SCENARIO_SOURCE" "$url" "$secret" "${SCENARIO_NAME} (stage ${stage_num})" "$tenant_id"
}

# ---------------------------------------------------------------------------
# main — Parse arguments and dispatch to the appropriate runner
# ---------------------------------------------------------------------------
# Entry point. Parses command-line arguments (--url, --secret, --tenant,
# --stage, --all-stages, --dry-run, --help) and dispatches to run_scenario
# for single-stage scenarios or run_multi_stage for the lateral attack chain.
#
# Environment variables (VYROX_URL, VYROX_HMAC_SECRET, VYROX_TENANT_ID)
# provide defaults that can be overridden by command-line flags.
#
# Exit codes:
#   0: Scenario executed successfully
#   1: Invalid arguments, missing scenario, or HTTP error
main() {
    local scenario=""
    local url="$VYROX_URL"
    local secret="$VYROX_HMAC_SECRET"
    local tenant_id="$VYROX_TENANT_ID"
    local stage_num=""
    local run_all=false
    local dry_run=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) scenarios_list; exit 0 ;;
            -u|--url) url="$2"; shift 2 ;;
            -s|--secret) secret="$2"; shift 2 ;;
            -t|--tenant) tenant_id="$2"; shift 2 ;;
            --stage) stage_num="$2"; shift 2 ;;
            --all-stages) run_all=true; shift ;;
            --dry-run) dry_run=true; shift ;;
            -*) error "Unknown option: $1"; scenarios_list; exit 1 ;;
            *) scenario="$1"; shift ;;
        esac
    done

    if [[ -z "$scenario" ]]; then
        scenarios_list
        exit 1
    fi

    # Check if it's a multi-stage scenario
    if [[ "$scenario" == "lateral" ]]; then
        run_multi_stage "lateral" "$url" "$secret" "$tenant_id" "$stage_num" "$run_all" "$dry_run"
    else
        run_scenario "$scenario" "$url" "$secret" "$tenant_id" "$dry_run"
    fi
}

main "$@"
