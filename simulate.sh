#!/usr/bin/env bash
# Vyrox Attack Simulator - Pure Shell Script Edition
#
# Generates deterministic EDR alert payloads and sends them to the
# Vyrox ingestion service for testing. No Python or Lua dependencies.
#
# Usage:
#   ./simulate.sh mimikatz
#   ./simulate.sh lateral --stage 1
#   ./simulate.sh lateral --all-stages
#   VYROX_TENANT_ID=acme-corp ./simulate.sh mimikatz
#
# Scenarios:
#   mimikatz              - Credential dumping (CRITICAL)
#   lateral               - Multi-stage lateral movement (8 stages)
#   ransomware            - File encryption behavior (CRITICAL)
#   sentinelone_lateral   - SentinelOne format lateral movement
#   benign                - Benign scheduled backup (LOW)
#   powershell_encoded    - Encoded PowerShell command (HIGH)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIOS_DIR="${SCRIPT_DIR}/scenarios"

VYROX_URL="${VYROX_URL:-http://localhost:8001/webhook}"
VYROX_HMAC_SECRET="${VYROX_HMAC_SECRET:-replace-with-64-hex-characters}"
VYROX_TENANT_ID="${VYROX_TENANT_ID:-default-tenant}"

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

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

build_signature() {
    local payload="$1"
    local secret="$2"
    echo -n "$payload" | openssl dgst -sha256 -hmac "$secret" | sed 's/^.* //'
}

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
