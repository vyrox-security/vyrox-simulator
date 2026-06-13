#!/usr/bin/env bash
# =============================================================================
# demo-fire.sh — fire demo alerts by SEVERITY (or by exact scenario name).
# =============================================================================
# The console shows Vyrox's TRIAGE VERDICT, not a label baked into the payload.
# Each severity below has a pool of 5 scenarios whose command lines are chosen
# so triage lands in that bucket (verified against the heuristics engine):
#
#   benign / low  -> heuristics confidence <=0.25 -> BENIGN          (no LLM)
#   medium        -> ambiguous band 0.25-0.75     -> LLM tier decides (~MEDIUM)
#   high          -> a >=0.75 HIGH keyword        -> HIGH            (no LLM)
#   critical      -> a >=0.9 CRITICAL keyword     -> CRITICAL        (no LLM)
#
# A pool fire picks one scenario at RANDOM, so repeated fires show variety.
#
# Usage:
#   ./demo-fire.sh <severity|scenario> [tenant]   one fire (random from a pool,
#                                                  or the exact scenario named)
#   ./demo-fire.sh --both <severity|scenario>     same, at BOTH demo tenants
#   ./demo-fire.sh --all  <severity> [tenant]     fire EVERY scenario in a pool
#   ./demo-fire.sh --populate                     fill every demo tenant with a
#                                                  full LOW->MED->HIGH->CRIT spread
#
# Env overrides (sensible demo defaults):
#   VYROX_URL          ingestion webhook base   (default http://localhost:8001/webhook)
#   VYROX_HMAC_SECRET  the fixed demo secret the seed installs for both tenants
#   DEMO_TENANTS       space-separated tenants  (default "demo-acme demo-globex")
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

# Seed $RANDOM from the nanosecond clock so two back-to-back invocations (each a
# fresh process) don't pick the same scenario from a pool. 10# forces base-10 so
# a leading-zero nanosecond value isn't misread as octal.
RANDOM=$(( 10#$(date +%N) % 32768 ))

VYROX_URL="${VYROX_URL:-http://localhost:8001/webhook}"
VYROX_HMAC_SECRET="${VYROX_HMAC_SECRET:-vyrox-demo-webhook-secret-not-for-production-use}"
DEMO_TENANTS="${DEMO_TENANTS:-demo-acme demo-globex}"

# Severity pools — 5 scenarios each. Edit here to add/remove scenarios; the
# justfile recipes and --populate all read these, so there is one source of truth.
POOL_LOW=(benign low_gpupdate low_software_install low_disk_cleanup low_dns_flush)
POOL_MEDIUM=(medium_certutil medium_scheduled_task medium_rundll32 medium_regsvr32 medium_ps_download)
POOL_HIGH=(high_lsass_dump high_defender_tamper high_kerberoast high_amsi_bypass high_clear_logs)
POOL_CRITICAL=(critical_dcsync critical_lockbit critical_mass_encrypt mimikatz ransomware)

# pool_for <word> — echo the pool array name for a severity word, or empty if the
# word is not a severity (i.e. it is an exact scenario name to fire as-is).
pool_for() {
    case "$1" in
        low|benign|bengin) echo "POOL_LOW" ;;
        medium|med)        echo "POOL_MEDIUM" ;;
        high)              echo "POOL_HIGH" ;;
        critical|crit)     echo "POOL_CRITICAL" ;;
        *)                 echo "" ;;
    esac
}

# fire <scenario> <tenant> — send one alert and let the worker triage it live.
fire() {
    local scenario="$1" tenant="$2"
    echo "  -> firing '${scenario}' at ${tenant}"
    VYROX_URL="$VYROX_URL" VYROX_HMAC_SECRET="$VYROX_HMAC_SECRET" \
        VYROX_TENANT_ID="$tenant" ./simulate.sh "$scenario"
}

# fire_one <severity|scenario> <tenant> — random pick from a pool, or exact name.
fire_one() {
    local word="$1" tenant="$2"
    local pool_name
    pool_name="$(pool_for "$word")"
    if [[ -n "$pool_name" ]]; then
        local -n pool="$pool_name"          # nameref to the chosen pool array
        fire "${pool[$((RANDOM % ${#pool[@]}))]}" "$tenant"
    else
        fire "$word" "$tenant"               # an exact scenario name
    fi
}

# fire_all <severity> <tenant> — fire EVERY scenario in a pool, in order.
fire_all() {
    local word="$1" tenant="$2"
    local pool_name
    pool_name="$(pool_for "$word")"
    [[ -n "$pool_name" ]] || { echo "not a severity pool: ${word}" >&2; exit 1; }
    local -n pool="$pool_name"
    local s
    for s in "${pool[@]}"; do fire "$s" "$tenant"; done
}

case "${1:-}" in
    --populate)
        echo "Populating a full LOW -> MEDIUM -> HIGH -> CRITICAL spread on:${DEMO_TENANTS}"
        for t in $DEMO_TENANTS; do
            for sev in low medium high critical; do fire_all "$sev" "$t"; done
        done
        echo "Done. Every demo account now has the full spread of live-triaged alerts."
        ;;
    --all)
        [[ $# -ge 2 ]] || { echo "usage: $0 --all <severity> [tenant]" >&2; exit 1; }
        fire_all "$2" "${3:-demo-acme}"
        ;;
    --both)
        [[ $# -ge 2 ]] || { echo "usage: $0 --both <severity|scenario>" >&2; exit 1; }
        for t in $DEMO_TENANTS; do fire_one "$2" "$t"; done
        ;;
    "" | -h | --help)
        sed -n '2,33p' "$0"
        ;;
    *)
        fire_one "$1" "${2:-demo-acme}"
        ;;
esac
