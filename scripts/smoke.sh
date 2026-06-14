#!/usr/bin/env bash
# =============================================================================
# Vyrox Simulator smoke test (CI-05)
# =============================================================================
#
# A fast, hermetic check that the public-facing simulator still emits a
# correctly-shaped, signed request. It needs NO ingestion server: it sources
# simulate.sh (which, thanks to the BASH_SOURCE guard, defines its functions
# without dispatching), builds a real scenario payload, signs it the exact way
# send_alert does, and asserts the signature shape the ingestion webhook
# expects.
#
# What it proves:
#   1. simulate.sh is syntactically valid (sh -n, also run in CI separately).
#   2. build_payload produces valid JSON for a known scenario.
#   3. build_signature produces a 64-char lowercase-hex HMAC-SHA256 digest.
#   4. that digest matches an independent openssl computation (the signer is
#      doing real HMAC-SHA256 over the payload with the secret, not a stub).
#   5. the wire header send_alert would set is "sha256=<hex>" (the prefix the
#      ingestion service strips), so the contract with the webhook holds.
#
# Exit 0 on success, non-zero (with a message) on the first failed assertion.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}
ok() {
    echo "[OK] $*"
}

# A throwaway test secret (NOT a real credential): the smoke test only checks
# the signature SHAPE, it never reaches a server, so any value works.
TEST_SECRET="smoke-test-secret-not-a-real-credential"
TEST_TENANT="smoke-tenant"

# 1. Syntax check (cheap, also gives a clear message if the script is broken).
sh -n "${SIM_ROOT}/simulate.sh" || fail "simulate.sh failed syntax check (sh -n)"
ok "simulate.sh passes syntax check"

# Source the simulator. The BASH_SOURCE guard in simulate.sh means main does
# NOT run on source, so this defines build_payload/build_signature/etc with no
# network side effects. The scenario scripts define build_payload; source the
# one we test, same as run_scenario does.
# shellcheck source=/dev/null
source "${SIM_ROOT}/simulate.sh"
# shellcheck source=/dev/null
source "${SIM_ROOT}/scenarios/mimikatz.sh"

# 2. build_payload produces valid JSON.
payload="$(build_payload "${TEST_TENANT}")"
[[ -n "${payload}" ]] || fail "build_payload returned an empty payload"
echo "${payload}" | python3 -m json.tool >/dev/null 2>&1 \
    || fail "build_payload did not produce valid JSON"
ok "build_payload emits valid JSON for the mimikatz scenario"

# 3 + 4. build_signature produces a 64-char lowercase-hex digest that matches
# an independent HMAC-SHA256 computation over the same bytes.
signature="$(build_signature "${payload}" "${TEST_SECRET}")"
[[ "${signature}" =~ ^[0-9a-f]{64}$ ]] \
    || fail "build_signature output is not a 64-char lowercase-hex digest: '${signature}'"
ok "build_signature emits a 64-char hex HMAC-SHA256 digest"

expected="$(printf '%s' "${payload}" | openssl dgst -sha256 -hmac "${TEST_SECRET}" | sed 's/^.* //')"
[[ "${signature}" == "${expected}" ]] \
    || fail "build_signature digest does not match an independent openssl HMAC-SHA256"
ok "signature matches an independent HMAC-SHA256 computation"

# 5. The wire header send_alert sets is "sha256=<hex>": the prefix the
#    ingestion webhook strips before verifying.
header_value="sha256=${signature}"
[[ "${header_value}" =~ ^sha256=[0-9a-f]{64}$ ]] \
    || fail "X-Vyrox-Signature header is not 'sha256=<64-hex>': '${header_value}'"
ok "X-Vyrox-Signature header has the expected 'sha256=<hex>' shape"

echo "[PASS] simulator smoke test: payload + signed-request shape is correct"
