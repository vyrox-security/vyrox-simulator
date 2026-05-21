# Vyrox Simulator Justfile
# =====================================================================
# Production-grade task runner for alert simulation scripts.
# MIT licensed - pure shell, no Python/Lua dependencies.
#
# Usage:
#   just              # Show all commands
#   just <command>   # Run specific command
# =====================================================================

set shell := ["sh", "-cu"]

VYROX_URL ?= "http://localhost:8001/webhook"
VYROX_HMAC_SECRET ?= "replace-with-64-hex-characters"
VYROX_TENANT_ID ?= "default-tenant"

default:
    @just --list

lint:
    @echo "Linting (shell script check)..."
    @sh -n simulate.sh
    @for f in scenarios/*.sh; do sh -n "$$f"; done
    @echo "All shell scripts syntax OK"

scenarios:
    @./simulate.sh --help

sim scenario:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh {{scenario}}

sim-dry scenario:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh {{scenario}} --dry-run

sim-mimikatz:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh mimikatz

sim-lateral:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh lateral --all-stages

sim-ransomware:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh ransomware

sim-sentinelone:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh sentinelone_lateral

sim-benign:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh benign

sim-stage scenario stage:
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh {{scenario}} --stage {{stage}}

sim-all:
    @echo "Running all single-stage scenarios..."
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh mimikatz
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh ransomware
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh sentinelone_lateral
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh benign
    @VYROX_URL="{{VYROX_URL}}" VYROX_HMAC_SECRET="{{VYROX_HMAC_SECRET}}" VYROX_TENANT_ID="{{VYROX_TENANT_ID}}" ./simulate.sh powershell_encoded

clean:
    rm -rf __pycache__ .ruff_cache .pytest_cache .venv
    find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

ci: lint scenarios sim-mimikatz
    @echo "CI passed"

help:
    @just --list --unsorted
