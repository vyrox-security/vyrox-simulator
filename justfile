# Vyrox Simulator Justfile
# =====================================================================
# Production-grade task runner for alert simulation scripts.
# MIT licensed - test scenarios for integration testing.
#
# Usage:
#   just              # Show all commands
#   just <command>   # Run specific command
# =====================================================================

set shell := ["zsh", "-cu"]

# =====================================================================
# DEFAULT
# =====================================================================

default:
    @just --list

# =====================================================================
# INSTALLATION
# =====================================================================

# Install dependencies
install:
    pip install -r requirements.txt

# =====================================================================
# SIMULATION SCENARIOS
# =====================================================================

# Simulate mimikatz attack
sim-mimikatz:
    python scripts/simulate_crowdstrike_alert.py --scenario mimikatz

# Simulate lateral movement
sim-lateral:
    python scripts/simulate_crowdstrike_alert.py --scenario lateral

# Simulate benign alert
sim-benign:
    python scripts/simulate_crowdstrike_alert.py --scenario benign

# Simulate credential dumping
sim-credentials:
    python scripts/simulate_crowdstrike_alert.py --scenario credentials

# Simulate PowerShell abuse
sim-powershell:
    python scripts/simulate_crowdstrike_alert.py --scenario powershell

# Run all scenarios
sim-all:
    @echo "Running all scenarios..."
    python scripts/simulate_crowdstrike_alert.py --scenario mimikatz
    python scripts/simulate_crowdstrike_alert.py --scenario lateral
    python scripts/simulate_crowdstrike_alert.py --scenario benign

# Custom scenario
sim scenario:
    python scripts/simulate_crowdstrike_alert.py --scenario {{ scenario }}

# =====================================================================
# LIST SCENARIOS
# =====================================================================

# List available scenarios
scenarios:
    python scripts/simulate_crowdstrike_alert.py --help

# =====================================================================
# LINTING
# =====================================================================

# Lint scripts
lint:
    ruff check scripts/

# Lint and fix
lint-fix:
    ruff check scripts/ --fix

# Type check
typecheck:
    mypy scripts/ --strict

# =====================================================================
# CLEANUP
# =====================================================================

# Clean caches
clean:
    rm -rf .pytest_cache
    rm -rf .ruff_cache
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# =====================================================================
# CI/CD
# =====================================================================

# Run CI pipeline
ci:
    set -e
    ruff check scripts/
    mypy scripts/ --strict

# =====================================================================
# HELP
# =====================================================================

help:
    @just --list --unsorted