# Changelog

All notable changes to the Vyrox attack simulator are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-14

The demo-fire scenario suite: fire a full, realistic spread of attacks at a
running Vyrox demo so the console lights up across every severity.

### Added
- **`demo-fire.sh`** — fire alerts by SEVERITY (random pick from a pool) or by
  exact scenario name. `--both` fires at both demo tenants, `--all` fires every
  scenario in a severity pool, and `--populate` fills every demo tenant with the
  full LOW -> MEDIUM -> HIGH -> CRITICAL spread. Tenants and the fixed demo
  webhook secret are configurable via env.
- **Severity scenario library** — five scenarios per band (LOW/MEDIUM/HIGH/
  CRITICAL), each with a command line chosen so Vyrox's own triage lands it in
  that band: e.g. `medium_certutil`, `high_lsass_dump`, `critical_dcsync`,
  `critical_lockbit`, plus the original `mimikatz`/`ransomware`/`lateral`.
- **`scripts/smoke.sh`** — hermetic signature-shape smoke test (no ingestion
  server): builds a real scenario payload, signs it, and asserts the
  `sha256=<64-hex>` HMAC-SHA256 wire shape the webhook expects.
- **CI** (`.github/workflows/simulator-ci.yml`) — `sh -n` syntax check,
  ShellCheck (error severity), and the smoke test on every push/PR. Actions are
  pinned to a full commit SHA and the job runs with `contents: read` only.
- GitHub issue templates (bug / feature / false-positive) and a PR template.

### Changed
- **`simulate.sh` only dispatches when executed directly** (a `BASH_SOURCE`
  guard), so the CI smoke test can source it to exercise the signer and payload
  builder without sending anything.

### Fixed
- **`high_defender_tamper.sh` crashed `--populate`** with "line 31: true:
  unbound variable": the PowerShell literal `$true` sat inside an unquoted
  heredoc, so `set -u` treated it as an unset shell variable. Escaped to `\$true`
  so the payload carries the literal `$true`. All scenarios now build clean under
  `set -u`.

## [0.1.0] - 2026-05-25

First tagged release of the attack simulator, fire realistic, signed EDR
alerts at a Vyrox ingestion endpoint to exercise the full pipeline without a
real EDR or real malware. MIT licensed.

### Added
- **Pure-shell simulator** (`simulate.sh`), no Python or Lua dependency; runs
  anywhere `bash` + `curl` exist.
- **Scenarios**: `mimikatz` (credential dumping), `lateral` (multi-stage lateral
  movement to exfil), `ransomware`, and `benign` (a scheduled task that should
  *not* page anyone).
- **Signed payloads**, alerts are HMAC-signed with the per-tenant secret, so the
  simulator exercises the real authentication path, not a bypass.
- **`--dry-run`**, prints the signed payload without POSTing.
- Production-grade documentation across all scripts.

### Changed
- Converted from the earlier Lua-based scenarios to pure shell scripts.
