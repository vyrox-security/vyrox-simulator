# Changelog

All notable changes to the Vyrox attack simulator are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-25

First tagged release of the attack simulator — fire realistic, signed EDR
alerts at a Vyrox ingestion endpoint to exercise the full pipeline without a
real EDR or real malware. MIT licensed.

### Added
- **Pure-shell simulator** (`simulate.sh`) — no Python or Lua dependency; runs
  anywhere `bash` + `curl` exist.
- **Scenarios**: `mimikatz` (credential dumping), `lateral` (multi-stage lateral
  movement to exfil), `ransomware`, and `benign` (a scheduled task that should
  *not* page anyone).
- **Signed payloads** — alerts are HMAC-signed with the per-tenant secret, so the
  simulator exercises the real authentication path, not a bypass.
- **`--dry-run`** — prints the signed payload without POSTing.
- Production-grade documentation across all scripts.

### Changed
- Converted from the earlier Lua-based scenarios to pure shell scripts.
