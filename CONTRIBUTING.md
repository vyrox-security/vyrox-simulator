# Contributing to Vyrox Simulator

## Before You Open a PR

This repository is in alpha. Bug reports and reproducible simulation improvements are welcome.

The most useful contributions add or improve realistic alert fixtures and simulation scripts.

## Development Setup

```bash
# Clone repository
git clone https://github.com/vyrox-security/vyrox-simulator.git
cd vyrox-simulator

# Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Optional dev checks
python -m pip install pytest ruff mypy || true
pytest -q || true
ruff check . || true
mypy . --strict || true
```

## Opening an Issue

Use issue templates under `.github/ISSUE_TEMPLATE`.

Do not report security vulnerabilities in public issues. Follow `SECURITY.md`.

## Opening a Pull Request

Use `.github/PULL_REQUEST_TEMPLATE.md`.

Include steps to reproduce, expected output, and test evidence.

## Code Style

- Keep scripts deterministic and redaction-safe
- Keep payload fixtures realistic and documented
- Commit messages follow Conventional Commits (`feat`, `fix`, `docs`, `test`, `chore`)

## What We Will Not Merge

- Unredacted production payloads
- Scripts that perform live containment actions
- Security guidance that weakens controls
- Documentation-only PRs without concrete corrections
