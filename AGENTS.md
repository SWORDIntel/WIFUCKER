# Repository Guidelines

## Project Structure & Module Organization
- Root keeps the launcher (`wifucker`) and TUI (`wifucker_unified_tui.py`) plus docs and deps (`requirements.txt`, `AGENTS.md`, `README.md`).
- Operational helpers live in `scripts/` (installer, clearance setter, TOPS check, CLI/TUI variants, hardware builders).
- Functional packages: `crackers/` (PBKDF2 + mutations), `ai_models/` (model assets), `capture/` and `surveillance/` (wireless ops), `parsers/` (input/output parsing), `utils/` (shared helpers), `HW/` and `ncs2/` (hardware runtimes), `docs/` (guides and archives).
- Virtual env sits in `venv/`; keep dependencies in `requirements.txt`. Assets like wordlists are expected outside the repo (e.g., `~/rockyou/rockyou.txt`).

## Build, Test, and Development Commands
- Auto-bootstrap + launch: `./wifucker` (use `sudo -E ./wifucker` for wireless control).
- Manual install (if needed): `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt` or `./scripts/install.sh`.
- Direct launcher: `sudo python3 scripts/launcher.py --interface wlan0` (detect/prepare interfaces, compile AVX512, start TUI).
- Hardware checks/tools: `python3 scripts/check_tops.py` (accel summary), `python3 scripts/set_max_clearance.py` (Layer 9 clearance), `python3 scripts/compile_runtimes.py` (build AVX/NPU helpers).

## Coding Style & Naming Conventions
- Python with 4-space indentation, docstrings for public functions, and type hints where practical (see `launcher.py`).
- Modules and files use `snake_case`; keep hardware-specific files in their existing subfolders.
- Prefer explicit logging via `rich`/`textual`; avoid bare prints in UI paths.
- Keep CLI flags lowercase with hyphenated options; surface defaults in help text.

## Testing Guidelines
- No automated test suite is committed; add targeted `pytest` cases per module when changing critical logic (e.g., PBKDF2 mutations, parser outputs).
- For manual verification, run `./wifucker` end-to-end on a test interface and confirm clearance + TOPS reporting via `scripts/check_tops.py`.
- Include regression inputs/pcaps alongside tests when adding new parsers or capture flows.

## Commit & Pull Request Guidelines
- Use short, imperative commit messages (e.g., `launcher: handle monitor fallback`, `crackers: add mutation rule`).
- For PRs, include: goal/approach summary, commands run (tests or manual flows), affected interfaces (CLI/TUI), and screenshots or logs for UI-facing changes.
- Link related issues/tasks; call out hardware requirements or elevated-permission steps for reviewers.

## Security & Configuration Notes
- Do not commit capture data, credentials, or wordlists; reference external paths instead.
- Assume root is required for monitor-mode and deauth operations—document when sudo is needed.
- Keep quantum/clearance scripts intact and avoid lowering defaults unless explicitly requested.
