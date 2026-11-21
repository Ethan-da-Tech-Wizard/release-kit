# Changelog

All notable changes. Dates are commit dates. This project does not use version numbers yet.

## Unreleased

- Rewrote the README as a short landing page with a diagram, a quick start run literally on 2026-11-21, a feature table, a full flag and environment variable reference, test counts and limits.
- Moved the previous long README, unchanged except for path fixes, to `docs/REFERENCE.md`. Path fix: commands in the old text said `tools/scrub_release.py`; in this repository the kit is the repository root, so the commands are now `python3 scrub_release.py ...`. Removed two rows from its file table (`publish_gate.sh`, `post_publish_scan.py`) because those files are not in this repository.
- Same `tools/` to repository-root path fix in `HERMETIC_RUN.md`.
- Added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue templates and a pull request template.
- No behaviour changes: the program files are byte-identical. The only test edit is one line in `tests/test_redteam6_fixes.py`: the documentation-text checks now read `docs/REFERENCE.md` (where the long README moved) instead of `README.md`; assertions and the test count (236) are unchanged.
- Added a GitHub Actions workflow (`.github/workflows/tests.yml`) in a separate commit: stdlib `unittest` on ubuntu-latest and macos-latest, Python 3.9 and 3.12. It has not run on GitHub yet.

## 2026-11-21

- First public commit (`0a7ca9a`): scrub, hot-swap, release gate and the hermetic test runner, with 236 tests (macOS, Python 3.9). MIT licence, copyright TWU LLC.
