# Contributing to release-kit

Issues and pull requests are welcome. This is a one-maintainer project (Ethan Kilmer, TWU LLC), so replies can take days. AI-assisted contributions are fine; say so in the PR.

## Run the tests

Python 3.9 or newer, standard library only, nothing to install, no network.

```bash
python3 -B -m unittest discover -s tests
```

Run them before you push, and say in the PR which Python and OS you used. The suite must pass as shipped, with no environment tweaks.

## Pull request checklist

- [ ] The change is small and does one thing; the PR says what it fixes and why.
- [ ] For a bug fix: a test that **fails on the old behaviour** and passes with the fix (show the failing run in the PR text).
- [ ] For a feature: tests for the new behaviour and for the case where it should refuse.
- [ ] The full suite passes locally; the number of tests did not go down (if it did, explain why).
- [ ] No new dependencies (standard library only) and no network access.
- [ ] Docs updated: the README or component README, the configuration table if you added a flag or environment variable, and `CHANGELOG.md`.
- [ ] No real secrets, private hostnames, home paths or personal data anywhere, including in tests. Build fixture credentials from pieces at runtime so the file never contains a complete key-shaped string.
- [ ] If an AI agent wrote part of it, you read and ran it, and the PR says so.

## Style

- Plain Python 3.9 compatible code (use `from __future__ import annotations` for new-style type hints). POSIX only.
- Prefer loud, early, specific errors over silent fallbacks. Fail closed for anything security related.
- Comments explain why, not what. Keep examples in comments and docstrings consistent with the README commands.
- Tests use `unittest` and live next to the code or under `tests/`.

## Security-sensitive changes

These tools decide what is allowed to leave your machine. Treat these as security-sensitive: `release_gate.py`, `scrub_release.py`, `normalize.py`, `allowlist.py`, `templates/check_placeholders.sh` and the isolation code in `hermetic_run.py`. Rules: do not weaken a check or widen an allowlist in the same PR as an unrelated change; a change that makes the gate accept something it used to reject needs a test that shows the new input is really safe; every new pattern or disguise you teach the gate needs one test that must be found and one that must not be (false positives); refusal and fail-closed paths keep their tests. Say plainly in the PR what a reviewer should try to break.

Report vulnerabilities privately, not in a public issue: see [SECURITY.md](SECURITY.md).

## Conduct

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
