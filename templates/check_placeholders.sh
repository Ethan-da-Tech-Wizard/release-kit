#!/usr/bin/env bash
# check_placeholders.sh - the shell leak check run by release.py (step 5).  Fails if unfilled template placeholders, likely secrets or private paths remain.
#
# Usage:  check_placeholders.sh [PATH] [--allow-registered]
#   PATH               directory to scan (default: current directory).  Nothing outside PATH is read.
#   --allow-registered a scrubbed release tree INTENTIONALLY contains {{TOKENS}}; with this flag a token passes
#                      only when it is registered in its component's ANNOTATIONS.json (component = first path part).
#                      An unregistered token (typo, stale, hand-added) still fails.
# Environment:
#   CHECK_PLACEHOLDERS_EXTRA_REGEX  optional extra ERE; any match fails ("custom private pattern").  Use it for a
#                      folder or project name that must never appear in a release.  Left unset, no extra rule runs.
#   CHECK_PLACEHOLDERS_IGNORE_FILE  optional file of FIXED strings, one per line (the allowlisted fake fixture
#                      strings).  A scan hit whose line contains one of them is ignored.  Whole-line granularity:
#                      keep fixture strings specific.
#   CHECK_PLACEHOLDERS_OVERCLAIM    set to 1 to ALSO fail on marketing-style overclaim words ("100% verified",
#                      "production-grade", "battle-tested").  This is a house-style rule, not a leak check, so it is
#                      OFF by default; a README that says "production-grade" passes unless you opt in.
# Notes:
#   * Any directory named "templates" and "node_modules" below PATH is not scanned by THIS script (the Python gate
#     still scans everything).  If your own project has a templates/ folder, rely on release_gate.py for it.
#   * Files named "ci.yml" and "check_placeholders.sh" are skipped at ANY depth (a CI file legitimately holds
#     "${{ ... }}" expressions and token-scanning patterns).  The generated pages ANNOTATIONS.md, ANNOTATIONS.json,
#     REFUSED.md and PLACEHOLDERS_INDEX.md are skipped by the --allow-registered token check ONLY at their real place
#     (<PATH>/<name> and <PATH>/<component>/<name>); a copy deeper in the tree is checked like any other file.
#   * Home paths: "/Users/<name>/" and "/home/<name>/" (with the trailing slash, as before) are flagged unless <name> is one of the generic names the
#     scrubber also leaves alone (user, you, name, username, yourname, example, runner, shared, me, someone, foo, bar,
#     test, guest; any case), so docs may show "/Users/you/project" or "/home/user/project".
#   * Token prefixes (sk-, ghp_, gho_, github_pat_, xox*-) must start a word: the character before them may not be a
#     letter, digit, "_" or "-".  So "disk-allocationstrategyinfo2" is not a token.  This matches the scrubber.
# Exit: 0 clean, 1 findings, 2 usage error.  Output is file:line plus the matching line (as the original script did);
# run it on an already-scrubbed tree, never on a tree that still holds private values.
set -u

ROOT="."
ALLOW_REGISTERED=0
for arg in "$@"; do
  case "$arg" in
    --allow-registered) ALLOW_REGISTERED=1 ;;
    -*) echo "usage: $0 [PATH] [--allow-registered]" >&2; exit 2 ;;
    *) ROOT="$arg" ;;
  esac
done
[ -d "$ROOT" ] || { echo "check_placeholders: not a directory: $ROOT" >&2; exit 2; }
cd "$ROOT" || exit 2          # every grep below is relative to PATH, so the script can be run from anywhere

fail=0
# Never descend into VCS metadata, vendored deps, the template sources, or this script / the CI file themselves.
EXCL=(--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=templates --exclude=check_placeholders.sh --exclude=ci.yml)

# filter_ignored: drop lines containing any fixed string from the ignore file (if one was given).
filter_ignored() {
  if [ -n "${CHECK_PLACEHOLDERS_IGNORE_FILE:-}" ] && [ -s "$CHECK_PLACEHOLDERS_IGNORE_FILE" ]; then
    grep -v -F -f "$CHECK_PLACEHOLDERS_IGNORE_FILE"
  else
    cat
  fi
}

# scan LABEL REGEX: grep -E over the tree; report up to 20 hits per rule.
scan() {
  local out
  out=$(grep -RInE "${EXCL[@]}" -e "$2" . 2>/dev/null | filter_ignored | head -20)
  if [ -n "$out" ]; then echo "FAIL: $1"; echo "$out"; fail=1; fi
}

if [ "$ALLOW_REGISTERED" -eq 1 ]; then
  # Registered-token mode: python3 (stdlib only) lists every {{TOKEN}} that is NOT recorded in the ANNOTATIONS.json of
  # its component.  The generated pages themselves (ANNOTATIONS.*, REFUSED.md, PLACEHOLDERS_INDEX.md) are skipped.
  out=$(python3 - <<'PY' 2>&1 | filter_ignored | head -20
import json, os, re
tok = re.compile(r"\{\{[A-Za-z_][^}]*\}\}")
# F9: the generated pages are skipped only where the kit writes them (root or component root); ci.yml and this script at any depth.
generated = {"ANNOTATIONS.md", "ANNOTATIONS.json", "REFUSED.md", "PLACEHOLDERS_INDEX.md"}
skip_names = {"check_placeholders.sh", "ci.yml"}
registered = {}                      # component (first path part) -> set of registered placeholder strings
for comp in sorted(os.listdir(".")):
    a = os.path.join(comp, "ANNOTATIONS.json")
    if os.path.isdir(comp) and os.path.isfile(a):
        try:
            registered[comp] = {r.get("placeholder") for r in json.load(open(a, encoding="utf-8")).get("replacements", [])}
        except ValueError:
            registered[comp] = set()
for d, dirs, files in os.walk("."):
    dirs[:] = [x for x in dirs if x not in (".git", "node_modules", "templates")]
    for f in files:
        if f in skip_names:
            continue
        p = os.path.join(d, f)
        rel = os.path.relpath(p, ".")
        if f in generated and rel.count(os.sep) <= 1:
            continue
        comp = rel.split(os.sep)[0] if os.sep in rel else ""
        ok = registered.get(comp, set())
        # file NAMES can carry tokens too
        for m in tok.finditer(rel):
            if m.group(0) not in ok:
                print("%s:0:%s" % (rel, rel))
        try:
            text = open(p, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.split("\n"), 1):
            for m in tok.finditer(line):
                if m.group(0) not in ok:
                    print("%s:%d:%s" % (rel, i, line))
PY
)
  if [ -n "$out" ]; then echo "FAIL: unregistered {{PLACEHOLDER}}"; echo "$out"; fail=1; fi
else
  scan "unfilled {{PLACEHOLDER}}" '\{\{[A-Za-z_][^}]*\}\}'
fi
# F2: extract each home path with -o, then drop the generic names (same list as the scrubber's _SAFE_HOME, any case,
# whole path component).  A line with one generic and one real path still reports the real one.
home_keys=$(grep -RInoE "${EXCL[@]}" -e '/(Users|home|USERS|HOME)/[A-Za-z0-9_][A-Za-z0-9_.-]*/' . 2>/dev/null \
  | grep -vEi ':/(Users|home)/(user|you|name|username|yourname|example|runner|shared|me|someone|foo|bar|test|guest)/$' \
  | cut -d: -f1,2 | sort -u | head -50)
# Report the WHOLE line (as every other rule does) so CHECK_PLACEHOLDERS_IGNORE_FILE keeps its whole-line meaning.
home_hits=$(printf '%s\n' "$home_keys" | while IFS= read -r key; do
  [ -n "$key" ] || continue
  printf '%s:%s\n' "$key" "$(sed -n "${key##*:}p" "${key%:*}")"
done | filter_ignored | head -20)
if [ -n "$home_hits" ]; then echo "FAIL: private home paths"; echo "$home_hits"; fail=1; fi
# Optional caller-supplied rule (kept out of this file so the kit names no private project).
if [ -n "${CHECK_PLACEHOLDERS_EXTRA_REGEX:-}" ]; then scan "custom private pattern" "$CHECK_PLACEHOLDERS_EXTRA_REGEX"; fi
# Case-insensitive and tolerant of extra spaces, like the scrubber's PRIVATE_KEY_RE.
scan "private key blocks" '[Bb][Ee][Gg][Ii][Nn][[:space:]]+([A-Za-z0-9]+[[:space:]]+)*[Pp][Rr][Ii][Vv][Aa][Tt][Ee][[:space:]]+[Kk][Ee][Yy]'
# Left boundary (start of line or a character that cannot be part of an identifier) keeps ordinary hyphenated or
# underscored words from matching, exactly like the scrubber's own token patterns.
# Vendor shapes added with the scrubber's: Stripe live keys, AWS temporary key ids (ASIA), npm and GitLab tokens.
scan "token-like strings" '(^|[^A-Za-z0-9_-])(ghp_|gho_|github_pat_|sk-[A-Za-z0-9]{20,}|xox[baprs]-|[sr]k_live_[A-Za-z0-9]{16,}|npm_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20,})|(AKIA|ASIA)[0-9A-Z]{16}'
# House-style rule: opt in with CHECK_PLACEHOLDERS_OVERCLAIM=1 (see the header).
if [ "${CHECK_PLACEHOLDERS_OVERCLAIM:-0}" = "1" ]; then
  scan "overclaim words" '(100% verified|production-grade|battle-tested)'
fi
[ $fail -eq 0 ] && echo "leak check: clean" || echo "leak check: FAILED"
exit $fail
