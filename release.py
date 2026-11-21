#!/usr/bin/env python3
"""release: the ONE command that turns an allowlisted source selection into a verified, git-initialised release tree.
Stdlib only (python 3.9), no network, nothing pushed.

  release.py --manifest M [--manifest M2 ...] --rules R --out OUT
             [--allowlist A] [--source-root DIR] [--release-root DIR] [--restore-map FILE]
             [--allow-refused] [--no-git] [--neutral-author NAME] [--git-name N] [--git-email E] [--git-date D]

  --manifest   allowlist-only file selection (JSON, see scrub_release.py); one component per manifest.
  --rules      the PRIVATE rules/values file (chmod 600, outside the release tree and OUT): exact private values,
               rename_prefixes, allow_emails, gate_ignore_words, gate_allow_strings.
  --allowlist  the exceptions file (see allowlist.py): fake-secret test fixtures, hand-approved binaries, syntax-exempt
               paths.  Optional; without it nothing is excepted.
  --out        new or empty directory that becomes the release tree (<OUT>/<component>/...).

Pipeline (each step prints PASS or FAIL; the first FAIL stops the steps that depend on it, the exit code is nonzero
if ANY step failed):
  1. scrub        copy ONLY manifest files; private values and structural identifiers become {{TOKENS}}; names of
                  files and directories are rewritten in the same pass (never refused for containing a value);
                  rename_prefixes applied; binaries refused unless hand-approved.  Refused files FAIL the step
                  unless --allow-refused.
  2. annotations  rebuild ANNOTATIONS.md/.json and PLACEHOLDERS_INDEX.md from the FINAL text (reannotate.py).
  3. syntax       ast / json / bash -n / plutil / XML on every rewritten file (syntax_check.py).
  4. verify       release_gate.py: private values and their encoded variants, structural patterns, carriers
                  (.gz, zip/docx/xlsx internals incl. author metadata, SQLite/PDF/binaries unless approved).
  5. placeholders templates/check_placeholders.sh (shipped in tools/templates/) OUT --allow-registered (every {{TOKEN}} must be registered in its
                  component's ANNOTATIONS.json; secrets/private paths must be absent).
  6. git          fresh `git init` inside OUT, ONE commit, neutral author/committer placeholder and fixed neutral date,
                  no remote, nothing pushed; then the commit metadata and tracked names are verified too.
                  Runs only when steps 1-5 all passed (a tree that failed a gate is never committed).
Output tree: besides <OUT>/<component>/ the tree gets TOP-LEVEL ANNOTATIONS.json, ANNOTATIONS.md and
PLACEHOLDERS_INDEX.md.  The top-level ANNOTATIONS page belongs to a pseudo-component called "(staging root)": it
covers the files that sit directly in the root (for example a README or LICENSE), and says "No placeholders remain
in this component." when there are none.  They are published with the tree on purpose (no hashes inside).
Step 5 note: the shell check is the kit's own copy unless --placeholders-script is given.
Exit: 0 everything passed, 1 any step failed, 2 setup/usage error (nothing written).  Output carries counts and
file:line only, never matched text.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import allowlist as al  # noqa: E402
import reannotate  # noqa: E402
import release_gate  # noqa: E402
import scrub_release as sr  # noqa: E402
import syntax_check  # noqa: E402

DEFAULT_RELEASE_ROOT = Path(HERE).parent
# Neutral identity for the single commit.  example.invalid is reserved (RFC 2606): it can never be a real mailbox.
NEUTRAL_NAME = "Release Author"
NEUTRAL_EMAIL = "release@example.invalid"
NEUTRAL_DATE = "2000-01-01T00:00:00+0000"     # fixed so the commit hash does not encode when the release was cut
COMMIT_MESSAGE = "Initial release snapshot"


class Step:
    """One pipeline step result: name, ok flag and a short count-only detail line (never matched text)."""

    def __init__(self, name):
        self.name, self.ok, self.detail, self.lines = name, False, "", []

    def line(self):
        return "step %-12s %s  %s" % (self.name, "PASS" if self.ok else "FAIL", self.detail)


def _inside(child, parent):
    """True if real path CHILD is PARENT or below it."""
    c, p = Path(child).resolve(), Path(parent).resolve()
    return c == p or p in c.parents


def check_setup(a):
    """Validate paths before anything is written.  Raises sr.ScrubError (exit 2) with a value-free message."""
    out = Path(os.path.abspath(os.path.expanduser(a.out)))
    src = Path(a.source_root).resolve()
    rel_root = Path(a.release_root).resolve()
    if not src.is_dir():
        raise sr.ScrubError("source root missing")
    if _inside(out, src) or _inside(src, out):
        raise sr.ScrubError("--out and the source root must not overlap (never write into the source)")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise sr.ScrubError("--out exists and is not empty; release never overwrites")
    # The private files must not end up inside the tree being published.
    for label, path in (("rules file", a.rules), ("restore map", a.restore_map)):
        if _inside(Path(path).expanduser().parent if label == "restore map" else Path(path).expanduser(), out):
            raise sr.ScrubError("%s must live OUTSIDE --out" % label)
    return out, src, rel_root


def step_scrub(a, pv, out, allow, results):
    """Step 1: run build_component for every manifest into OUT."""
    st = Step("scrub")
    comps, refused, copied, repl = [], 0, 0, 0
    for m in a.manifest:
        res = sr.build_component(m, a.rules, a.release_root, a.source_root, a.restore_map, stage_root=out, allow=allow)
        comps.append(res)
        refused += res["refused"]
        copied += res["copied"]
        repl += len(res["records"])
        for r in res["refused_list"]:
            st.lines.append("REFUSED %s: %s" % (r["path"], r["reason"]))
    st.ok = refused == 0 or a.allow_refused
    st.detail = "components=%d copied=%d refused=%d replacements=%d" % (len(comps), copied, refused, repl)
    results["comps"] = comps
    return st


def step_annotations(out):
    """Step 2: rebuild the annotation pages from the final text (quiet: reannotate prints counts only)."""
    st = Step("annotations")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = reannotate.main(["--staging", str(out)])
    st.ok = code == 0
    st.detail = (buf.getvalue().strip().splitlines() or [""])[-1]
    return st


def step_syntax(comps, a, allow):
    """Step 3: syntax gate per component (file_map lets a failure be blamed on the rewrite or the source)."""
    st = Step("syntax")
    checked, bad = 0, []
    for res in comps:
        n, b = syntax_check.check_tree(res["comp_dir"], a.source_root, res["file_map"], allow)
        checked += n
        for cat, kind, rel, line in b:
            st.lines.append("%s/%s:%d: %s[%s]" % (Path(res["comp_dir"]).name, rel, line, cat, kind))
        bad.extend(b)
    st.ok = not bad
    st.detail = "checked=%d failures=%d" % (checked, len(bad))
    return st


def step_verify(a, pv, out, allow):
    """Step 4: the verifier (values, variants, patterns, carriers)."""
    st = Step("verify")
    files, findings = release_gate.gate(out, pv, a.release_root, (), allow, a.neutral_author, values_path=a.rules)
    counts = {}
    for cat, detail, rel, line in findings:
        counts[cat] = counts.get(cat, 0) + 1
        st.lines.append("%s:%d: %s%s" % (rel, line, cat, "[%s]" % detail if detail else ""))
    st.ok = not findings
    st.detail = "scanned=%d findings=%d %s" % (files, len(findings), " ".join("%s=%d" % kv for kv in sorted(counts.items())))
    return st


def step_placeholders(a, out, allow):
    """Step 5: the shell leak check, restricted to OUT, tokens allowed only when registered."""
    st = Step("placeholders")
    # Order: explicit --placeholders-script, then the copy that ships inside tools/ (always present).  The release
    # root's own templates/ is only a last resort: running a script from an unreviewed tree would execute its code.
    cands = ([Path(a.placeholders_script)] if a.placeholders_script else []) + [
        Path(HERE) / "templates" / "check_placeholders.sh",
        Path(a.release_root) / "templates" / "check_placeholders.sh"]
    script = next((c for c in cands if c.is_file()), cands[0])
    if not script.is_file():
        st.detail = "check_placeholders.sh not found"
        return st
    env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="ignore_") as d:
        ign = Path(d) / "ignore.txt"
        ign.write_text("\n".join(allow.all_fixture_strings()) + ("\n" if allow.fixtures else ""), encoding="utf-8")
        if allow.fixtures:
            env["CHECK_PLACEHOLDERS_IGNORE_FILE"] = str(ign)
        r = subprocess.run(["bash", str(script), str(out), "--allow-registered"], capture_output=True, text=True,
                           env=env, stdin=subprocess.DEVNULL, timeout=600)
    st.ok = r.returncode == 0
    # The script prints matching lines; keep only the location (file:line) so no text is echoed.
    for ln in r.stdout.splitlines():
        if ln.startswith(("FAIL", "leak check")):
            st.lines.append(ln)
        else:
            st.lines.append(":".join(ln.split(":", 2)[:2]))
    st.detail = "leak check %s" % ("clean" if st.ok else "FAILED")
    return st


def _git(out, env, *args):
    """Run git in OUT with a sanitised environment.  -> CompletedProcess (text)."""
    return subprocess.run(["git", "-C", str(out)] + list(args), capture_output=True, text=True, env=env,
                          stdin=subprocess.DEVNULL, timeout=600)


def git_env(name, email, date, home):
    """Environment that ignores every user/system git config, hook and credential: the commit can only carry the
    neutral identity we give it."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email, "GIT_COMMITTER_DATE": date,
            "GIT_TERMINAL_PROMPT": "0"}


def step_git(a, pv, out, allow):
    """Step 6: fresh repo, one neutral commit, then verify the commit's own metadata and tracked names."""
    st = Step("git")
    if a.no_git:
        st.ok, st.detail = True, "skipped (--no-git)"
        return st
    if (out / ".git").exists():
        st.detail = ".git already present"
        return st
    with tempfile.TemporaryDirectory(prefix="githome_") as home:
        env = git_env(a.git_name, a.git_email, a.git_date, home)
        steps = [("init", ["-c", "init.defaultBranch=main", "init", "-q"]),
                 ("add", ["add", "-A"]),
                 ("commit", ["-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, "commit", "-q",
                             "--no-verify", "--no-gpg-sign", "-m", COMMIT_MESSAGE])]
        for label, argv in steps:
            r = _git(out, env, *argv)
            if r.returncode != 0:
                st.detail = "git %s failed (exit %d)" % (label, r.returncode)
                return st
        # ---- verify what git itself recorded --------------------------------------------------------------
        meta = _git(out, env, "log", "--all", "--format=%an%n%ae%n%cn%n%ce%n%s%n%b").stdout.split("\n")
        expect = [a.git_name, a.git_email, a.git_name, a.git_email, COMMIT_MESSAGE]
        count = _git(out, env, "rev-list", "--all", "--count").stdout.strip()
        remotes = _git(out, env, "remote").stdout.strip()
        names = _git(out, env, "ls-tree", "-r", "-t", "--name-only", "HEAD").stdout
        problems = []
        if meta[:5] != expect:
            problems.append("commit identity is not the neutral placeholder")
        if count != "1":
            problems.append("expected exactly 1 commit, found %s" % count)
        if remotes:
            problems.append("a remote is configured")
        # Commit metadata and every tracked path run through the same scanner as the files.
        ctx = release_gate.Ctx(release_gate.HashScanner(pv), release_gate.VariantScanner(pv.flat),
                               set(pv.allow_emails), allow, release_gate.NEUTRAL_AUTHORS)
        hits = []
        rep = lambda c, d, ln: hits.append((c, d))
        release_gate.scan_text("\n".join(meta), ctx, rep)
        release_gate.scan_text(names, ctx, rep)
        if hits:
            problems.append("private value in git metadata or tracked names (%d hits)" % len(hits))
        tracked = len([n for n in _git(out, env, "ls-files").stdout.splitlines() if n])
        st.ok = not problems
        st.lines.extend(problems)
        st.detail = "commits=%s tracked=%d author=%s" % (count, tracked, "neutral" if meta[:2] == expect[:2] else "NOT neutral")
    return st


def run(a):
    """Execute the pipeline for parsed args A.  -> (exit code, [Step])."""
    out, _src, _rel = check_setup(a)
    pv = sr.load_values(a.rules, a.release_root)
    allow = al.load_allowlist(a.allowlist, pv.flat.values())
    results, steps = {}, []
    # The restore map must also sit outside OUT (checked above) and outside the release tree (checked by scrub).
    s1 = step_scrub(a, pv, out, allow, results)
    steps.append(s1)
    comps = results["comps"]
    # Later steps only make sense when there is a tree; they all run even after an earlier FAIL so the person sees
    # every problem in one pass.  Only the git step is gated on everything else passing.
    steps.append(step_annotations(out))
    steps.append(step_syntax(comps, a, allow))
    steps.append(step_verify(a, pv, out, allow))
    steps.append(step_placeholders(a, out, allow))
    if all(s.ok for s in steps):
        steps.append(step_git(a, pv, out, allow))
    else:
        g = Step("git")
        g.detail = "not run: an earlier step failed (a tree that failed a gate is never committed)"
        steps.append(g)
    return (0 if all(s.ok for s in steps) else 1), steps


def build_parser():
    ap = argparse.ArgumentParser(description="One-command release: scrub, annotate, syntax, verify, leak check, git init")
    ap.add_argument("--manifest", action="append", required=True)
    ap.add_argument("--rules", required=True, help="private rules/values file (outside the release tree)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--allowlist", help="exceptions file: fake-secret fixtures, approved binaries, syntax-exempt paths")
    ap.add_argument("--source-root", default=str(sr.DEFAULT_SOURCE_ROOT))
    ap.add_argument("--release-root", default=str(DEFAULT_RELEASE_ROOT))
    ap.add_argument("--restore-map", default=str(sr.DEFAULT_RESTORE))
    ap.add_argument("--allow-refused", action="store_true", help="do not fail the scrub step when files were refused")
    ap.add_argument("--no-git", action="store_true")
    ap.add_argument("--neutral-author", action="append", default=[], help="metadata value that identifies nobody")
    ap.add_argument("--git-name", default=NEUTRAL_NAME)
    ap.add_argument("--git-email", default=NEUTRAL_EMAIL)
    ap.add_argument("--git-date", default=NEUTRAL_DATE)
    ap.add_argument("--placeholders-script")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        code, steps = run(a)
    except (sr.ScrubError, al.AllowlistError) as e:
        print("release: FATAL: %s" % e, file=sys.stderr)
        return 2
    for s in steps:
        print(s.line())
        for ln in s.lines[:50]:
            print("    " + ln)
        if len(s.lines) > 50:
            print("    ... %d more" % (len(s.lines) - 50))
    print("release: %s" % ("PASS" if code == 0 else "FAIL (do not publish this tree)"))
    return code


if __name__ == "__main__":
    sys.exit(main())
