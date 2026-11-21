#!/usr/bin/env python3
r"""reannotate: rebuild ANNOTATIONS.md, ANNOTATIONS.json and PLACEHOLDERS_INDEX.md from the FINAL staged text.

Purpose
  scrub_release.py writes annotation pages at scrub time. After hand edits to staged files (fixing a typo, adding a
  line to a README) the line/column numbers in those pages go stale. This tool ignores the old annotation files and
  rescans every staged file (and every file name) for {{TOKEN}} placeholders, so the pages always match the text that
  is actually published. Stdlib only, no network, never reads private values.

Design notes / threat model
  * It only ever READS staged text and WRITES the three public page types. It never opens the private values file,
    the private restore map or the private annotation copies, so it cannot leak a real value even if it has a bug.
  * Public ANNOTATIONS.json holds placeholder / file / line / column only (no hashes). Salted hashes stay in the
    private copy under the private config folder (annotations.private/, written by scrub_release.py); this tool never
    touches it. Consequence: after reannotate the private copy can be older than the public one; that is expected,
    hotswap only uses it to verify values per key.
  * The `refused` list and `exclude_exceptions` of an existing ANNOTATIONS.json are carried over unchanged, because
    they describe scrub-time decisions that cannot be recovered from staged text.
  * The staging root itself is treated as one extra pseudo-component "(staging root)" (top-level files only) so
    placeholders in root-level files are indexed as well.

Meanings
  A built-in table below gives a specific meaning, example and "where to swap" for known placeholders; an optional
  JSON file {"KEY": {"meaning": "...", "example": "...", "where": "..."}} adds or overrides entries.

Usage
  python3 tools/reannotate.py [--release-root DIR] [--staging DIR] [--meanings FILE.json]

  Example:  python3 tools/reannotate.py --staging ./staging --meanings extra_meanings.json
  Exit status: 0 on success, 2 if the staging dir or the meanings file is unusable.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import scrub_release as sr  # shared token regex, class prefixes and meaning helpers (must be importable, e.g. run from tools/)

# Specific, human-written descriptions for placeholders whose generic "private value" text would be unhelpful.
# Shape: KEY -> {"meaning": what it stands for, "example": a harmless sample value, "where": where to swap it in}.
# Keys are token names without braces, e.g. "COPYRIGHT_HOLDER" for the token {{COPYRIGHT_HOLDER}}.
BUILTIN_MEANINGS = {
    "COPYRIGHT_HOLDER": {
        "meaning": "the name of the person or organisation that holds the copyright, shown in the MIT LICENSE header "
                   "(the licence text itself is unchanged)",
        "example": "Jane Doe  or  Example Software Ltd",
        "where": "the copyright line of LICENSE",
    },
}
# Generated pages that must never be scanned for tokens (they would just list themselves):
# ANNOTATIONS.md, ANNOTATIONS.json and REFUSED.md.
SKIP_NAMES = set(sr.META_FILES)


def _classify(key):
    """Guess the class of a placeholder from its name alone.

    Args:
        key: token name without braces, e.g. "HOST_3" or "OWNER_NAME".
    Returns:
        The pattern class (e.g. "HOSTNAME") when the key is "<class prefix>_<digits>", otherwise "EXACT" (a named
        private value). Edge case: a user value literally named like "HOST_3" is reported as a pattern class; this is
        only used for wording in the pages, not for any safety decision.
    """
    # CLASS_PREFIX maps class -> token prefix (e.g. "HOSTNAME" -> "HOST"); numbered tokens look like HOST_1, HOST_2.
    for cls, prefix in sr.CLASS_PREFIX.items():
        if key.startswith(prefix + "_") and key[len(prefix) + 1:].isdigit():
            return cls
    return "EXACT"


def scan_component(cdir, top_only=False):
    """-> (files, records) for one staged dir; records are {'class','column','file','key','kind','line','placeholder','variant'}.

    Args:
        cdir: Path of the staged directory to scan.
        top_only: scan only the files directly in cdir (used for the staging root, whose sub-folders are components).
    Returns:
        (files, records): sorted relative POSIX file names, and one record per token occurrence, sorted by
        (file, line, column). Line is 0 for a token found in a file NAME (column is then the position in the path).
    Edge cases: files that are not valid UTF-8 are listed but contribute no content records; generated annotation
    files are skipped entirely.
    """
    recs, files = [], []
    for f in sorted(p for p in (cdir.glob("*") if top_only else cdir.rglob("*")) if p.is_file()):
        rel = f.relative_to(cdir).as_posix()
        # Skip our own generated pages (and, at the staging root, the cross-component index).
        if rel in SKIP_NAMES or (top_only and rel == "PLACEHOLDERS_INDEX.md"):
            continue
        files.append(rel)
        # Tokens may also appear in the path itself (a renamed file); line 0 marks "file name".
        for m in sr.TOKEN_RE.finditer(rel):
            recs.append(_rec(m, rel, 0, m.start() + 1, "filename"))
        try:
            text = f.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue   # binary or non-UTF-8 file: nothing to scan
        for m in sr.TOKEN_RE.finditer(text):
            line, col = sr._line_col(text, m.start())
            recs.append(_rec(m, rel, line, col, "content"))
    recs.sort(key=lambda r: (r["file"], r["line"], r["column"]))
    return files, recs


def _rec(m, rel, line, col, kind):
    """Build one public annotation record from a TOKEN_RE match.

    Args:
        m: match of sr.TOKEN_RE (group 1 = key, group 2 = optional case variant such as "lower").
        rel: file path relative to the scanned directory.
        line, col: 1-based position (line 0 for a file-name hit).
        kind: "filename" or "content".
    Returns:
        dict with exactly the public keys (no hashes).
    """
    key = m.group(1)
    return {"class": _classify(key), "column": col, "file": rel, "key": key, "kind": kind, "line": line,
            "placeholder": m.group(0), "variant": m.group(2) or ""}


def meaning_for(key, cls, meanings):
    """Look up (meaning, example, where) for a placeholder key.

    A user/builtin entry in `meanings` wins; otherwise fall back to scrub_release's generic wording for the class,
    with an empty example. Returns three strings (possibly empty).
    """
    e = meanings.get(key)
    if e:
        return e["meaning"], e.get("example", ""), e.get("where", "")
    m, hint = sr.meaning_for(key, cls)
    return m, "", hint


def render_md(comp, recs, meanings):
    """Render the per-component ANNOTATIONS.md page as one string.

    Args:
        comp: component name shown in the title.
        recs: records from scan_component.
        meanings: table used for the meaning/example/where columns. (Note: the table rows below actually read the
            module-level MEANINGS; callers pass that same object, so the two agree.)
    Returns:
        Markdown text with one table row per distinct placeholder key, listing every file:line:column.
    """
    by = {}   # key -> list of occurrences
    for r in recs:
        by.setdefault(r["key"], []).append(r)
    L = ["# Placeholders in component `%s`" % comp, "",
         "A placeholder is a marker written with double curly braces around an upper-case name. This page lists every one",
         "in this component, what it stands for, an example of a value, and where it appears (file:line:column in the",
         "files as published). It holds no real values.", "",
         "To fill one in, replace it in the listed file(s) with your own value (a text editor, or `sed`; see README.md).", ""]
    if not by:
        L += ["No placeholders remain in this component.", ""]
    else:
        L += ["| placeholder | meaning | example value | where to swap | file:line:column |", "|---|---|---|---|---|"]
        for key in sorted(by, key=sr.natural_key):
            rs = by[key]
            meaning, example, where = meaning_for(key, rs[0]["class"], MEANINGS)
            toks = sorted(set(r["placeholder"] for r in rs))
            locs = ", ".join("%s:%d:%d" % (r["file"], r["line"], r["column"]) for r in rs)
            L.append("| %s | %s | %s | %s | %s |" % (" ".join("`%s`" % t for t in toks), meaning, example or "-", where or "-", locs))
        L.append("")
    L += ["Generated by tools/reannotate.py from the published text; the numbers match the files as they are.", ""]
    return "\n".join(L)


# Working copy of the meanings table: starts as the built-in entries and is extended/overridden by --meanings in main().
MEANINGS = dict(BUILTIN_MEANINGS)


def write_component(cdir, top_only=False):
    """Rescan one staged directory and rewrite its ANNOTATIONS.json and ANNOTATIONS.md in place.

    Args:
        cdir: Path of a component directory (or the staging root when top_only is true).
        top_only: see scan_component.
    Returns:
        The public annotation dict that was written (used afterwards for the index).
    Edge cases: an unreadable/corrupt old ANNOTATIONS.json is treated as empty, so refused/exceptions are lost
    rather than the run failing.
    """
    comp = "(staging root)" if top_only else cdir.name
    files, recs = scan_component(cdir, top_only)
    old = {}   # previous annotation data, only used to carry over scrub-time decisions
    aj = cdir / "ANNOTATIONS.json"
    if aj.is_file():
        try:
            old = json.loads(aj.read_text(encoding="utf-8"))
        except ValueError:
            old = {}
    refused = old.get("refused", []) if isinstance(old.get("refused"), list) else []
    exceptions = old.get("exclude_exceptions", []) if isinstance(old.get("exclude_exceptions"), list) else []
    pub = {"version": 2, "component": comp, "files": files, "exclude_exceptions": exceptions,
           "replacements": recs, "refused": refused}
    aj.write_text(json.dumps(pub, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (cdir / "ANNOTATIONS.md").write_text(render_md(comp, recs, MEANINGS), encoding="utf-8")
    return pub


def write_index(staging, pubs):
    """Write staging/PLACEHOLDERS_INDEX.md aggregating all components.

    Args:
        staging: staging directory (Path or str).
        pubs: {component name: public annotation dict} as returned by write_component.
    Counts occurrences per placeholder key and per component; also lists files copied/refused per component.
    """
    agg = {}   # key -> {"class": ..., "comps": {component: occurrence count}}
    for c, pub in pubs.items():
        for r in pub["replacements"]:
            e = agg.setdefault(r["key"], {"class": r["class"], "comps": {}})
            e["comps"][c] = e["comps"].get(c, 0) + 1
    L = ["# Placeholders index (all components)", "",
         "A placeholder is `{` `{NAME}` `}`-style text (double curly braces around an upper-case name) that stands for a value that was",
         "removed or not yet chosen. Each component's ANNOTATIONS.md gives the meaning, an example value and the exact",
         "file:line:column. Pattern-class names such as `HOST_1` are numbered per component, so hot-swap one component at a time.", "",
         "| placeholder key | class | meaning | component (occurrences) |", "|---|---|---|---|"]
    for k in sorted(agg, key=sr.natural_key):
        e = agg[k]
        meaning = meaning_for(k, e["class"], MEANINGS)[0]
        L.append("| `%s` | %s | %s | %s |" % (k, e["class"], meaning, ", ".join("%s (%d)" % (c, n) for c, n in sorted(e["comps"].items()))))
    if not agg:
        L.append("| (none) | | | |")
    L += ["", "| component | files | files refused |", "|---|---|---|"]
    for c in sorted(pubs):
        L.append("| %s | %d | %d |" % (c, len(pubs[c]["files"]), len(pubs[c]["refused"])))
    (Path(staging) / "PLACEHOLDERS_INDEX.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def main(argv=None):
    """Command-line entry point.

    Args:
        argv: optional argument list (defaults to sys.argv[1:]).
    Returns:
        0 on success; 2 if staging is missing or the meanings file is unreadable or malformed.
    """
    ap = argparse.ArgumentParser(description="Rebuild annotation pages from the final staged text")
    ap.add_argument("--release-root", default=str(sr.DEFAULT_RELEASE_ROOT))
    ap.add_argument("--staging")
    ap.add_argument("--meanings")
    a = ap.parse_args(argv)
    staging = Path(a.staging) if a.staging else Path(a.release_root) / "staging"
    if not staging.is_dir():
        print("reannotate: staging dir not found", file=sys.stderr)
        return 2
    if a.meanings:
        try:
            extra = json.loads(Path(a.meanings).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print("reannotate: cannot read meanings file", file=sys.stderr)
            return 2
        for k, v in extra.items():
            if not isinstance(v, dict) or "meaning" not in v:
                print("reannotate: bad meanings entry %s" % k, file=sys.stderr)
                return 2
            MEANINGS[k] = v   # user entries add to or override the built-ins
    comps = [d for d in sorted(staging.iterdir()) if d.is_dir()]
    total = 0
    pubs = {}
    for d in comps:
        pubs[d.name] = write_component(d)
    # Also cover loose files at the top of staging (not inside any component).
    pubs["(staging root)"] = write_component(staging, top_only=True)
    for name, pub in pubs.items():
        total += len(pub["replacements"])
        print("%s: files=%d placeholders=%d" % (name, len(pub["files"]), len(pub["replacements"])))
    write_index(staging, pubs)
    print("index written; placeholders total=%d" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
