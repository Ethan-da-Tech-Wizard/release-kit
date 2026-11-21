#!/usr/bin/env python3
"""syntax_check: prove the scrub did not break the files it rewrote.  Stdlib only (python 3.9), no network.

Goal: syntax gates after each rewrite (ast, json, bash -n, plutil, XML).
A placeholder swapped into code can silently break it (e.g. a private value used as a bare identifier), and the
release would then ship files that do not even parse.  This module checks every rewritten file:

  .py                      ast.parse                       (never imports or runs the file)
  .json                    json.loads
  .sh .bash .zsh, or a     bash -n / zsh -n                (parse only, nothing executes; skipped if shell absent)
    bash/sh/zsh shebang
  .plist                   plutil -lint when plutil exists, else the XML parser
  .xml .svg .xhtml         xml.etree parser (a DOCTYPE/ENTITY is refused outright: entity-expansion bombs)

Before checking, every {{TOKEN}} is rendered to the harmless word "placeholderx" - this is what a hot-swap with an
ordinary value would produce, so a token inside a string passes while a token in a position where no value could
ever work (e.g. as half of a Python identifier is fine, but as a bare JSON value it is not) is caught.

A failing file is classified by also checking its SOURCE original:
  BROKEN_BY_REWRITE   source parses, scrubbed output does not  -> the scrub caused it
  SOURCE_INVALID      neither parses                          -> the file was already broken
Either is a failure unless the path is listed in the allowlist's "syntax_exempt" (with a reason).
Output never contains file content: only category, kind of check, path and line number.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scrub_release as sr  # noqa: E402
import allowlist as al  # noqa: E402

RENDER = "placeholderx"                       # throwaway value substituted for every {{TOKEN}}
SHELL_EXT = {".sh": "bash", ".bash": "bash", ".zsh": "zsh"}
XML_EXT = {".xml", ".svg", ".xhtml"}
SHEBANG_RE = re.compile(r"^#!\s*(?:/usr/bin/env\s+)?(?:\S*/)?(bash|zsh|sh)\b")
LINE_RE = re.compile(r"line (\d+)")
TIMEOUT = 20                                  # seconds for an external checker


def render(text):
    """Replace every {{TOKEN}} with RENDER (what a hot-swap with a plain value would yield)."""
    return sr.TOKEN_RE.sub(RENDER, text)


def kind_of(rel, text):
    """-> checker name for this file or None when we have no validator for it."""
    ext = os.path.splitext(rel.lower())[1]
    if ext == ".py":
        return "python"
    if ext == ".json":
        return "json"
    if ext in SHELL_EXT:
        return SHELL_EXT[ext]
    if ext == ".plist":
        return "plist"
    if ext in XML_EXT:
        return "xml"
    first = text.split("\n", 1)[0]
    m = SHEBANG_RE.match(first)
    if m and not ext:                         # extension-less script with a shell shebang
        return "zsh" if m.group(1) == "zsh" else "bash"
    return None


def _shell(shell, text):
    """bash/zsh -n on TEXT (written to a private temp file).  -> (ok, line or 0).  Skips (ok) if no shell."""
    exe = shutil.which(shell)
    if exe is None:
        return True, 0
    with tempfile.TemporaryDirectory(prefix="syntax_") as d:
        f = Path(d) / "s.sh"
        f.write_text(text, encoding="utf-8")
        # -n = read and parse commands but do not execute them.  Minimal environment, no stdin.
        r = subprocess.run([exe, "-n", str(f)], capture_output=True, text=True, timeout=TIMEOUT,
                           env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL)
    if r.returncode == 0:
        return True, 0
    m = LINE_RE.search(r.stderr)               # only the line NUMBER is kept; the message may quote content
    return False, int(m.group(1)) if m else 0


def _xml(text):
    """Parse XML with the stdlib parser; refuse DTD/entities (billion-laughs protection).  -> (ok, line)."""
    if re.search(r"<!(?:DOCTYPE|ENTITY)", text, re.I):
        return False, 0
    try:
        ET.fromstring(text)
    except ET.ParseError as e:
        return False, getattr(e, "position", (0, 0))[0]
    return True, 0


def _plist(text):
    """plutil -lint when available (macOS), else fall back to the XML parser."""
    exe = shutil.which("plutil")
    if exe is None:
        return _xml(text)
    with tempfile.TemporaryDirectory(prefix="syntax_") as d:
        f = Path(d) / "p.plist"
        f.write_text(text, encoding="utf-8")
        r = subprocess.run([exe, "-lint", str(f)], capture_output=True, text=True, timeout=TIMEOUT,
                           stdin=subprocess.DEVNULL)
    return r.returncode == 0, 0


def validate(kind, text):
    """Run checker KIND on already-rendered TEXT.  -> (ok, line number or 0).  Never raises on bad input."""
    try:
        if kind == "python":
            ast.parse(text)
            return True, 0
        if kind == "json":
            json.loads(text)
            return True, 0
        if kind in ("bash", "zsh"):
            return _shell(kind, text)
        if kind == "plist":
            return _plist(text)
        if kind == "xml":
            return _xml(text)
    except SyntaxError as e:
        return False, e.lineno or 0
    except ValueError as e:                    # json.JSONDecodeError, null bytes in source, ...
        return False, getattr(e, "lineno", 0) or 0
    except (subprocess.TimeoutExpired, OSError):
        return False, 0
    return True, 0


def check_tree(root, source_root=None, file_map=None, allow=None):
    """Check every validatable file under ROOT.

    file_map: {output rel path (relative to ROOT) -> source rel path} so a failure can be classified against the
    original; allow: allowlist.Allowlist (syntax_exempt).  -> (files checked, [(category, kind, rel, line)]).
    """
    root = Path(root)
    allow = allow or al.Allowlist()
    checked, bad = 0, []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink() or ".git" in p.relative_to(root).parts:
            continue
        rel = p.relative_to(root).as_posix()
        if os.path.basename(rel) in sr.META_FILES:
            continue
        try:
            text = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue                           # binaries are the verifier's business
        kind = kind_of(rel, text)
        if kind is None:
            continue
        checked += 1
        ok, line = validate(kind, render(text))
        if ok:
            continue
        # Which side is to blame?  Check the source original (raw, it has no placeholders).
        category = "SOURCE_INVALID"
        src_rel = (file_map or {}).get(rel)
        if source_root and src_rel:
            try:
                src_text = (Path(source_root) / src_rel).read_bytes().decode("utf-8")
                if validate(kind, src_text)[0]:
                    category = "BROKEN_BY_REWRITE"
            except (OSError, UnicodeDecodeError):
                pass
        # Exemptions are matched on the source path (what the owner writes) and the output path.
        if allow.syntax_exempt(rel) or (src_rel and allow.syntax_exempt(src_rel)):
            continue
        bad.append((category, kind, rel, line))
    return checked, bad


def main(argv=None):
    """CLI: syntax_check.py TREE [--source-root DIR] [--allowlist FILE]; exit 1 on any failure."""
    import argparse
    ap = argparse.ArgumentParser(description="Syntax-check a scrubbed tree")
    ap.add_argument("tree")
    ap.add_argument("--source-root")
    ap.add_argument("--allowlist")
    a = ap.parse_args(argv)
    try:
        allow = al.load_allowlist(a.allowlist)
    except al.AllowlistError as e:
        print("syntax_check: FATAL: %s" % e, file=sys.stderr)
        return 2
    n, bad = check_tree(a.tree, a.source_root, None, allow)
    for cat, kind, rel, line in bad:
        print("%s:%d: %s[%s]" % (rel, line, cat, kind))
    print("syntax_check: checked %d files; failures=%d" % (n, len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
