#!/usr/bin/env python3
"""allowlist: the ONE file that records every deliberate exception to the release rules.  Stdlib only (python 3.9).

Why it exists: many test files deliberately contain fake secrets,
fake SSNs and the like, and a few binaries (a PDF, a database) may be wanted in the release.  Without a recorded,
reviewable exception the scrubber would rewrite the fixtures (breaking the tests) and the verifier could not tell a
fixture from a leak.  Everything exceptional is therefore listed here, with a reason, and nowhere else.

File format (JSON object; unknown keys are an error so a typo cannot silently disable a rule):

  {
    "version": 1,
    "fixtures": [
      {"path": "tests/test_scan.py",              # fnmatch glob against the relative path ('*' also crosses '/')
       "strings": ["ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000"],   # the EXACT fake strings, each >= 6 chars
       "reason": "detector test input, not a real credential"}    # required, non-empty
    ],
    "approved_binaries": [
      {"sha256": "<64 hex chars of the exact bytes>",             # approval is by content hash: a changed file is
       "path": "docs/spec.pdf",                                   # no longer approved.  'path' is documentation only.
       "reason": "hand-reviewed: no metadata"}
    ],
    "syntax_exempt": [
      {"path": "tests/fixtures/broken.py", "reason": "deliberately invalid input for a parser test"}
    ]
  }

What an exception does NOT do:
  * a fixture string never hides a real private value: loading is refused when a fixture string contains a private
    value (or a private value contains the fixture string), so an allowlisted string can never be the owner's data;
  * an approved binary is still scanned inside (archives are opened, bytes are searched); approval only waives the
    "binary type needs a human" finding, never a private-value finding;
  * nothing here is ever printed with its content: messages carry paths and counts only.
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

import normalize

# Keys allowed at the top level and inside each entry kind.  Anything else is rejected (typo protection).
TOP_KEYS = {"version", "fixtures", "approved_binaries", "syntax_exempt"}
FIXTURE_KEYS = {"path", "strings", "reason"}
BINARY_KEYS = {"sha256", "path", "reason"}
SYNTAX_KEYS = {"path", "reason"}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MIN_FIXTURE_LEN = 6          # shorter strings would blank out too much of a line during verification


# Common words that are never treated as sensitive on their own (single source: release_gate imports this set).
STOP_WORDS = {"local", "home", "users", "user", "this", "that", "with", "from", "file", "test", "name", "example",
              "host", "localhost", "documents", "library", "desktop", "root", "public", "private", "the", "and"}
WORD_RE = re.compile(r"[A-Za-z0-9]+")


def distinct_words(text):
    """Lower-cased, folded words of TEXT that are distinctive enough for the gate to scan for on their own: letters
    words of 4+ chars or digit words of 7+ chars, never a stop word.  The SAME rule the gate uses for the words of
    a private value, so "the gate would flag this word" and "an allowlist may not contain this word" agree.
    Example: distinct_words("Zebediah-test") -> {"zebediah"}  ("test" is a stop word)."""
    out = set()
    for m in WORD_RE.finditer(normalize.fold(text)):
        w = m.group(0).lower()
        if w in STOP_WORDS:
            continue
        if (re.search(r"[a-z]", w) and len(w) >= 4) or (not re.search(r"[a-z]", w) and len(w) >= 7):
            out.add(w)
    return out


class AllowlistError(Exception):
    """The allowlist file is malformed or unsafe (message never contains fixture text)."""


def _check_entry(entry, allowed, what, idx):
    """Common validation: dict, only known keys, non-empty reason."""
    if not isinstance(entry, dict):
        raise AllowlistError("%s[%d] must be an object" % (what, idx))
    extra = set(entry) - allowed
    if extra:
        raise AllowlistError("%s[%d] has unknown keys: %s" % (what, idx, ", ".join(sorted(extra))))
    if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
        raise AllowlistError("%s[%d] needs a non-empty \"reason\"" % (what, idx))


class Allowlist:
    """Parsed, validated allowlist.  An empty Allowlist() allows nothing (the default)."""

    def __init__(self, data=None, private_values=None):
        # data: parsed JSON dict (or None for "no exceptions").
        # private_values: iterable of the owner's exact private strings, used only to refuse unsafe fixtures.
        data = data or {}
        if not isinstance(data, dict):
            raise AllowlistError("allowlist must be a JSON object")
        extra = set(data) - TOP_KEYS
        if extra:
            raise AllowlistError("unknown top-level keys: %s" % ", ".join(sorted(extra)))
        self.fixtures = []          # list of (glob, [strings])
        self.binaries = {}          # sha256 -> reason
        self.syntax = []            # list of globs
        priv = [p.casefold() for p in (private_values or [])]
        # Every distinctive WORD of every private value.  A fixture string may not contain one: the value-scan blanks
        # fixture strings, so "Zebediah-test" would hide the owner's name wherever it is written.  (Whole-value and
        # containment overlap is checked below as before.)
        priv_words = set()
        for p in (private_values or []):
            priv_words |= distinct_words(p)
        for i, e in enumerate(data.get("fixtures", [])):
            _check_entry(e, FIXTURE_KEYS, "fixtures", i)
            if not isinstance(e.get("path"), str) or not e["path"]:
                raise AllowlistError("fixtures[%d] needs a \"path\"" % i)
            if not re.search(r"[^*?/\[\]]", e["path"]):
                # fnmatch '*' crosses '/', so a wildcard-only path would blank the string in EVERY file.
                raise AllowlistError("fixtures[%d] path must name something (not only wildcards)" % i)
            strs = e.get("strings")
            if not isinstance(strs, list) or not strs or not all(isinstance(s, str) for s in strs):
                raise AllowlistError("fixtures[%d] needs a non-empty \"strings\" list" % i)
            for s in strs:
                if len(s) < MIN_FIXTURE_LEN or "\n" in s or "\r" in s or "{{" in s:
                    raise AllowlistError("fixtures[%d] has a string that is too short, multi-line or contains a placeholder" % i)
                cf = s.casefold()
                # A fixture string must never be (or contain, or sit inside) a real private value.
                if any(p in cf or cf in p for p in priv):
                    raise AllowlistError("fixtures[%d] overlaps a private value; an allowlist cannot whitelist real data" % i)
                if distinct_words(s) & priv_words:
                    raise AllowlistError("fixtures[%d] contains a word of a private value; an allowlist cannot whitelist real data" % i)
            self.fixtures.append((e["path"], list(strs)))
        for i, e in enumerate(data.get("approved_binaries", [])):
            _check_entry(e, BINARY_KEYS, "approved_binaries", i)
            sha = e.get("sha256")
            if not isinstance(sha, str) or not SHA_RE.match(sha):
                raise AllowlistError("approved_binaries[%d] needs a lowercase 64-hex \"sha256\"" % i)
            self.binaries[sha] = e["reason"]
        for i, e in enumerate(data.get("syntax_exempt", [])):
            _check_entry(e, SYNTAX_KEYS, "syntax_exempt", i)
            if not isinstance(e.get("path"), str) or not e["path"]:
                raise AllowlistError("syntax_exempt[%d] needs a \"path\"" % i)
            self.syntax.append(e["path"])

    # ---- queries -------------------------------------------------------------------------------------------
    def fixture_strings(self, rel):
        """Exact fake strings that may appear unscrubbed in file REL (longest first, so overlaps resolve sanely)."""
        out = []
        for glob, strs in self.fixtures:
            if fnmatch.fnmatchcase(rel, glob):
                out.extend(strs)
        return sorted(set(out), key=lambda s: (-len(s), s))

    def all_fixture_strings(self):
        """Every fixture string regardless of path (used to filter the shell leak check)."""
        return sorted({s for _g, strs in self.fixtures for s in strs})

    def binary_approved(self, sha256_hex):
        """True if the bytes with this sha256 were hand-approved."""
        return sha256_hex in self.binaries

    def syntax_exempt(self, rel):
        """True if REL is exempt from the syntax gate."""
        return any(fnmatch.fnmatchcase(rel, g) for g in self.syntax)


def load_allowlist(path, private_values=None):
    """Read PATH (or return an empty Allowlist when PATH is None)."""
    if path is None:
        return Allowlist(None, private_values)
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise AllowlistError("cannot read allowlist: %s" % type(e).__name__)
    return Allowlist(data, private_values)


def mask_fixtures(text, strings):
    """Return TEXT with every occurrence of each fixture string replaced by same-length spaces.

    Same length keeps offsets and line numbers identical, so findings elsewhere on the line stay exact.
    """
    for s in strings:
        if s in text:
            text = text.replace(s, " " * len(s))
    return text


def fixture_spans(text, strings):
    """(start, end) of every occurrence of each fixture string in TEXT.

    The gate uses these spans to ignore a PATTERN hit ONLY when the whole hit lies inside an allowlisted fixture;
    text outside the fixture is still pattern-scanned (the fixture never blanks its neighbours)."""
    spans = []
    for s in strings:
        i = text.find(s)
        while i != -1:
            spans.append((i, i + len(s)))
            i = text.find(s, i + 1)
    return spans
