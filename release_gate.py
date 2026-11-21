#!/usr/bin/env python3
r"""release_gate: the single VERIFIER.  Scans an output tree; exit nonzero if anything private could ship.
Stdlib only (python 3.9).

  release_gate.py [--staging DIR] [--values PRIVATE.json] [--release-root DIR] [--allow-email ADDR ...]
                  [--allowlist FILE]

Checks (per file, per path part, and INSIDE carriers):
  PRIVATE_VALUE   private value, its words, or contiguous word runs: salted-hash match (case-insensitive) PLUS the
                  encoded variants of each full value: url-encoded, base64 (3 alignments, std + urlsafe) and
                  punctuation-split (john.smith / john_smith).  Detail is the KEY name (and ":variant").
  PATTERN         leftover pattern-class hit (home path, email, private IP, MAC, hostname, tailnet name, keys, tokens,
                  phone, EIN/UEI/DUNS, Syncthing id)
  PRIVATE_KEY     PEM/PGP private key block
  REFUSED_TYPE    binary / archive / db / pdf / image / key file type or content that is NOT hand-approved
                  (approval = sha256 of the exact bytes listed in the allowlist file)
  METADATA        author/creator/company metadata inside office documents (docx/xlsx/pptx/odf) and PDFs, unless neutral
  CARRIER         a container that could not be fully inspected (too big when decompressed, too deep, encrypted,
                  corrupt, zip-slip member name)
  EXCLUDE_LIST    path (inside the component) matches _privacy/EXCLUDE_LIST.txt
  STRUCTURE       symlink, missing ANNOTATIONS.json
Carriers: .gz is decompressed; zip/docx/xlsx/pptx/odt/jar are opened and every member (name and content) is scanned,
recursively (depth <= 3, size and ratio capped against decompression bombs); tar is opened the same way; SQLite, PDF
and other binaries have their printable ASCII and UTF-16LE strings extracted and scanned (PDF flate streams are
inflated).  Allowlisted fixture strings (see allowlist.py) are blanked for the value scan (see below).
Matching is done on normalised text (see normalize.py): zero-width characters, soft hyphens, fullwidth letters,
accents, Cyrillic/Greek look-alikes, \uXXXX / \xXX / &#NN; escapes, adjacent string literals and CRLF are folded away; a
value split over two lines is found; rot13, reversed, hex and base64 (any common casing) forms are checked.
Allowlisted fixture strings are blanked for the VALUE scan only; the PATTERN scan sees the raw line and ignores a hit
only when it lies entirely inside a fixture.  A file or folder NAME that holds a private value is printed as "path#<n>".
Output: counts and file:line only.  Matched text is never printed.  Exit 0 clean, 1 findings, 2 setup error.

Purpose
  The last line of defence before publishing. scrub_release.py replaces private values with tokens; this gate
  independently re-scans the result and fails if anything private could still be present, including things the
  scrubber is not expected to catch (a stray word of a private value, a file edited by hand afterwards, a value
  hidden inside an archive or encoded as base64 / url-encoding).

Design notes / threat model
  * The scan works from salted hashes of every private value, each of its words and each contiguous run of words.
    Candidate strings exist only in memory; matched text is never printed, only the KEY name, file and line, so the
    gate's own output cannot leak what it finds. Archive member names are reported as "member#<n>" for the same reason.
  * {{TOKEN}} placeholders are blanked out before scanning (they are the intended replacement), as are whole words the
    values file explicitly allows (public names that merely contain a private word), the public phrases it lists in
    gate_public_phrases (whole phrase only, case-sensitive, word-bounded, may overlap only the WORKSPACE_NAME key) and
    allowlisted fixture strings.
  * Pattern checks (home paths, emails, IPs, keys, tokens, phone numbers...) reuse scrub_release.PATTERNS so the
    scrubber and the gate cannot drift apart.
  * Fails closed: unreadable files, symlinks, foreign .git folders, a missing ANNOTATIONS.json, hashes in the public
    annotation file, containers that cannot be fully inspected, and non-neutral document metadata are all findings.
  * Decompression is capped (depth, member count, bytes, ratio) so a malicious archive cannot exhaust memory.

Usage
  python3 tools/release_gate.py --staging staging [--allowlist FILE] [--neutral-author NAME] [--allow-email ADDR]
  Example output: "demo/notes.txt:12: PATTERN[EMAIL]" lines, then "release_gate: FAIL" (exit 1) or "release_gate: PASS".
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path
from urllib.parse import quote, quote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scrub_release as sr  # noqa: E402  (shared value loading, patterns, hashing and exclude-list logic)
import allowlist as al  # noqa: E402  (fixture strings and hand-approved binaries)
import normalize  # noqa: E402  (shared text folding: zero-width, accents, fullwidth, escapes)

# Common words that are never treated as sensitive on their own when they appear as a word of a private value,
# e.g. a value "Alice Smith Home" must not make every "home" in the text a finding.
# (They still match as part of the full value or a longer run of words.)
STOP_WORDS = al.STOP_WORDS   # single definition shared with the allowlist validator
# One "word" for the gate: a run of ASCII letters/digits. Example: "alpha-9" yields words "alpha" and "9".
WORD_RE = re.compile(r"[A-Za-z0-9]+")


def _qualifies(word):
    """Decide whether a single word of a private value is distinctive enough to be scanned for on its own.

    Stop words never qualify. Words with letters need 4+ characters; all-digit words need 7+ (short numbers such
    as years or ports would cause constant false positives).
    """
    w = word.lower()
    if w in STOP_WORDS:
        return False
    if re.search(r"[a-z]", w):
        return len(w) >= 4
    return len(w) >= 7


class HashScanner:
    """Finds private strings in text by salted hash.  Candidate strings are derived in memory from the private
    values: the full value, each qualifying word, and each contiguous run of words (with original separators).

    Only salted hashes are kept after construction, so the scanner does not retain the plaintext candidates.
    """

    def __init__(self, pv):
        """Build the hash index.

        Args:
            pv: a scrub_release.PrivateValues (needs .salt, .allow_re, .public_re, .flat, .ignore_words).
        """
        self.salt = pv.salt
        self.allow_re = pv.allow_re
        self.public_re = pv.public_re      # whole public phrases to blank before scanning (gate_public_phrases)
        self.identity_re = pv.identity_re  # declared public contact/handle tokens (gate_public_identity), blanked whole
        self.identity_count = 0            # occurrences blanked in the CURRENT file (gate() collects it per file)
        self.hashes = {}        # gate_hash -> set(keys)
        self.by_prefix = {}     # first 3 chars -> set(lengths)
        for key, value in pv.flat.items():
            cands = {value.lower()}   # the whole value always counts (case-insensitive)
            words = [m for m in WORD_RE.finditer(value)]
            for i, wi in enumerate(words):
                # single words: only distinctive ones, and not those the values file says to ignore
                if _qualifies(wi.group(0)) and wi.group(0).lower() not in pv.ignore_words:
                    cands.add(wi.group(0).lower())
                for j in range(i + 1, len(words)):
                    # contiguous runs of 2+ words, keeping the original separators; skip runs made only of
                    # non-distinctive words (e.g. "the and")
                    run = value[wi.start():words[j].end()]
                    if any(_qualifies(w.group(0)) for w in words[i:j + 1]):
                        cands.add(run.lower())
            # Index by hash, plus a (first 3 chars -> lengths) table so scan() only hashes plausible windows.
            # Also index the FOLDED form (accents/zero-width/fullwidth removed) of every candidate, so a value that itself
            # contains an accent is still found in text that the gate folds.
            cands |= {normalize.fold(c).lower() for c in cands}
            for c in cands:
                if len(c) < sr.MIN_VALUE_LEN:
                    continue
                self.hashes.setdefault(sr.gate_hash(self.salt, c), set()).add(key)
                self.by_prefix.setdefault(c[:3], set()).add(len(c))

    def scan(self, text, min_len=0):
        """Return the set of value keys whose strings occur in text (case-insensitive).

        min_len: ignore candidates shorter than this (used for the rot13 / reversed views, where short candidates
        would match ordinary text by accident).

        Slides over the lowercased text; at each position looks up which candidate lengths start with those 3
        characters, hashes just those substrings and checks them against the index. Cost is roughly linear in the
        text length. Returns an empty set when nothing matches; never returns the matched text.
        """
        low = text.lower()
        hits = set()
        bp = self.by_prefix
        for i in range(len(low) - 2):
            lens = bp.get(low[i:i + 3])
            if lens:
                for n in lens:
                    if n < min_len:
                        continue
                    h = sr.gate_hash(self.salt, low[i:i + n])
                    if h in self.hashes:
                        hits |= self.hashes[h]
        return hits


# --------------------------------------------------------------------------------------------- encoded variants
# The salted-hash scanner only knows plain (case-insensitive) text.  Attackers (and sloppy tools) also leave values
# url-encoded, base64-encoded or with different punctuation.  These needles are built in memory from the private
# values for every FULL value (not word fragments: too noisy) and are never printed or stored.
# Minimum length of a base64 fragment used as a search needle, e.g. "am9obiBzbWl0aA" (8+ chars of a base64 stream).
MIN_B64_FRAGMENT = 8          # shorter base64 fragments would false-positive on ordinary text


def base64_needles(value):
    """Base64 fragments of VALUE as they appear at any 3-byte alignment (standard and URL-safe alphabets).

    Encode (k filler bytes + value), then drop the leading characters influenced by the filler and the trailing
    character that mixes in padding bits: what is left occurs inside ANY larger base64 stream embedding the value.

    Args:
        value: private value string.
    Returns:
        set of fragments (8+ chars each); empty for very short values.
    """
    raw = value.encode("utf-8")
    out = set()
    for k in range(3):   # k filler bytes model the three possible alignments of the value in a byte stream
        enc = base64.b64encode(b"\x00" * k + raw).decode("ascii").rstrip("=")
        lead = {0: 0, 1: 2, 2: 3}[k]   # base64 characters still affected by the filler bytes
        trail = 1 if (k + len(raw)) % 3 else 0
        frag = enc[lead:len(enc) - trail] if trail else enc[lead:]
        if len(frag) >= MIN_B64_FRAGMENT:
            out.add(frag)
            out.add(frag.replace("+", "-").replace("/", "_"))
    return out


class VariantScanner:
    """Compiled needles for the encoded variants of every private value."""

    def __init__(self, flat):
        """Build needles from the flat {key: value} mapping of private values (kept in memory only)."""
        self.needles = []            # (key, variant label, compiled regex)
        for key, v in flat.items():
            encs = {quote(v, safe=""), quote(v), quote_plus(v), quote(quote(v, safe=""), safe="")}
            for enc in sorted(encs):
                if enc != v:
                    self.needles.append((key, "urlencoded", re.compile(re.escape(enc), re.I)))
            # base64 is case-sensitive, so encode every common casing of the value, not only the one in the file.
            frags = set()
            for cv in {v, v.lower(), v.upper(), v.title(), v.capitalize()}:
                frags |= base64_needles(cv)
            for frag in sorted(frags):
                self.needles.append((key, "base64", re.compile(re.escape(frag))))
            # hex of the UTF-8 bytes (any casing of the value; hex digits themselves case-insensitive), optionally
            # separated by space/colon/comma/dash and "0x" prefixes.  Needs 4+ bytes to stay out of ordinary numbers.
            for cv in sorted({v, v.lower(), v.upper(), v.title(), v.capitalize()}):
                raw = cv.encode("utf-8")
                if len(raw) >= 4:
                    sep = r"(?:[\s:,\-]|0x)*"
                    rx = sep.join("%02x" % b for b in raw)
                    self.needles.append((key, "hex", re.compile(rx, re.I)))
            parts = re.findall(r"[A-Za-z0-9]+", v)
            if len(parts) >= 2:                                                       # john smith -> john.smith
                rx = r"[^A-Za-z0-9]{0,3}".join(re.escape(p) for p in parts)
                self.needles.append((key, "split-punctuation", re.compile(rx, re.I)))
            elif len(parts) == 1 and len(parts[0]) >= 6 and re.fullmatch(r"[A-Za-z0-9]+", v):
                # A SINGLE-word value with up to 3 punctuation/space characters between ANY two of its characters
                # (z-q-u-i-l-l-7-7, "z q u i l l", zqu.ill77).  Needs 6+ characters so ordinary short words are
                # not matched by accident.  Labelled "split-chars".
                rx = r"[^A-Za-z0-9]{0,3}".join(re.escape(c) for c in parts[0])
                self.needles.append((key, "split-chars", re.compile(rx, re.I)))

    def scan(self, text):
        """Return the set of 'KEY:variant' labels (variant = urlencoded, base64 or split-punctuation) found in TEXT."""
        return {"%s:%s" % (k, var) for k, var, rx in self.needles if rx.search(text)}


# --------------------------------------------------------------------------------------------- scanning context
# Metadata author/company values that identify nobody and are therefore not findings (lower-case comparison).
NEUTRAL_AUTHORS = {"", "author", "anonymous", "unknown", "neutral", "release", "user", "microsoft office user",
                   "python-docx", "openpyxl"}   # tool/neutral names that identify nobody; extend via --neutral-author
# Limits that stop decompression bombs and pathological archives; hitting one is a CARRIER finding, not a skip.
MAX_DEPTH = 3                           # archive-in-archive nesting allowed
MAX_MEMBER_BYTES = 64 * 1024 * 1024     # one decompressed member
MAX_TOTAL_BYTES = 256 * 1024 * 1024     # all decompressed bytes for one top-level file
MAX_MEMBERS = 5000                      # members per archive
MAX_RATIO = 1000                        # compressed->decompressed ratio treated as a bomb (when >1 MiB out)
# Printable ASCII run of 4+ characters inside binary data (like the `strings` tool). Example: b"hello world".
STR_ASCII = re.compile(rb"[\x20-\x7e\t]{4,}")
# UTF-16LE text run of 4+ characters (each ASCII character followed by NUL), as found in Office and Windows files.
STR_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
# Author-like XML elements in Office/ODF metadata. Matches "<dc:creator>Name</dc:creator>", "<Company>X</Company>",
# "<cp:lastModifiedBy>..." etc.; group 1 = tag name, group 2 = text content.
META_TAG = re.compile(r"<(dc:creator|cp:lastModifiedBy|meta:initial-creator|Company|Manager|dc:lastModifiedBy)"
                      r"(?:\s[^>]*)?>([^<]*)</", re.I)
# PDF info-dictionary entry holding text. Matches "/Author (Some Name)", "/Creator (tool)"; group 1 = field, group 2 = value.
PDF_INFO = re.compile(rb"/(Author|Creator|Title|Subject|Keywords)\s*\(((?:[^()\\]|\\.)*)\)")
# A PDF stream body between "stream" and "endstream" (usually flate-compressed); group 1 = the raw stream bytes.
PDF_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)


class Ctx:
    """Everything one scan needs: scanners, allowlists, a finding sink and the decompression budget."""

    def __init__(self, scanner, variants, allow_emails, allow, neutral, literals=(), registered=None):
        """Args: scanner (HashScanner), variants (VariantScanner), allow_emails (lower-case set), allow (allowlist.
        Allowlist), neutral (iterable of metadata values that identify nobody; stored lower-case).

        literals: (label, text) pairs that must NEVER appear anywhere (B2: the salt and the values file's path); a hit
        is reported as PRIVATE_VALUE[label] without the text.
        registered: None = do not check placeholder tokens (library use, tests); otherwise the set of placeholder
        strings that the file's component lists in its ANNOTATIONS.json.  A {{TOKEN}} not in the set is a finding
        (LOW-2), set per file by gate()."""
        self.scanner, self.variants, self.allow_emails = scanner, variants, allow_emails
        self.allow, self.neutral = allow, set(n.lower() for n in neutral)
        self.literals = [(lab, t) for lab, t in literals if t]
        self.registered = registered
        self.mask = []          # fixture strings valid for the file being scanned (set per top-level file)
        self.budget = 0         # remaining decompressed bytes for the file being scanned


def _blank_tokens(text):
    """Blank {{TOKEN}} placeholders (same length) so a placeholder name is never mistaken for a private word."""
    return sr.TOKEN_RE.sub(lambda m: " " * len(m.group(0)), text)


def _within(spans, start, end):
    """True if [start, end) lies completely inside one of the (s, e) SPANS."""
    return any(s <= start and end <= e for s, e in spans)


def _value_hits(view, ctx):
    """All private-value detections in one text VIEW, as a set of detail strings (never the matched text).

    Detections: salted-hash match of the value / its words / word runs -> "KEY"; encoded needles (url, base64 of any
    casing, hex, punctuation-split) -> "KEY:variant"; the same hash scan on the rot13 and the reversed text ->
    "KEY:rot13" / "KEY:reversed" (candidates under 6 chars skipped there to avoid accidental matches).
    """
    if not view.strip():
        return set()
    hits = set(ctx.scanner.scan(view))
    hits |= set(ctx.variants.scan(view))
    for label, other in (("rot13", normalize.rot13(view)), ("reversed", view[::-1])):
        hits |= {"%s:%s" % (k, label) for k in ctx.scanner.scan(other, min_len=6)}
    return hits


def _line_views(clean, ctx):
    """Texts of ONE line that the value scans run on: the line itself and its folded form (see normalize.fold), each
    with whole allowed words and public phrases blanked (same length).  Duplicates removed."""
    views = []
    for v in (clean, normalize.fold(clean)):
        aw = ctx.scanner.allow_re
        if aw:
            v = aw.sub(lambda m: " " * len(m.group(0)), v)
        pp = ctx.scanner.public_re
        if pp:
            v = pp.sub(lambda m: " " * len(m.group(0)), v)
        ir = ctx.scanner.identity_re
        if ir:
            # gate_public_identity: blank each declared token as a WHOLE token (same length, so a name written next to
            # it is still found).  Only the first view (the line as written) is counted, the folded view is the same
            # text again.
            first = not views
            def blank(m, first=first):
                if first:
                    ctx.scanner.identity_count += 1
                return " " * len(m.group(0))
            v = ir.sub(blank, v)
        if v not in views:
            views.append(v)
    return views


def scan_text(text, ctx, report, where=None, is_path=False):
    """Scan TEXT line by line; report(category, detail, line).

    Order of operations (the allowlist can only ever hide the fixture string itself):
      * PATTERN / PRIVATE_KEY scan runs on the UNMASKED line.  A hit is ignored only when it lies entirely inside an
        allowlisted fixture string, so a fixture cannot hide an email, IP, home path or key written next to it.
      * the VALUE scan runs on the line with fixture strings, {{TOKENS}}, allowed words and public phrases blanked
        (same length), on the line AND on its folded form (zero-width, soft hyphen, fullwidth, accents, look-alike
        letters, \\u / \\x / &#..; escapes, adjacent string literals), plus rot13, reversed, url, base64 (any casing),
        hex and punctuation-split variants.
      * a value split over two consecutive lines (LF or CRLF, indentation ignored) is found by also scanning the two
        lines joined; the finding is reported at the first line.

    Args:
        text: file content, or a relative path when is_path is true.
        ctx: Ctx with scanners and the per-file fixture mask.
        report: callable report(category, detail, line); line is 0 for a path.
        where: unused label kept for call-site readability.
        is_path: treat text as one path string (no line splitting; findings get line 0).
    Never passes matched text to report, only categories, keys and classes.
    """
    lines = [text] if is_path else text.split("\n")
    prev_view, prev_hits, prev_ln = None, set(), 0
    for i, raw in enumerate(lines, 1):
        ln = 0 if is_path else i
        spans = al.fixture_spans(raw, ctx.mask) if ctx.mask else []
        for m in sr.PRIVATE_KEY_RE.finditer(raw):
            if not _within(spans, m.start(), m.end()):
                report("PRIVATE_KEY", "", ln)
                break
        else:
            # B3: a header disguised with zero-width / fullwidth / look-alike characters or escapes only shows after folding
            if sr.PRIVATE_KEY_RE.search(normalize.fold(raw, join_literals=False)):
                report("PRIVATE_KEY", "", ln)
        # B2: strings that must never ship at all (the salt, the values file path).  Checked on the raw line and on its
        # folded form, case-sensitively and case-insensitively; only the label is reported.
        if ctx.literals:
            fl = normalize.fold(raw, join_literals=False)
            rl, fll = raw.lower(), fl.lower()
            for label, lit in ctx.literals:
                ll = lit.lower()
                if lit in raw or lit in fl or ll in rl or ll in fll:
                    report("PRIVATE_VALUE", label, ln)
        # LOW-2: a {{TOKEN}} that the component's ANNOTATIONS.json does not list was added by hand.  Tokens are blanked
        # below so a placeholder name is never mistaken for a private word, which means a value written AS a token
        # name ({{ZQUILL77}}) would otherwise be invisible.
        if ctx.registered is not None:
            for tm in sr.TOKEN_RE.finditer(raw):
                if tm.group(0) not in ctx.registered:
                    report("PLACEHOLDER", "unregistered token", ln)
                    break
        clean = _blank_tokens(raw)
        # Pattern scan: unmasked line; only hits fully inside a fixture are ignored.
        for st, en, cls in sr.pattern_spans(clean, ctx.allow_emails):
            if not _within(spans, st, en):
                report("PATTERN", cls, ln)
        masked = al.mask_fixtures(clean, ctx.mask)
        folded = normalize.fold(masked, join_literals=False)   # no literal-joining here: see normalize.fold
        if folded != masked:
            # A pattern hidden by Unicode tricks (fullwidth "@", zero-width inside an address) shows up after folding.
            for _s, _e, cls in sr.pattern_spans(folded, ctx.allow_emails):
                report("PATTERN", cls, ln)
        hits = set()
        views = _line_views(masked, ctx)
        for v in views:
            hits |= _value_hits(v, ctx)
        for h in sorted(hits):
            report("PRIVATE_VALUE", h, ln)
        # Two-line join: the folded view of the previous line and this one, indentation and line ends removed.
        cur_view = views[-1]
        if prev_view is not None and not is_path:
            joined = prev_view.rstrip() + cur_view.lstrip()
            for h in sorted(_value_hits(joined, ctx) - prev_hits - hits):
                report("PRIVATE_VALUE", h, prev_ln)
        prev_view, prev_hits, prev_ln = cur_view, hits, ln


def _bytes_as_text(data):
    """Printable ASCII and UTF-16LE runs of DATA as newline-joined text (what `strings` would show)."""
    runs = [m.group(0).decode("ascii", "replace") for m in STR_ASCII.finditer(data)]
    runs += [m.group(0).decode("utf-16-le", "replace") for m in STR_UTF16.finditer(data)]
    return "\n".join(runs)


def _inflate_capped(data, ctx):
    """zlib/gzip-inflate DATA with the remaining budget as a hard cap.  -> bytes, or None if not inflatable.
    Raises OverflowError when the cap is hit (decompression bomb)."""
    for wbits in (31, 15):   # 31 = gzip container, 15 = raw zlib stream; try both
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, min(ctx.budget, MAX_MEMBER_BYTES) + 1)
        except zlib.error:
            continue   # not this format; try the next
        if len(out) > min(ctx.budget, MAX_MEMBER_BYTES) or d.unconsumed_tail:
            raise OverflowError
        ctx.budget -= len(out)   # charge the decompressed size against this file's total budget
        return out
    return None


def scan_blob(data, name, ctx, report, depth=0, label_for_member=None):
    """Inspect non-text bytes DATA (named NAME) for private values; descend into containers.

    report(category, detail, line) writes a finding against the top-level file; member names are folded into the
    detail as '#<n>' counters rather than printed (a member NAME can itself be private).
    """
    if depth > MAX_DEPTH:
        report("CARRIER", "nested too deeply", 0)
        return
    low = name.lower()
    # ---- gzip -----------------------------------------------------------------------------------------
    if data[:2] == b"\x1f\x8b":
        try:
            inner = _inflate_capped(data, ctx)
        except OverflowError:
            report("CARRIER", "gzip expands beyond the size cap", 0)
            return
        if inner is None:
            report("CARRIER", "corrupt gzip", 0)
            return
        scan_blob_or_text(inner, name[:-3] if low.endswith(".gz") else name, ctx, report, depth + 1)
        return
    # ---- zip family (zip, docx, xlsx, pptx, odt, jar, whl ...) --------------------------------------------
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            report("CARRIER", "corrupt zip", 0)
            return
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            report("CARRIER", "too many archive members", 0)
            return
        if zf.comment:
            scan_text(zf.comment.decode("utf-8", "replace"), ctx, lambda c, d, ln: report(c, "zip-comment:" + d, 0))
        for n, zi in enumerate(infos, 1):
            tag = "member#%d" % n
            # report wrapper that tags every finding with the member counter instead of the (possibly private) name
            sub = lambda c, d, ln, tag=tag: report(c, ("%s:%s" % (tag, d)) if d else tag, ln)
            # member name: private value inside it, or a path-traversal name
            scan_text(zi.filename, ctx, sub, is_path=True)
            if zi.filename.startswith("/") or ".." in zi.filename.split("/"):
                report("CARRIER", tag + ":unsafe member name", 0)
            if zi.is_dir():
                continue
            if zi.flag_bits & 0x1:   # bit 0 = encrypted: cannot be inspected, so it fails
                report("CARRIER", tag + ":encrypted member", 0)
                continue
            # size caps and compression-ratio cap (zip bomb)
            if zi.file_size > MAX_MEMBER_BYTES or zi.file_size > ctx.budget or \
                    (zi.file_size > (1 << 20) and zi.compress_size and zi.file_size / zi.compress_size > MAX_RATIO):
                report("CARRIER", tag + ":member too large or suspicious ratio", 0)
                continue
            try:
                content = zf.read(zi)
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error):
                report("CARRIER", tag + ":unreadable member", 0)
                continue
            ctx.budget -= len(content)
            # Author metadata of office documents / odf lives in these well-known members.
            if zi.filename in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
                _check_office_meta(content, ctx, lambda c, d, ln: report(c, d, 0))
            scan_blob_or_text(content, zi.filename, ctx, sub, depth + 1)
        return
    # ---- tar -------------------------------------------------------------------------------------------
    if low.endswith((".tar", ".tgz")) or data[257:262] == b"ustar":   # "ustar" magic sits at offset 257
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data))
            members = tf.getmembers()
        except (tarfile.TarError, EOFError, OSError):
            report("CARRIER", "corrupt tar", 0)
            return
        if len(members) > MAX_MEMBERS:
            report("CARRIER", "too many archive members", 0)
            return
        for n, tm in enumerate(members, 1):
            tag = "member#%d" % n
            sub = lambda c, d, ln, tag=tag: report(c, ("%s:%s" % (tag, d)) if d else tag, ln)
            scan_text(tm.name, ctx, sub, is_path=True)
            # absolute paths, "..", symlinks and hard links could escape on extraction; never followed
            if tm.name.startswith("/") or ".." in tm.name.split("/") or tm.issym() or tm.islnk():
                report("CARRIER", tag + ":unsafe member (path or link)", 0)
                continue
            if not tm.isfile():
                continue
            if tm.size > MAX_MEMBER_BYTES or tm.size > ctx.budget:
                report("CARRIER", tag + ":member too large", 0)
                continue
            fh = tf.extractfile(tm)
            content = fh.read() if fh else b""
            ctx.budget -= len(content)
            scan_blob_or_text(content, tm.name, ctx, sub, depth + 1)
        return
    # ---- PDF: info dictionary + inflated streams + strings ----------------------------------------------------
    if data.startswith(b"%PDF-"):
        for m in PDF_INFO.finditer(data):
            val = m.group(2).decode("latin-1").strip()
            if val and val.lower() not in ctx.neutral and not sr.TOKEN_RE.search(val):
                report("METADATA", "pdf:/" + m.group(1).decode("ascii"), 0)
        chunks = [data]   # raw bytes plus every inflated stream, searched together
        for m in PDF_STREAM.finditer(data):
            if ctx.budget <= 0:
                break
            try:
                inner = _inflate_capped(m.group(1), ctx)
            except OverflowError:
                report("CARRIER", "pdf stream expands beyond the size cap", 0)
                break
            if inner:
                chunks.append(inner)
        scan_text(_bytes_as_text(b"\n".join(chunks)), ctx, lambda c, d, ln: report(c, d, 0))
        return
    # ---- SQLite and any other binary: search the printable strings --------------------------------------------
    scan_text(_bytes_as_text(data), ctx, lambda c, d, ln: report(c, d, 0))


def scan_blob_or_text(data, name, ctx, report, depth):
    """Dispatch for container members: valid UTF-8 without NULs is text, everything else is a blob.

    Args are those of scan_blob; depth is the current nesting level (bounded by MAX_DEPTH).
    """
    if depth > MAX_DEPTH:
        report("CARRIER", "nested too deeply", 0)
        return
    if b"\x00" not in data and not data.startswith((b"\x1f\x8b", b"PK", b"%PDF", b"SQLite format 3")):
        try:
            scan_text(data.decode("utf-8"), ctx, report)
            return
        except UnicodeDecodeError:
            pass   # not text after all: fall through to the binary scan
    scan_blob(data, name, ctx, report, depth)


def _check_office_meta(xml_bytes, ctx, report):
    """Flag non-neutral author/company fields of docProps/core.xml, app.xml or odf meta.xml (the NAME is never printed)."""
    text = xml_bytes.decode("utf-8", "replace")
    for m in META_TAG.finditer(text):
        val = m.group(2).strip()
        if val.lower() not in ctx.neutral and not sr.TOKEN_RE.search(val):
            report("METADATA", "office:" + m.group(1), 0)


# Generated pages that DESCRIBE placeholders (they quote token syntax such as `{{KEY.lower}}`) and so are not checked
# for unregistered tokens.  Only these exact locations count: <staging>/<name> and <staging>/<component>/<name>.
GENERATED_PAGES = ("ANNOTATIONS.md", "ANNOTATIONS.json", "REFUSED.md", "PLACEHOLDERS_INDEX.md")


def _registered_tokens(staging, comp):
    """Placeholder strings listed in <staging>/<comp>/ANNOTATIONS.json ("" = the staging root's own file).
    Missing or unreadable file -> empty set (every token is then unregistered, which fails closed)."""
    ap = (staging / comp / "ANNOTATIONS.json") if comp else (staging / "ANNOTATIONS.json")
    try:
        aj = json.loads(ap.read_text(encoding="utf-8"))
        return {r.get("placeholder") for r in aj.get("replacements", []) if isinstance(r, dict)}
    except (OSError, ValueError, AttributeError):
        return set()


def _values_path_literals(values_path):
    """Spellings of the values file's path that must not occur in a published tree (B2): as given, absolute,
    symlink-resolved and in "~/" form.  A path is only a path when it has a separator, so tiny values are skipped."""
    if not values_path:
        return []
    out = set()
    raw = str(values_path)
    p = os.path.expanduser(raw)
    for c in (raw, p, os.path.abspath(p), os.path.realpath(p)):
        out.add(c)
        home = os.path.expanduser("~")
        if home and c.startswith(home + os.sep):
            out.add("~" + c[len(home):])
    return [("VALUES_FILE_PATH", c) for c in sorted(out) if len(c) >= 12 and os.sep in c]


def gate(staging, pv, release_root, extra_allow=(), allow=None, neutral_authors=(), values_path=None, stats=None):
    """Scan STAGING.  -> (files scanned, sorted unique findings [(cat, detail, relpath, line)]).

    allow: allowlist.Allowlist (fixture strings, hand-approved binaries).  neutral_authors: extra metadata values
    that identify nobody.

    Args:
        staging: staging directory; its sub-folders are components, each with an ANNOTATIONS.json.
        pv: scrub_release.PrivateValues.
        release_root: release tree root (to find _privacy/EXCLUDE_LIST.txt).
        extra_allow: additional allowed email addresses.
        stats: optional dict; when given it receives "identity_blanked" = {shown path: occurrences} for the
            gate_public_identity tokens that were blanked (paths and counts only, never the tokens).
        values_path: path of the private values file; its path text and the salt are scanned for (B2).
    Findings use line 0 for "whole file" or "file name". Raises sr.ScrubError if staging does not exist.
    """
    staging = Path(staging)
    release_root = Path(release_root)
    allow = allow or al.Allowlist()
    pats = sr.parse_excludes(release_root / "_privacy" / "EXCLUDE_LIST.txt")
    # B2: the salt itself and the values file path are "private values" too (hash of a value is only as safe as the salt).
    literals = [("SALT", pv.salt)] + _values_path_literals(values_path)
    # A declared public contact EMAIL is also exempt from the EMAIL pattern (exact string only): it was declared on purpose.
    declared_emails = {x.lower() for x in pv.identity if "@" in x}
    ctx = Ctx(HashScanner(pv), VariantScanner(pv.flat), set(pv.allow_emails) | declared_emails | set(x.lower() for x in extra_allow),
              allow, set(NEUTRAL_AUTHORS) | set(neutral_authors), literals=literals)
    findings = []   # (category, detail, relpath, line)
    identity_by_file = {}   # relpath -> number of gate_public_identity tokens blanked in it
    registered_cache = {}   # component ("" = staging root) -> set of registered placeholder strings

    def add(rel):
        """Return a report callback bound to one file path."""
        def report(cat, detail, line):
            """Record one finding (category, detail, line) against the bound file path."""
            findings.append((cat, detail, rel, line))
        return report

    if not staging.is_dir():
        raise sr.ScrubError("staging dir not found")
    files = 0
    components = 0
    all_paths = sorted(q.relative_to(staging).as_posix() for q in staging.rglob("*"))
    order = {r: n for n, r in enumerate(all_paths, 1)}   # 1-based position in the plain string-sorted path list
    for p in sorted(staging.rglob("*")):
        rel = p.relative_to(staging).as_posix()
        if p.is_symlink():   # a link could point outside the tree and publish unscanned data
            findings.append(("STRUCTURE", "symlink", rel, 0))
            continue
        if p.is_dir():
            # every top-level folder is a component and must carry its annotation file
            if "/" not in rel and not (p / "ANNOTATIONS.json").is_file():
                findings.append(("STRUCTURE", "missing ANNOTATIONS.json", rel, 0))
            if "/" not in rel and rel != ".git":
                components += 1
            continue
        if not stat.S_ISREG(p.lstat().st_mode):
            # F5: a FIFO / socket / device would block (or never end) in read_bytes().  Never opened; always a finding.
            findings.append(("STRUCTURE", "special file (not a regular file)", rel, 0))
            continue
        parts = rel.split("/")
        if ".git" in parts:
            # Version-control metadata cannot be scrubbed or inspected here (history!).  The release step creates the
            # repo only AFTER this gate has passed, so any .git seen here is foreign and fails (reported once per dir).
            findings.append(("STRUCTURE", "git metadata in tree", "/".join(parts[:parts.index(".git") + 1]), 0))
            continue
        files += 1
        inner = "/".join(parts[1:]) if len(parts) > 1 else None   # path inside the component, None for root files
        rep = add(rel)
        # fixture strings allowed for this file (by full path or by in-component path); budget resets per top-level file
        ctx.mask = allow.fixture_strings(rel) + (allow.fixture_strings(inner) if inner else [])
        ctx.budget = MAX_TOTAL_BYTES
        # LOW-2: which {{TOKEN}}s may this file contain?  Those its component registers.  The generated description pages
        # (see GENERATED_PAGES) are exempt, but only at their real location.
        generated = (inner in GENERATED_PAGES) if inner is not None else (rel in GENERATED_PAGES)
        if generated:
            ctx.registered = None
        else:
            tokens = registered_cache.get(parts[0] if inner is not None else "")
            if tokens is None:
                tokens = registered_cache[parts[0] if inner is not None else ""] = _registered_tokens(
                    staging, parts[0] if inner is not None else "")
            ctx.registered = tokens
        ctx.scanner.identity_count = 0
        scan_text(rel, ctx, rep, is_path=True)
        exceptions = set()   # paths the component's manifest was granted an exclude-list exception for
        if inner is not None:
            ap = staging / parts[0] / "ANNOTATIONS.json"
            if ap.is_file():
                try:
                    aj = json.loads(ap.read_text(encoding="utf-8"))
                    exceptions = set(aj.get("exclude_exceptions", []))
                    if inner == "ANNOTATIONS.json" and any("hash" in r for r in aj.get("replacements", [])):
                        findings.append(("STRUCTURE", "ANNOTATIONS.json contains hashes (must stay private)", rel, 0))
                except ValueError:
                    findings.append(("STRUCTURE", "bad ANNOTATIONS.json", parts[0] + "/ANNOTATIONS.json", 0))
            if sr.excluded(inner, pats) and inner not in exceptions:
                rep("EXCLUDE_LIST", "", 0)
        try:
            data = p.read_bytes()
        except OSError:
            rep("STRUCTURE", "unreadable", 0)
            continue
        why = sr.refused_type(rel, data)
        approved = allow.binary_approved(hashlib.sha256(data).hexdigest())   # exact-bytes approval of a binary
        # private-key blocks are always reported (scan_text gives them a line number), so skip the duplicate here
        if why and "private key" not in why and not approved:
            rep("REFUSED_TYPE", why, 0)
        is_text = False   # text = valid UTF-8, no NUL, and not a known container/binary header
        try:
            text = data.decode("utf-8")
            is_text = b"\x00" not in data and not data.startswith((b"\x1f\x8b", b"PK", b"%PDF", b"SQLite format 3"))
        except UnicodeDecodeError:
            text = None
        if is_text:
            scan_text(text, ctx, rep)
        else:
            # Non-text: even when flagged/approved we look INSIDE, so a clean-looking archive cannot hide a value.
            scan_blob(data, rel, ctx, rep)
        if ctx.scanner.identity_count:
            identity_by_file[rel] = ctx.scanner.identity_count
    # B1: an empty tree must not PASS.  A wrong --staging path (the commonest operator mistake) would otherwise print
    # "scanned 0 files; findings=0 / PASS".
    if components == 0:
        findings.append(("STRUCTURE", "no component folder found in the staging directory (wrong path?)", "(staging)", 0))
    if files == 0:
        findings.append(("STRUCTURE", "scanned 0 files: nothing was checked (wrong path?)", "(staging)", 0))
    ctx.registered = None
    # A file or folder NAME can itself hold a private value.  Findings must never echo it, so a path whose own name
    # trips the scanner is shown as "path#<n>" (n = its position in the string-sorted list of all paths under the
    # staging dir, see README: `find DIR -mindepth 1 | sed 's#^DIR/##' | LC_ALL=C sort | sed -n <n>p`).
    shown = {}

    def display(rel):
        """rel unchanged when the name is clean, else a masked 'path#n' form (never contains name text)."""
        if rel not in shown:
            hits = []
            saved, ctx.mask = ctx.mask, []
            scan_text(rel, ctx, lambda c, d, l: hits.append(c), is_path=True)
            ctx.mask = saved
            if hits:
                key = rel
                while key not in order and "/" in key:    # derived paths (e.g. "<dir>/.git") borrow their parent's index
                    key = key.rsplit("/", 1)[0]
                shown[rel] = "path#%d" % order.get(key, 0)
            else:
                shown[rel] = rel
        return shown[rel]

    if stats is not None:
        stats["identity_blanked"] = {display(r): n for r, n in sorted(identity_by_file.items())}
    findings = [(c, d, display(r), l) for c, d, r, l in findings]
    # de-duplicate (same category/detail/file/line)
    seen, uniq = set(), []
    for f in findings:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    uniq.sort(key=lambda f: (f[2], f[3], f[0], f[1]))
    return files, uniq


def main(argv=None):
    """Command-line entry point.

    Args:
        argv: optional argument list (defaults to sys.argv[1:]).
    Returns:
        0 clean, 1 findings present, 2 setup error (bad values file or allowlist, missing staging dir).
    Prints one "path:line: CATEGORY[detail]" line per finding, then a summary and PASS/FAIL.
    """
    ap = argparse.ArgumentParser(description="Release gate: fail if staging may leak")
    ap.add_argument("--staging")
    ap.add_argument("--values", default=str(sr.DEFAULT_VALUES))
    ap.add_argument("--release-root", default=str(sr.DEFAULT_RELEASE_ROOT))
    ap.add_argument("--allow-email", action="append", default=[])
    ap.add_argument("--allowlist", help="allowlist JSON (fixture strings, approved binaries); see allowlist.py")
    ap.add_argument("--neutral-author", action="append", default=[], help="metadata value that identifies nobody")
    a = ap.parse_args(argv)
    staging = a.staging or str(Path(a.release_root) / "staging")
    try:
        pv = sr.load_values(a.values, a.release_root)
        allow = al.load_allowlist(a.allowlist, pv.flat.values())
        stats = {}
        files, findings = gate(staging, pv, a.release_root, a.allow_email, allow, a.neutral_author, values_path=a.values,
                               stats=stats)
    except (sr.ScrubError, al.AllowlistError) as e:
        print("release_gate: FATAL: %s" % e, file=sys.stderr)
        return 2
    counts = {}
    for cat, _d, _f, _l in findings:
        counts[cat] = counts.get(cat, 0) + 1
    for cat, detail, rel, line in findings:
        print("%s:%d: %s%s" % (rel, line, cat, "[%s]" % detail if detail else ""))
    print("release_gate: scanned %d files; findings=%d %s" % (
        files, len(findings), " ".join("%s=%d" % (k, counts[k]) for k in sorted(counts))))
    if pv.identity:
        # gate_public_identity report: declared entries only in masked form, then counts per file (paths and numbers only).
        blanked = stats.get("identity_blanked", {})
        print("release_gate: public identity: %d declared (%s); %d occurrence(s) blanked in %d file(s)" % (
            len(pv.identity), ", ".join(sr.mask_identity(x) for x in pv.identity), sum(blanked.values()), len(blanked)))
        for rel in sorted(blanked):
            print("release_gate:   public identity blanked: %s x%d" % (rel, blanked[rel]))
    print("release_gate: %s" % ("FAIL" if findings else "PASS"))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
