#!/usr/bin/env python3
r"""scrub_release: copy an ALLOWLISTED set of text files into staging/<component>/ with every private value
replaced by a {{PLACEHOLDER}} token.  Stdlib only (python 3.9).  Fails closed.

Inputs
  manifest   JSON {"component": "name", "files": ["rel/path", ...], "exclude_exceptions": ["rel/path", ...]}
             Paths are relative to the source root (default: env RELEASE_SOURCE_ROOT, else the current directory).  Only listed files are ever
             read; no globs, no directories.  Unknown manifest keys are an error.
  values     PRIVATE JSON (default ~/.config/twu_release/values.private.json), chmod 600, outside the release
             tree, owned by the caller.  {"salt": "...", "values": {"KEY": "value" | ["v1","v2"]},
             "allow_emails": [...], "gate_ignore_words": [...], "gate_allow_strings": [...],
             "gate_public_phrases": [...]}.  Never copied, never printed.

Outputs (all under <release-root>/staging/)
  <component>/<files, scrubbed names>   text with {{KEY}} / {{KEY.lower}} / {{HOST_1}} ... tokens
  <component>/ANNOTATIONS.md / ANNOTATIONS.json (no hashes) / REFUSED.md
  ~/.config/twu_release/annotations.private/<component>.json (chmod 600): the same records WITH salted hashes
  PLACEHOLDERS_INDEX.md                 across all components
  ~/.config/twu_release/restore.private.json (chmod 600): token -> original for pattern-class tokens
Exit: 0 ok, 3 ok but some files refused, 2 fatal (nothing written).

Why this exists
  A project that was developed privately contains personal data (names, home paths, hosts, addresses, keys). To
  publish it, a reviewed list of files is copied to a staging folder with each private value replaced by a stable
  placeholder token, so the published text is safe and a user can later fill in their own values (hotswap.py).
  release_gate.py then re-scans the result independently, and reannotate.py rebuilds the placeholder pages after
  hand edits.

Design notes / threat model
  * Allowlist, not blocklist: only files named in the manifest are read; everything else is invisible.
  * Fail closed: anything ambiguous refuses the single file (exit 3) and anything structurally wrong aborts the
    whole run before a single byte is written (exit 2). Binary, archive, key, database and image files, symlinks,
    oversized files, backup/sync-conflict copies and files matching the exclude list are never copied. The one
    exception is a binary whose exact SHA-256 was explicitly approved in the allowlist module; it is copied
    verbatim (only its file name is scrubbed). Private key blocks, sensitive names and backups are never approvable.
  * Two detectors run on every file name and file body: exact private values from the private values file
    (case-insensitive, with lower/upper/title variants kept as {{KEY.lower}} etc.), and generic pattern classes
    (home paths, emails, private IPs, MAC addresses, hostnames, keys, tokens, phone numbers, business IDs) that are
    numbered per component ({{HOST_1}}, {{EMAIL_2}}...). Matches are resolved to non-overlapping spans, longest
    first; a partial overlap or a mixed-case variant is ambiguous and refuses the file.
  * Optional namespace renaming: the values file may map personal-name prefixes to neutral ones
    ("rename_prefixes"); this is a one-way rewrite of names and text done before token planning.
  * Allowlisted fixture strings (intentional fake secrets in test files) are left exactly as written.
  * Private data stays outside the release tree: the values file, the restore map and the salted-hash annotation
    copies must be chmod 600, owned by the caller and live outside the release root. The published ANNOTATIONS.json
    deliberately omits hashes.
  * Text that already looks like a placeholder is refused, so a later hotswap can never mis-resolve a token.
  * Output is deterministic: the same inputs give the same tokens and ordering.
  * Reports and errors never echo matched private text.

Usage
  python3 tools/scrub_release.py --manifest manifests/demo.json \
      [--values PRIVATE.json] [--release-root DIR] [--source-root DIR] [--restore-map PATH]

  Example manifest:  {"component": "demo", "files": ["README.md", "src/app.py"], "exclude_exceptions": []}
  Example output line:  component=demo copied=2 refused=0 replacements=5
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # sibling modules, however we were started
import allowlist as al  # noqa: E402  (fixture strings, hand-approved binaries)
import normalize  # noqa: E402  (text folding; used so a disguised private-key header is still refused)
try:
    import fcntl  # POSIX only (the kit supports macOS and Linux); used to lock the restore map during a merge
except ImportError:  # pragma: no cover
    fcntl = None

# Folder that holds tools/ and staging/ (this file lives in <root>/tools/).
DEFAULT_RELEASE_ROOT = Path(__file__).resolve().parent.parent  # the folder that holds tools/ and staging/
DEFAULT_SOURCE_ROOT = Path(os.environ.get("RELEASE_SOURCE_ROOT") or os.getcwd())  # folder the manifest paths are relative to
# Private files live in a per-user config folder, deliberately outside the release tree.
# Default location of the private values file (salt + private values); never published, must be chmod 600.
DEFAULT_VALUES = Path.home() / ".config" / "twu_release" / "values.private.json"
# Default location of the private restore map (token -> original for pattern-class tokens); chmod 600.
DEFAULT_RESTORE = Path.home() / ".config" / "twu_release" / "restore.private.json"

# A placeholder token as written into staged files. Matches "{{OWNER_NAME}}" and the case variants
# "{{OWNER_NAME.lower}}", "{{OWNER_NAME.upper}}", "{{OWNER_NAME.title}}"; group 1 = key, group 2 = variant or None.
# Used both to find tokens and to refuse inputs that already contain token-like text.
TOKEN_RE = re.compile(r"\{\{([A-Z][A-Z0-9_]*)(?:\.(lower|upper|title))?\}\}")
# A legal placeholder key: upper-case letter first, then upper-case letters, digits or "_". Example: "HOST_1".
KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9_.-]+$")   # characters allowed in a rename_prefixes key/value
# A legal component (output folder) name: starts alphanumeric, then letters, digits, "_", "." or "-".
# Example: "demo-tools_2". Keeps names free of slashes and leading dots so they cannot escape staging/.
COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
# Private values shorter than this are rejected as ambiguous (a 2-letter value would match almost anywhere).
MIN_VALUE_LEN = 3
# Files bigger than 5 MiB are refused (source text is small; a huge file is more likely data or a dump).
MAX_FILE_BYTES = 5 * 1024 * 1024
# Generated per-component pages; no staged file may use these names (reserved so output cannot clash).
META_FILES = ("ANNOTATIONS.md", "ANNOTATIONS.json", "REFUSED.md")

# File extensions that are never text-scrubbed: documents, archives, disk images, ML weights, databases, images,
# media, compiled code, fonts and key/certificate stores. Such files cannot be scrubbed reliably, so they are refused.
REFUSE_EXT = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".tar",
    ".ipa", ".dmg", ".gguf", ".safetensors", ".bin", ".npy", ".npz", ".pkl", ".pickle", ".pt", ".onnx",
    ".sqlite", ".sqlite3", ".db", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".ico", ".tiff", ".bmp",
    ".mp4", ".mov", ".mp3", ".wav", ".m4a", ".pyc", ".pyo", ".so", ".dylib", ".o", ".a", ".exe", ".whl",
    ".jar", ".class", ".ttf", ".otf", ".woff", ".woff2", ".pem", ".key", ".p12", ".pfx", ".keystore", ".kdbx",
}
# Exact file names that usually hold credentials (SSH private keys, netrc, pgpass, .env); always refused.
# ".env.example"-style templates are allowed separately in refused_type().
REFUSE_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".netrc", ".pgpass", ".env"}
# Leading bytes of common binary formats (PDF, ZIP/Office, PNG, SQLite, ELF, gzip, JPEG, Mach-O, GIF, bzip2, xz).
# A file starting with any of them is refused even if its name looks like text.
MAGIC = (b"%PDF", b"PK\x03\x04", b"\x89PNG", b"SQLite format 3", b"\x7fELF", b"\x1f\x8b", b"\xff\xd8\xff",
         b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"GIF8", b"BZh", b"\xfd7zXZ")
# Names of sync-conflict files and editor/working backups, which are dropped: they are stale copies that may hold
# older, unscrubbed content. Matches "notes.sync-conflict-2024.txt", "app.py.bak", "a.orig", "file.before.txt",
# and editor backups ending in "~" such as "config.yml~".
BACKUP_NAME_RE = re.compile(r"sync-conflict|\.(?:before|after|candidate|prior|orig|bak)(?:\.|$)|~$")
# Start of a PEM/PGP private key block: five dashes, BEGIN, an optional algorithm word (RSA, EC, DSA, OPENSSH, PGP),
# PRIVATE KEY, an optional BLOCK, five dashes. Public key headers do not match.
# B3: also matches lower/mixed case ("-----begin private key-----"), runs of spaces or tabs between the words and
# spaces inside the dashes.  (Zero-width, fullwidth and look-alike characters inside the header are handled by the
# callers, which also run this regex on the normalize.fold() form of the text.)
PRIVATE_KEY_RE = re.compile(r"-{3,}[ \t]*BEGIN[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?[ \t]*-{3,}", re.I)


def has_private_key_block(text):
    """True if TEXT holds a private-key header, plain or hidden by invisible/fullwidth/escaped characters."""
    return bool(PRIVATE_KEY_RE.search(text) or PRIVATE_KEY_RE.search(normalize.fold(text, join_literals=False)))


class ScrubError(Exception):
    """Fatal configuration or safety error: the whole run aborts and nothing is written.

    Messages must not contain private values (they are printed to stderr).
    """


class Ambiguous(Exception):
    """A single file (or file name) cannot be scrubbed unambiguously: refuse that one file, continue with others."""


# ----------------------------------------------------------------------------------------------- hashing
def ann_hash(salt: str, text: str) -> str:
    """Salted hash of an original string, recorded in the PRIVATE annotations so hotswap can verify a restored value.

    sha256(salt NUL text), first 32 hex chars. The NUL separator keeps this domain apart from gate_hash.
    """
    return hashlib.sha256((salt + "\x00" + text).encode("utf-8", "surrogatepass")).hexdigest()[:32]


def gate_hash(salt: str, text_lower: str) -> str:
    """Salted hash used by release_gate to look for private strings without keeping them in plain text.

    Takes an already lower-cased string. Uses a different separator byte (0x01) than ann_hash so the two hash
    families can never be confused with each other.
    """
    # "surrogatepass": text decoded from a JSON escape such as \ud83d can hold a LONE surrogate; plain "utf-8" would raise
    # UnicodeEncodeError and crash the gate (F7).  For all ordinary text the bytes are identical.
    return hashlib.sha256((salt + "\x01" + text_lower).encode("utf-8", "surrogatepass")).hexdigest()[:32]


# ----------------------------------------------------------------------------------------------- private file
def check_private_file(path, release_root, what="private file"):
    """Validate a file that holds private data before it is read.

    Requirements: exists; outside release_root (checked on both the literal and the symlink-resolved path); a regular
    file; no group/other permission bits (mode 600 or stricter); owned by the current user.

    Args:
        path: file path (may start with "~").
        release_root: the release tree the file must not live in.
        what: noun used in error messages.
    Returns:
        The fully resolved Path.
    Raises:
        ScrubError if any requirement fails (the run must stop).
    """
    p = Path(path).expanduser()
    root = Path(release_root).resolve()
    if not p.exists():
        raise ScrubError("%s not found: %s" % (what, p))
    # Check both spellings so neither a symlink into the tree nor a relative path can hide the location.
    for cand in (Path(os.path.abspath(str(p))), p.resolve()):
        if cand == root or root in cand.parents:
            raise ScrubError("%s must live OUTSIDE the release tree" % what)
    real = p.resolve()
    st = os.stat(str(real))
    if not stat.S_ISREG(st.st_mode):
        raise ScrubError("%s is not a regular file" % what)
    if st.st_mode & 0o077:   # any group/other permission bit set => other users could read the secrets
        raise ScrubError("%s must be chmod 600 (mode is %s); refusing to run" % (what, oct(st.st_mode & 0o777)))
    if st.st_uid != os.getuid():
        raise ScrubError("%s is not owned by the current user; refusing to run" % what)
    return real


def flatten_values(values):
    """Turn {"KEY": "v" | ["v1", "v2"]} into a flat {"KEY": "v", "KEY_1": "v1", "KEY_2": "v2"} mapping.

    A list value yields numbered keys starting at 1. Raises ScrubError for any other value type.
    """
    flat = {}
    for key, v in values.items():
        if isinstance(v, str):
            flat[key] = v
        elif isinstance(v, list):
            for i, s in enumerate(v):
                flat["%s_%d" % (key, i + 1)] = s
        else:
            raise ScrubError("value for %s must be a string or list of strings" % key)
    return flat


# ---- gate_public_phrases support -----------------------------------------------------------------------------------
MIN_PUBLIC_PHRASE_LEN = 6                      # shorter phrases are too easy to hide a fragment behind
PUBLIC_PHRASE_OVERLAP_KEYS = {"WORKSPACE_NAME"}  # the only private-value key a public phrase may overlap
_PHRASE_WORD_RE = re.compile(r"[A-Za-z0-9]+")
_PHRASE_STOP = {"local", "home", "users", "user", "this", "that", "with", "from", "file", "test", "name", "example",
                "host", "localhost", "documents", "library", "desktop", "root", "public", "private", "the", "and"}


def _base_key(key):
    """KEY_3 -> KEY (list values are flattened to KEY_1, KEY_2 ...); any other key is returned unchanged."""
    m = re.fullmatch(r"(.+)_\d+", key)
    return m.group(1) if m and m.group(1) in PUBLIC_PHRASE_OVERLAP_KEYS else key


def _distinctive_words(text, ignore):
    """Lower-case words of TEXT that identify something on their own: 4+ letters-with-digits chars or 7+ digits,
    excluding stop words and the values file's gate_ignore_words."""
    out = set()
    for w in _PHRASE_WORD_RE.findall(text):
        lw = w.lower()
        if lw in _PHRASE_STOP or lw in ignore:
            continue
        if (re.search(r"[a-z]", lw) and len(lw) >= 4) or len(lw) >= 7:
            out.add(lw)
    return out


def _phrases_overlap(phrase, value, ignore):
    """True if PHRASE and a private VALUE overlap (case-insensitive): one contains the other, or they share a
    distinctive word.  Used to refuse a public phrase that could hide a real leak."""
    p, v = phrase.casefold(), value.casefold()
    return p in v or v in p or bool(_distinctive_words(phrase, ignore) & _distinctive_words(value, ignore))


# ---- gate_public_identity support ----------------------------------------------------------------------------------
# A SEPARATE, narrow feature (not a loosening of gate_public_phrases): the owner's intentionally PUBLISHED contact
# handle/email, e.g. a repository URL "https://github.com/<handle>/<repo>" or a contact address.  Each entry must have
# exactly one of three shapes; free text and spaces are refused.  It is for public contact data ONLY, never for secrets.
IDENTITY_URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.~/-]*)?$")
IDENTITY_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
IDENTITY_BARE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{5,63}$")
MAX_IDENTITY_ENTRIES = 20
# Value keys whose values an identity entry MAY contain: the owner's name parts, handle, email and GitHub names.  Any
# other key (hosts, IPs, workspace name, phone, address ...) must not appear inside an entry.
IDENTITY_OWNER_PREFIXES = ("OWNER_", "GITHUB_", "GIT_AUTHOR_")


def _is_handle_key(key):
    """Keys that hold a user/handle name (OWNER_HANDLE, OWNER_HANDLE_1, GITHUB_ORG ...): the only values a BARE token
    entry may equal.  A first name (OWNER_FIRST) is not a handle, so a lone first name can never be declared public."""
    return "HANDLE" in key or key.startswith("GITHUB_")


def mask_identity(entry):
    """Printable masked form of an identity entry: its kind, length and first character only ("url:h***(34)").
    The tools print declared entries only in this form."""
    kind = "email" if "@" in entry else ("url" if "://" in entry else "handle")
    return "%s:%s***(%d)" % (kind, entry[:1], len(entry))


class PrivateValues:
    """Validated, pre-compiled view of the private values file.

    Attributes: salt; flat (key -> value); exact (list of (key, value, compiled lookahead regex)); allow_emails and
    ignore_words (lower-case sets); prefix_map / prefix_re (rename_prefixes); allow_strings / allow_re (words the gate
    may ignore); public_phrases / public_re (whole public phrases the gate blanks, see gate_public_phrases). Construction validates everything and raises ScrubError rather than accept an ambiguous config.
    """

    def __init__(self, data):
        """Validate `data` (the parsed JSON object of the values file) and precompute the matchers.

        Rejects: a non-object file, a salt shorter than 8 characters, empty/short values, values that look like a
        placeholder token, two keys holding the same value (case-insensitive), malformed optional lists, and
        rename_prefixes whose replacement would itself contain a private value.
        """
        if not isinstance(data, dict):
            raise ScrubError("values file must be a JSON object")
        salt = data.get("salt")
        if not isinstance(salt, str) or len(salt) < 8:
            raise ScrubError("values file needs a \"salt\" string of at least 8 characters")
        if "EXAMPLE-ONLY-DO-NOT-USE" in salt:
            # The salt shipped in examples/example_values.json is PUBLIC.  Hashes made with it can be guessed offline
            # for low-entropy values, so refuse it: the quick start shows how to generate your own.
            raise ScrubError("the salt is the public example salt; generate your own (see the README quick start)")
        self.salt = salt
        vals = data.get("values")
        if not isinstance(vals, dict) or not vals:
            raise ScrubError("values file needs a non-empty \"values\" object")
        for k in vals:
            if not KEY_RE.match(k):
                raise ScrubError("bad key name %r (A-Z, 0-9, _ only)" % k)
        self.flat = flatten_values(vals)
        seen = {}   # casefolded value -> key, to detect two keys holding the same value
        for k in sorted(self.flat):
            v = self.flat[k]
            if not isinstance(v, str) or len(v) < MIN_VALUE_LEN:
                raise ScrubError("value for %s is empty or shorter than %d characters (ambiguous)" % (k, MIN_VALUE_LEN))
            if TOKEN_RE.search(v):
                raise ScrubError("value for %s looks like a placeholder token" % k)
            n = v.casefold()   # case-insensitive comparison, matching how values are searched later
            if n in seen:
                raise ScrubError("keys %s and %s hold the same value (ambiguous)" % (seen[n], k))
            seen[n] = k
        allow = data.get("allow_emails", [])
        ign = data.get("gate_ignore_words", [])
        if not (isinstance(allow, list) and all(isinstance(x, str) for x in allow)):
            raise ScrubError("allow_emails must be a list of strings")
        if not (isinstance(ign, list) and all(isinstance(x, str) for x in ign)):
            raise ScrubError("gate_ignore_words must be a list of strings")
        # allow_emails: public contact addresses that may stay in the text; ignore_words: words the gate's word scan skips.
        self.allow_emails = set(x.lower() for x in allow)
        self.ignore_words = set(x.lower() for x in ign)
        # ---- rename_prefixes: {"alice_": "ab_", "proj-alice-": "ab-"} (old prefix -> neutral prefix) ----------
        # A personal-name namespace becomes a neutral one in file names, directory
        # names AND text (imports, unit names, docs), so references stay consistent.  The prefix is matched at a
        # word start (not after a letter/digit), longest first.  This is a deliberate one-way rewrite (no token),
        # unlike private VALUES which become reversible {{KEY}} tokens.
        rp = data.get("rename_prefixes", {})
        if not isinstance(rp, dict):
            raise ScrubError("rename_prefixes must be an object {\"old_prefix\": \"new_prefix\"}")
        self.prefix_map = {}
        for old, new in rp.items():
            if not isinstance(old, str) or not isinstance(new, str) or len(old) < MIN_VALUE_LEN or not PREFIX_RE.match(new):
                raise ScrubError("rename_prefixes entries need an old prefix of >= %d chars and a new prefix made of "
                                 "letters, digits, '_', '-', '.'" % MIN_VALUE_LEN)
            if not PREFIX_RE.match(old):
                raise ScrubError("rename_prefixes old prefix has characters outside letters, digits, '_', '-', '.'")
            # The replacement must not itself carry a private value, or the rewrite would re-introduce a leak.
            if any(v.casefold() in new.casefold() for v in self.flat.values()):
                raise ScrubError("a rename_prefixes replacement contains a private value")
            self.prefix_map[old.casefold()] = new
        self.prefix_re = None
        if self.prefix_map:
            alts = "|".join(re.escape(k) for k in sorted(self.prefix_map, key=lambda k: (-len(k), k)))
            # Word start = not preceded by a letter or digit ('_' '-' '/' '.' ' ' all count as boundaries).
            self.prefix_re = re.compile(r"(?<![A-Za-z0-9])(?:" + alts + ")", re.IGNORECASE)
        # gate_allow_strings: whole ordinary words (e.g. a public tool name) that CONTAIN a private value but are not it.
        # The gate blanks them out before looking for private values.  Whole-word, case-insensitive, letters/digits only, 6+ chars.
        aw = data.get("gate_allow_strings", [])
        if not (isinstance(aw, list) and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9]{6,}", x) for x in aw)):
            raise ScrubError("gate_allow_strings must be a list of letters/digits-only words, 6+ characters")
        self.allow_strings = sorted(set(x.lower() for x in aw), key=len, reverse=True)
        self.allow_re = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(x) for x in self.allow_strings) + r")(?![A-Za-z0-9])",
                                   re.IGNORECASE) if self.allow_strings else None
        # ---- gate_public_phrases ---------------------------------------------------------------------------------
        # PUBLIC phrases (e.g. a company name in a copyright line) that overlap ONLY the workspace/org-name key.
        # The gate blanks each phrase, as a WHOLE phrase, before scanning.  Rules (all enforced here, fail closed):
        #   * exact and case-sensitive (no .lower()): "Acme Works" is allowed, "acme works" is not blanked;
        #   * at least MIN_PUBLIC_PHRASE_LEN characters; spaces allowed;
        #   * word boundaries: the phrase can never match inside a longer letter/digit token (see gate_public_re);
        #   * it may overlap a private value ONLY for the key(s) in PUBLIC_PHRASE_OVERLAP_KEYS.  Overlap means: a
        #     value is inside the phrase, the phrase is inside a value, or they share a distinctive word (4+ letters,
        #     or 7+ digits; gate_ignore_words and common stop words do not count).  Overlap with any other key (owner
        #     name or name part, host, handle, IP, email...) refuses the whole file, because blanking such a phrase
        #     would hide a leak.  Error text never includes the phrase or the value.
        gp = data.get("gate_public_phrases", [])
        if not (isinstance(gp, list) and all(isinstance(x, str) and len(x) >= MIN_PUBLIC_PHRASE_LEN and x == x.strip()
                                             for x in gp)):
            raise ScrubError("gate_public_phrases must be a list of strings, %d+ characters, no leading/trailing space"
                             % MIN_PUBLIC_PHRASE_LEN)
        for ph in gp:
            for k, v in self.flat.items():
                if _base_key(k) in PUBLIC_PHRASE_OVERLAP_KEYS:
                    continue                      # the one key a public phrase may overlap
                if _phrases_overlap(ph, v, self.ignore_words):
                    raise ScrubError("a gate_public_phrases entry overlaps private value %s (only %s may be overlapped)"
                                     % (k, "/".join(sorted(PUBLIC_PHRASE_OVERLAP_KEYS))))
        self.public_phrases = sorted(set(gp), key=lambda x: (-len(x), x))     # longest first so a phrase containing another wins
        # Boundary guards: not preceded/followed by a letter or digit, so "Acme Works" never matches inside "Acme WorksX" or
        # "XAcme Works".  NOT re.IGNORECASE: phrases are case-sensitive.
        self.public_re = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(x) for x in self.public_phrases) + r")(?![A-Za-z0-9])") \
            if self.public_phrases else None
        # ---- gate_public_identity (see the block comment above IDENTITY_URL_RE) --------------------------------------
        gi = data.get("gate_public_identity", [])
        if not (isinstance(gi, list) and len(gi) <= MAX_IDENTITY_ENTRIES and all(isinstance(x, str) for x in gi)):
            raise ScrubError("gate_public_identity must be a list of at most %d strings" % MAX_IDENTITY_ENTRIES)
        for ent in gi:
            # Rule 1: exact shape.  No spaces, no free text.
            if not (IDENTITY_URL_RE.match(ent) or IDENTITY_EMAIL_RE.match(ent) or IDENTITY_BARE_RE.match(ent)):
                raise ScrubError("a gate_public_identity entry is not a URL path, an email address or a bare handle "
                                 "(no spaces or free text; masked: %s)" % mask_identity(ent))
            bare = not (IDENTITY_URL_RE.match(ent) or IDENTITY_EMAIL_RE.match(ent))
            for k, v in self.flat.items():
                if bare:
                    # Rule 2: a bare token must BE a handle value.  A lone first name (or any other private word) is refused.
                    continue
                # Rule 3: no private value of a non-owner key may appear in the entry (hostname, IP, workspace ...).
                if not k.startswith(IDENTITY_OWNER_PREFIXES) and _phrases_overlap(ent, v, self.ignore_words):
                    raise ScrubError("a gate_public_identity entry overlaps private value %s, which is not an owner "
                                     "name/handle (masked: %s)" % (k, mask_identity(ent)))
            if bare:
                if not any(_is_handle_key(k) and v.casefold() == ent.casefold() for k, v in self.flat.items()):
                    raise ScrubError("a bare gate_public_identity token must equal a handle value (OWNER_HANDLE, "
                                     "GITHUB_*); a name or word is refused (masked: %s)" % mask_identity(ent))
            else:
                for k, v in self.flat.items():
                    if not k.startswith(IDENTITY_OWNER_PREFIXES) and v.casefold() in ent.casefold():
                        raise ScrubError("a gate_public_identity entry contains private value %s (masked: %s)"
                                         % (k, mask_identity(ent)))
        self.identity = sorted(set(gi), key=lambda x: (-len(x), x))
        # Whole-token match: not preceded by a letter/digit/_ % + . -, not followed by a letter/digit/_ - (nor ".word");
        # an optional ".git" suffix belongs to the URL.  Case-SENSITIVE.  Compiled once; used only by release_gate.
        self.identity_re = re.compile(r"(?<![A-Za-z0-9_%+.-])(?:" + "|".join(re.escape(x) for x in self.identity) +
                                      r")(?:\.git)?(?!\.?[A-Za-z0-9_-])") if self.identity else None
        # Per value: a zero-width lookahead regex "(?=(value))" so overlapping occurrences are all found, case-insensitively.
        self.exact = [(k, self.flat[k], re.compile("(?=(" + re.escape(self.flat[k]) + "))", re.IGNORECASE))
                      for k in sorted(self.flat)]


def load_values(path, release_root):
    """Read the private values file (after check_private_file) and return a PrivateValues.

    Error messages carry only the exception type, never file content, to avoid echoing private data.
    """
    real = check_private_file(path, release_root, "values file")
    try:
        data = json.loads(real.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ScrubError("cannot parse values file: %s" % type(e).__name__)
    return PrivateValues(data)


# ----------------------------------------------------------------------------------------------- patterns
def _octets_ok(s):
    """True if every dotted number in s is a valid IPv4 octet (0-255); rejects look-alikes such as 10.999.1.1."""
    return all(0 <= int(x) <= 255 for x in re.findall(r"\d+", s))


# Email addresses that are safe by construction and need no scrubbing: reserved example domains, ".invalid" and
# "localhost" hosts, GitHub's noreply addresses, and "noreply@"/"no-reply@" mailboxes.
# Matches "bob@example.com", "x@mail.invalid", "123+bob@users.noreply.github.com", "noreply@whatever.org".
_SAFE_EMAIL = re.compile(r"(?i)@(?:example\.(?:com|org|net)|[\w.-]*\.invalid|users\.noreply\.github\.com|localhost)$|^no-?reply@")
# "Domains" that are really image file names (an "icon@2x.png" asset name looks like an email); not emails.
_IMG_TLD = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp"}


# F4: things that look like "name@domain" but are not addresses.
#   * "git@github.com:org/repo.git" (an SSH clone URL; the local part "git" is a convention shared by every host),
#   * "lodash@4.17.21", "pkg@1.2.3-beta.1", "actions/setup-python@v5.1.0" (package / action version pins).
# A real top-level domain is never all digits, and a version looks like [v]N(.N)+ with an optional pre-release.
_VERSION_DOMAIN = re.compile(r"(?i)^v?\d+(?:\.\d+)+(?:[-+][\w.-]*)?$")


def _email_ok(text, ctx):
    """Validator for EMAIL hits: True means "this is private, scrub it".

    ctx is the set of allowed (lower-case) addresses. Safe/reserved addresses, allowed addresses, image-file
    look-alikes, "git@host" clone URLs and package@version pins return False.
    """
    if _SAFE_EMAIL.search(text) or text.lower() in ctx:
        return False
    local, _, domain = text.rpartition("@")
    if local.lower() == "git":                    # git@github.com:org/repo.git, ssh://git@host/path
        return False
    if _VERSION_DOMAIN.match(domain) or domain.rsplit(".", 1)[-1].isdigit():   # lodash@4.17.21, setup-python@v5.1.0
        return False
    return text.rsplit(".", 1)[-1].lower() not in _IMG_TLD


def _phone_ok(text, ctx):
    """Validator for PHONE hits: False for the reserved fictional "555-01xx" range, True otherwise."""
    return not re.search(r"555[ .-]555[ .-]01\d\d|555[ .-]01\d\d", text)


def _uei_ok(text, ctx):
    """Validator for UEI hits: a real identifier mixes letters and digits; all-letter or all-digit runs are not."""
    return bool(re.search(r"\d", text) and re.search(r"[A-Z]", text))


def _ip_ok(text, ctx):
    """Validator for IP hits: True only if all octets are in range."""
    return _octets_ok(text)


def _zero_padded_private_ip(text, ctx):
    """Validator for dotted quads written with leading zeros ("010.001.002.003", "192.168.001.005").

    True only if (a) the text really has a zero-padded octet (the plain form is matched by the LAN_IP/VPN_IP
    patterns), (b) every octet is 0-255 and (c) the NORMALISED address is private (10/8, 172.16/12, 192.168/16)
    or CGNAT (100.64/10).  A version number such as 1.04.0.2 is therefore left alone.
    """
    parts = text.split(".")
    if len(parts) != 4 or not any(len(x) > 1 and x.startswith("0") for x in parts):
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        if any(not 0 <= int(x) <= 255 for x in parts):
            return False
    except ValueError:
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127)


def _cisco_mac_ok(text, ctx):
    """Validator for dotted MACs ("aabb.ccdd.eeff"): needs at least one hex LETTER, so a dotted number such as
    1234.5678.9012 is not a MAC."""
    return bool(re.search(r"[a-fA-F]", text))


# A secret-like assigned value is only treated as a password when it looks like one: it holds a digit or one of these
# special characters, and is not a template/placeholder ("{{x}}", "${VAR}", "<password>", "%s").  This keeps i18n
# labels ("password": "Password") and doc placeholders ("your-password-here") out.  Short all-letter passwords and
# letters-only pass-phrases are therefore NOT found (README limit).
_PW_SPECIAL = re.compile(r"[0-9!@#$%^&*+=~|\\;]")
_PW_TEMPLATE = re.compile(r"\{\{|\$\{|%\(|%s|[<>{}]")


def _password_value_ok(text, ctx):
    """Validator for `password = "..."` hits (the group is the VALUE): True when it looks like a real password."""
    return bool(_PW_SPECIAL.search(text)) and not _PW_TEMPLATE.search(text) and bool(re.search(r"[A-Za-z0-9]", text))


# Generic user names that do not identify anyone; "/Users/<one of these>" is left alone.
# Matches (case-insensitively, as a whole path component) "user", "you", "name", "username", "example", "runner", ...
_SAFE_HOME = r"(?i:user|you|name|username|yourname|example|runner|shared|me|someone|foo|bar|test|guest)"
# Generic detectors for private data that is not in the values file. Each entry:
#   (class, token prefix, compiled regex, regex group to replace (0 = whole match), validator or None).
# A validator receives (matched text, allowed emails) and returns True to keep the hit. Tokens become <prefix>_<n>.
PATTERNS = [
    # HOME_PATH: a personal home directory such as "/Users/alice" or "/home/bob/project" (only the "/Users/alice" part
    # is matched). Generic names (see _SAFE_HOME) and paths glued to a preceding word/slash are not matched.
    # B3: "/Users/x" is also matched in the spellings /USERS/x and /HOME/x (never a URL route), and after the prefixes
    # that put a home path in the MIDDLE of a longer string: file:///Users/x, /System/Volumes/Data/Users/x,
    # /Volumes/<disk>/Users/x, /mnt/<drive>/Users/x (WSL), /usr/home/x, /host_mnt/... (any case of Users/home there,
    # because those file systems are case-insensitive).  Only the "/Users/x" part (group 1) is replaced.
    # NOT matched (README limits): a bare lower-case "/users/x" or "/root/", "~user", C:\\Users\\x, other glue
    # (a "/users/42" REST route must stay untouched).
    ("HOME_PATH", "HOME_DIR",
     re.compile(r"(?<![\w/])(/(?:Users|USERS|home|HOME)/(?!" + _SAFE_HOME + r"(?![A-Za-z0-9_.-]))[A-Za-z0-9_][A-Za-z0-9_.-]*)"), 1, None),
    ("HOME_PATH", "HOME_DIR",
     re.compile(r"(?i:file://|/System/Volumes/Data|/Volumes/[^/\s]{1,64}|/mnt/[a-z]|/usr|/host_mnt/[^/\s]{1,64})"
                r"(/(?i:users|home)/(?!" + _SAFE_HOME + r"(?![A-Za-z0-9_.-]))[A-Za-z0-9_][A-Za-z0-9_.-]*)"), 1, None),
    # EMAIL: "alice.smith+tag@mail.example.co.uk". Validator drops safe/allowed addresses.
    ("EMAIL", "EMAIL",
     re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), 0, _email_ok),
    # LAN_IP: RFC1918 private IPv4: "10.0.0.5", "192.168.1.20" (also 192.168.1 prefix), "172.16.0.1" to "172.31.x.x".
    ("LAN_IP", "LAN_IP",
     re.compile(r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}(?:\.\d{1,3})?|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)"), 0, _ip_ok),
    # LAN_IP written with leading zeros ("010.001.002.003"): inet_aton reads that as OCTAL, but a human reads 10.1.2.3.
    ("LAN_IP", "LAN_IP",
     re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])"), 0, _zero_padded_private_ip),
    # VPN_IP: carrier-grade NAT range 100.64.0.0/10 used by mesh VPNs, e.g. "100.101.2.3".
    ("VPN_IP", "VPN_IP",
     re.compile(r"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?!\d)"), 0, _ip_ok),
    # MAC: hardware address with ":" or "-" separators, six hex byte pairs joined by ":" or "-", in lower or upper case.
    ("MAC", "MAC",
     re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])"), 0, None),
    # MAC (more spellings, B3): Cisco dotted "aabb.ccdd.eeff", and a bare 12-hex address ONLY when labelled
    # ("mac: aabbccddeeff", "hwaddr=..."), because a bare 12-hex run is also an ordinary short commit hash.
    ("MAC", "MAC", re.compile(r"(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])"), 0, _cisco_mac_ok),
    ("MAC", "MAC", re.compile(r"(?i:\b(?:mac|hwaddr|ether|lladdr)\b)[\s:=#\"']{0,6}([0-9a-fA-F]{12})(?![0-9a-zA-Z])"), 1, None),
    # HOSTNAME: names on private-only domains, a name followed by ".lan", ".home.arpa" or the mDNS suffix.
    ("HOSTNAME", "HOST",
     re.compile(r"(?<![\w.-])(?:[A-Za-z0-9][\w-]*\.)*[A-Za-z0-9][\w-]*\.(?i:local|lan|home\.arpa)(?!\w|\.\w)"), 0, None),
    # WG_KEY: a 32-byte key in base64: 43 base64 characters plus "=", e.g. "<43 chars>=" (WireGuard style).
    ("WG_KEY", "WG_KEY",
     re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])"), 0, None),
    # SSH_KEY: a public key line such as "ssh-ed25519 AAAAC3Nza..." or "ecdsa-sha2-nistp256 AAAA...".
    ("SSH_KEY", "SSH_KEY",
     re.compile(r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com) AAAA[A-Za-z0-9+/=]{20,}"), 0, None),
    # SSH_FPR: key fingerprints, either "SHA256:<43 base64 chars>" or colon-separated MD5 "aa:bb:...:ff" (16 bytes).
    ("SSH_FPR", "SSH_FPR",
     re.compile(r"SHA256:[A-Za-z0-9+/]{43}|(?<![\w:])(?:[0-9a-f]{2}:){15}[0-9a-f]{2}(?![\w:])"), 0, None),
    # SYNCTHING_ID: file-sync device ID, eight dash-joined groups of seven upper-case letters/digits ("ABCDEFG-" x8 style).
    ("SYNCTHING_ID", "SYNCTHING_DEVICE",
     re.compile(r"(?<![A-Z0-9-])[A-Z0-9]{7}(?:-[A-Z0-9]{7}){7}(?![A-Z0-9-])"), 0, None),
    # API_TOKEN (known shapes): "sk-..." keys, GitHub "ghp_/gho_/ghu_/ghs_/ghr_" and "github_pat_" tokens, Slack
    # "xoxb-" tokens, AWS "AKIA" access key IDs, Google "AIza" keys, Hugging Face "hf_" tokens and JWTs ("eyJ...eyJ...sig").
    ("API_TOKEN", "API_TOKEN",
     re.compile(r"(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|"
                r"xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{30,}|"
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), 0, None),
    # API_TOKEN (assignments): a long value assigned to a secret-like name, e.g. 'api_key = "abc...20+ chars"' or
    # "token: xxxxxxxxxxxxxxxxxxxx". Only the value (group 1) is replaced; 20+ chars avoids ordinary short words.
    ("API_TOKEN", "API_TOKEN",
     re.compile(r"(?i:api[_-]?key|secret|token|passw(?:or)?d)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_+/=-]{20,})"), 1, None),
    # API_TOKEN (more vendor shapes, B3): Stripe "sk_live_/rk_live_/pk_live_", npm "npm_" + 36, GitLab "glpat-", PyPI
    # "pypi-", SendGrid "SG.<id>.<secret>", Slack incoming-webhook URLs and "Bearer <20+ chars>" authorization values.
    # Lengths are chosen so ordinary identifiers (npm_config_x, a variable called sk_live_mode) are not matched.
    ("API_TOKEN", "API_TOKEN",
     re.compile(r"(?<![A-Za-z0-9_-])(?:[sr]k_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}|npm_[A-Za-z0-9]{36}|"
                r"glpat-[A-Za-z0-9_-]{20,}|pypi-[A-Za-z0-9_-]{50,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|"
                r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})"), 0, None),
    ("API_TOKEN", "API_TOKEN",
     re.compile(r"(?i:\bbearer)[ \t]+([A-Za-z0-9._~+/-]{20,}=*)"), 1, None),
    # API_TOKEN (quoted password, B3): password = "hunter2", pwd: 'S3cret!'.  The quoted value may be ANY length but must
    # look like a password (see _password_value_ok).  The unquoted 20+ char form is the pattern below.
    ("API_TOKEN", "API_TOKEN",
     re.compile(r"(?i:(?<![A-Za-z0-9])(?:passw(?:or)?d|pwd|passwd)(?![A-Za-z0-9_]))[\"']?\s*[:=]\s*([\"'])((?:(?!\1)[^\n]){1,200})\1"), 2, _password_value_ok),
    # PHONE (US-style, separated): "(555) 123-4567", "555-123-4567", "+1 555.123.4567". The validator skips the
    # fictional 555-01xx range used in examples.
    ("PHONE", "PHONE",
     re.compile(r"(?<![\w.:-])(?:\+?1[ .\-\u2013\u2014]?)?\(?\b\d{3}\)?[ .\-\u2013\u2014]\d{3}[ .\-\u2013\u2014]\d{4}(?![\w-])"), 0, _phone_ok),
    # "(555)123-4567": no separator after the closing parenthesis.
    ("PHONE", "PHONE", re.compile(r"(?<![\w.:-])\(\d{3}\)\d{3}[ .\-\u2013\u2014]?\d{4}(?![\w-])"), 0, _phone_ok),
    # International / unseparated phone shapes: E.164 (+ then 10-14 digits, e.g. "+441234567890") and a labelled
    # run of 10 digits (e.g. "tel: 5551234567"; only the digits are replaced for the labelled form).
    ("PHONE", "PHONE", re.compile(r"(?<![\w.:+-])\+\d{10,14}(?![\w-])"), 0, None),
    ("PHONE", "PHONE",
     re.compile(r"(?i:\b(?:tel|phone|cell|mobile|fax)\b)[\s:=#\"']{0,6}(\d{10})(?!\d)"), 1, None),
    # EIN (dashed): US employer ID "12-3456789".
    ("EIN", "EIN", re.compile(r"(?<![\w.-])\d{2}-\d{7}(?![\w-])"), 0, None),
    # Labelled EIN written without the dash, e.g. "EIN: 123456789" (a bare 9-digit number is far too common to match
    # unlabelled). Only the digits (group 1) are replaced.
    ("EIN", "EIN", re.compile(r"(?i:\bEIN\b)[\s:=#\"']{0,6}(\d{9})(?!\d)"), 1, None),
    # DUNS: nine digits, labelled, optionally written 2-3-4 with dashes. Matches "DUNS: 123456789",
    # "D-U-N-S number 12-345-6789". Only the digits (group 1) are replaced.
    ("DUNS", "DUNS",
     re.compile(r"(?i:\bD-?U-?N-?S\b)(?:\s*(?:number|no\.?|#))?[\s:=#\"']{0,6}(\d{9}|\d{2}-\d{3}-\d{4})(?![\w-])"), 1, None),
    # Tailscale tailnet names: <host>.<tailnet>.ts.net and the legacy <host>.<tailnet>.beta.tailscale.net,
    # e.g. "laptop.tail1234.ts.net".
    ("TAILNET_HOST", "TAILNET_HOST",
     re.compile(r"(?<![\w.-])(?:[A-Za-z0-9][\w-]*\.)+(?i:ts\.net|beta\.tailscale\.net)(?!\w)"), 0, None),
    # UEI: US federal entity ID, labelled, 12 upper-case letters/digits, e.g. "UEI: ABCDEF123456". The validator
    # requires at least one digit and one letter so ordinary words after "UEI" are not hit.
    ("UEI", "UEI", re.compile(r"(?i:\bUEI\b)[\s:=#\"']{0,6}([A-Z0-9]{12})(?![A-Za-z0-9])"), 1, _uei_ok),
]
# Pattern class -> token name prefix (e.g. "HOSTNAME" -> "HOST"), derived from PATTERNS above.
CLASS_PREFIX = {}
for _c in PATTERNS:
    CLASS_PREFIX[_c[0]] = _c[1]

# Per pattern class: (what the token stands for, what a user should put there). Used in the annotation pages.
CLASS_MEANING = {
    "HOME_PATH": ("a home-directory path of the machine's user", "your own home directory"),
    "EMAIL": ("an email address that is not an allowlisted public contact", "your own email address"),
    "LAN_IP": ("a private (RFC1918) LAN IPv4 address", "the LAN address of your own machine"),
    "VPN_IP": ("a VPN / CGNAT range IPv4 address", "the VPN address of your own machine"),
    "MAC": ("a network hardware (MAC) address", "the hardware address of your own device"),
    "HOSTNAME": ("a machine hostname on a private domain", "the hostname of your own machine"),
    "WG_KEY": ("a WireGuard-style 32-byte base64 key", "your own WireGuard key (never commit it)"),
    "SSH_KEY": ("an SSH public key line", "your own SSH public key"),
    "SSH_FPR": ("an SSH key fingerprint", "the fingerprint of your own key"),
    "SYNCTHING_ID": ("a Syncthing device ID", "your own Syncthing device ID"),
    "API_TOKEN": ("an API token or secret", "your own token, normally via an environment variable"),
    "PHONE": ("a phone number", "your own phone number"),
    "DUNS": ("a D-U-N-S business identifier", "your own DUNS number, if the feature needs one"),
    "TAILNET_HOST": ("a Tailscale tailnet machine name (*.ts.net)", "the tailnet name of your own machine"),
    "EIN": ("a US employer identification number", "your own EIN, if the feature needs one"),
    "UEI": ("a US federal unique entity identifier", "your own UEI, if the feature needs one"),
}
# Plain-language meaning for well-known value keys (and key prefixes such as HOST for HOST_1). Used in annotation pages;
# unknown keys get a generic description.
KEY_MEANING = {
    "OWNER_NAME": "the owner's full name", "OWNER_HANDLE": "the owner's unix/github user name",
    "HOME_DIR": "home directory", "OWNER_EMAIL": "the owner's email",
    "OWNER_PHONE": "the owner's phone", "OWNER_ADDRESS": "the owner's postal address",
    "GIT_AUTHOR_NAME": "git author name", "GIT_AUTHOR_EMAIL": "git author email", "GITHUB_ORG": "GitHub org or user",
    "ORG_NAME": "the organisation name", "HOST": "a machine nickname or address",
}


def pattern_spans(text, allow_emails=frozenset()):
    """Find every pattern-class hit in text.

    Args:
        text: string to scan.
        allow_emails: set of lower-case email addresses that must be left alone.
    Returns:
        list of (start, end, class) before overlap resolution; overlapping or duplicate spans are possible.
    """
    out = []
    for cls, _prefix, rx, grp, valid in PATTERNS:
        for m in rx.finditer(text):
            s, e = m.span(grp)   # the group lets a pattern replace just the value after a label
            if s < 0:
                continue
            if valid is not None and not valid(text[s:e], allow_emails):
                continue
            out.append((s, e, cls))
    return out


# ----------------------------------------------------------------------------------------------- spans
class Span:
    """One planned replacement: a half-open character range [start, end) in the original text.

    kind is "exact" (a private value: key + variant set) or "pattern" (a generic class: cls set).
    variant is "", "lower", "upper" or "title" for exact matches.
    """
    __slots__ = ("start", "end", "kind", "key", "cls", "variant")

    def __init__(self, start, end, kind, key=None, cls=None, variant=""):
        """Record one match: START/END character offsets, KIND ("exact" or "pattern"), the value KEY or pattern CLS, and VARIANT."""
        self.start, self.end, self.kind, self.key, self.cls, self.variant = start, end, kind, key, cls, variant


def _variant_of(matched, value):
    """Classify how matched text relates to the stored value.

    Returns "" (identical), "lower", "upper", "title" for those exact case forms, or None for any other mix of case
    (which cannot be restored faithfully and therefore makes the file ambiguous).
    """
    if matched == value:
        return ""
    if matched == value.lower():
        return "lower"
    if matched == value.upper():
        return "upper"
    if matched == value.title():
        return "title"
    return None


def apply_prefixes(text, pv):
    """Rewrite personal-name namespace prefixes (values file "rename_prefixes") in TEXT; -> new text.

    Used for BOTH file/dir name parts and file content, so a renamed module and every import of it agree.
    Case handling: all-lower matches get the new prefix as written, ALL-CAPS matches get it upper-cased, and any
    other spelling (e.g. "Alice_" for a prefix "alice_") is ambiguous -> the file is refused, because guessing could leave a half-renamed
    reference.  No-op when the rules file has no rename_prefixes.
    """
    if pv.prefix_re is None:
        return text

    def rep(m):
        """re.sub callback: map one prefix match to its neutral replacement, preserving all-lower / ALL-CAPS."""
        matched = m.group(0)
        new = pv.prefix_map[matched.casefold()]
        if matched == matched.lower():
            return new
        if matched == matched.upper():
            return new.upper()
        raise Ambiguous("mixed-case variant of a rename prefix at line %d" % (text.count("\n", 0, m.start()) + 1))

    return pv.prefix_re.sub(rep, text)


def fixture_mask_spans(text, strings):
    """Find every occurrence of an allowlisted fixture string in TEXT.

    Args:
        text: file body.
        strings: iterable of literal strings (intentional fake secrets in test files) to protect.
    Returns:
        list of (start, end) character ranges; overlapping occurrences are all reported. Plain substring search,
        case-sensitive.
    """
    spans = []
    for fs in strings:
        i = text.find(fs)
        while i != -1:
            spans.append((i, i + len(fs)))
            i = text.find(fs, i + 1)
    return spans


def plan_spans(text, pv, mask=()):
    """Resolve all exact + pattern hits into disjoint spans, longest first. Raises Ambiguous.

    mask: allowlisted fixture strings that must be left exactly as they are (intentional fake secrets in tests).
    A candidate replacement lying wholly inside a masked string is dropped; one that only partly overlaps a
    masked string is ambiguous (we cannot both keep the fixture intact and replace part of it) -> refuse.

    Args:
        text: file body or one path component.
        pv: PrivateValues.
        mask: iterable of fixture strings (empty for path parts and files without fixtures).
    Returns:
        list of Span sorted by position and not overlapping. A match fully inside a longer one is dropped (longest
        wins); a partial overlap, a mixed-case variant of a value, or pre-existing placeholder text raises Ambiguous.
    """
    if TOKEN_RE.search(text):
        raise Ambiguous("contains a placeholder-like token already")
    cands = []   # all candidate spans, exact values and patterns together
    for key, value, rx in pv.exact:
        for m in rx.finditer(text):
            s = m.start(1)
            matched = text[s:s + len(value)]
            var = _variant_of(matched, value)
            if var is None:
                raise Ambiguous("mixed-case variant of a private value (%s) at line %d" % (key, text.count("\n", 0, s) + 1))
            cands.append(Span(s, s + len(value), "exact", key=key, variant=var))
    for s, e, cls in pattern_spans(text, pv.allow_emails):
        cands.append(Span(s, e, "pattern", cls=cls))
    if mask:
        keep = []   # candidates that survive the fixture mask
        mspans = fixture_mask_spans(text, mask)
        for c in cands:
            inside = any(ms <= c.start and c.end <= me for ms, me in mspans)
            partial = any(c.start < me and ms < c.end for ms, me in mspans)
            if inside:
                continue                      # part of an allowlisted fixture: deliberately left alone
            if partial:
                raise Ambiguous("a private value overlaps an allowlisted fixture string at line %d"
                                % (text.count("\n", 0, c.start) + 1))
            keep.append(c)
        cands = keep
    # Order: earliest start, then longest, then exact values before patterns, then name (deterministic).
    cands.sort(key=lambda c: (c.start, -(c.end - c.start), 0 if c.kind == "exact" else 1, c.key or c.cls))
    out = []
    for c in cands:
        if out and c.start < out[-1].end:
            if c.end <= out[-1].end:
                continue   # fully contained in the previous (longer or equal) match: drop it
            raise Ambiguous("partially overlapping matches at line %d" % (text.count("\n", 0, c.start) + 1))
        out.append(c)
    return out


class State:
    """Token allocation for one component run (deterministic by processing order)."""

    def __init__(self, pv):
        """Start with empty allocation tables for the values in `pv`."""
        self.pv = pv
        self.exact_keys = set(pv.flat)   # names a generated token may not reuse
        self.counter = {}   # prefix -> last number handed out
        self.pat_map = {}   # (class, original text) -> token key, so repeats share one token
        self.restore = {}   # token key -> original text (written to the private restore map)

    def pattern_key(self, cls, orig):
        """Return the token key for a pattern hit, allocating the next number (e.g. HOST_3) for new originals.

        The same (class, original) always gets the same key within a run; a number that collides with a user-defined
        key name is skipped. Records the original in self.restore.
        """
        k = (cls, orig)
        if k in self.pat_map:
            return self.pat_map[k]
        prefix = CLASS_PREFIX[cls]
        n = self.counter.get(prefix, 0)
        while True:
            n += 1
            name = "%s_%d" % (prefix, n)
            if name not in self.exact_keys:
                break
        self.counter[prefix] = n
        self.pat_map[k] = name
        self.restore[name] = orig
        return name


def apply_spans(text, spans, state):
    """Replace each span with its token.

    Args:
        text: original text.
        spans: disjoint Span list from plan_spans (sorted).
        state: State used to allocate pattern tokens.
    Returns:
        (new_text, records) where each record has the token, key, class, kind, variant, salted hash of the original,
        and "off" = offset of the token in new_text (callers convert it to line/column).
    Raises:
        Ambiguous if the new text would contain placeholder-like text other than the tokens just written.
    """
    out, recs, pos, outlen = [], [], 0, 0
    for s in spans:
        out.append(text[pos:s.start])
        outlen += s.start - pos
        orig = text[s.start:s.end]
        if s.kind == "exact":
            tkey = s.key
            tok = "{{%s%s}}" % (tkey, "." + s.variant if s.variant else "")
            cls = "EXACT"
        else:
            tkey = state.pattern_key(s.cls, orig)
            tok = "{{%s}}" % tkey
            cls = s.cls
        recs.append({"off": outlen, "placeholder": tok, "key": tkey, "class": cls, "kind": s.kind,
                     "variant": s.variant, "hash": ann_hash(state.pv.salt, orig)})
        out.append(tok)
        outlen += len(tok)
        pos = s.end
    out.append(text[pos:])
    new = "".join(out)
    # Safety net: the only tokens in the result must be the ones we wrote, in order.
    found = [m.group(0) for m in TOKEN_RE.finditer(new)]
    if found != [r["placeholder"] for r in recs]:
        raise Ambiguous("replacement would create or merge placeholder-like text")
    return new, recs


# ----------------------------------------------------------------------------------------------- excludes
def parse_excludes(path):
    """Read the exclude list: whitespace-separated path patterns, "#" starts a comment, "(...)" notes are ignored.

    Returns a list of pattern strings. Raises ScrubError if the file is missing (fail closed: no list, no run).
    Patterns: "dir/" (any directory part sequence), glob names ("*.log"), "a/b" path prefixes, plain names.
    """
    p = Path(path)
    if not p.is_file():
        raise ScrubError("EXCLUDE_LIST not found: %s" % p)
    pats = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()   # drop comments
        skip = False   # true while inside a parenthesised note spanning several words
        for t in line.split():
            if skip:
                if t.endswith(")"):
                    skip = False
                continue
            if t.startswith("("):
                if not t.endswith(")"):
                    skip = True
                continue
            pats.append(t)
    return pats


def excluded(rel, pats):
    """True if the relative POSIX path matches any exclude pattern (see parse_excludes for pattern forms)."""
    parts = rel.split("/")
    for p in pats:
        if p.endswith("/"):   # directory pattern: matches that directory sequence anywhere in the parent path
            dparts = p.rstrip("/").split("/")
            for i in range(0, len(parts) - len(dparts)):
                if all(fnmatch.fnmatchcase(parts[i + j], dparts[j]) for j in range(len(dparts))):
                    return True
        elif "*" in p or "?" in p:   # glob: against the whole path if it has a slash, else against any single part
            if "/" in p:
                if fnmatch.fnmatchcase(rel, p):
                    return True
            elif any(fnmatch.fnmatchcase(x, p) for x in parts):
                return True
        elif "/" in p:   # literal path: the file itself or anything below it
            if rel == p or rel.startswith(p + "/"):
                return True
        elif p in parts:   # plain name: matches any path component
            return True
    return False


def refused_type(rel, data=None):
    """Decide whether a file must be refused instead of scrubbed.

    Args:
        rel: relative path (only the file name and extension are used).
        data: optional raw bytes; when given, content checks run too (magic headers, NUL bytes, UTF-8, private key).
    Returns:
        A short reason string, or None if the file may be text-scrubbed. Never includes file content.
    """
    name = rel.rsplit("/", 1)[-1]
    low = name.lower()
    ext = os.path.splitext(low)[1]
    if ext in REFUSE_EXT:
        return "refused file type (%s)" % ext
    if BACKUP_NAME_RE.search(low):
        return "sync-conflict or backup copy (never published)"
    # ".env" files hold secrets; ".env.example"-style templates are allowed.
    if name in REFUSE_NAMES or (low.startswith(".env.") and not low.endswith((".example", ".sample", ".template"))):
        return "refused sensitive file name"
    if data is not None:
        if any(data.startswith(m) for m in MAGIC):
            return "binary magic header"
        if b"\x00" in data:
            return "binary content (NUL byte)"
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return "not valid UTF-8"
        if has_private_key_block(text):
            return "contains a private key block"
    return None


# ----------------------------------------------------------------------------------------------- core
def _line_col(text, off):
    """Convert a character offset into 1-based (line, column)."""
    line = text.count("\n", 0, off) + 1
    col = off - (text.rfind("\n", 0, off) + 1) + 1
    return line, col


def scrub_name_parts(rel, pv):
    """Plan spans for each path part separately (so a "/" can never be part of a match).

    Returns a list of (part, spans) where part is the path component after prefix renaming and spans are planned
    on that renamed text. Raises Ambiguous like plan_spans.
    """
    out = []
    for part in rel.split("/"):
        part = apply_prefixes(part, pv)        # neutral namespace first, then private values -> tokens
        out.append((part, plan_spans(part, pv)))
    return out


def check_rel(rel):
    """Validate one manifest path: non-empty relative POSIX path with no "..", ".", empty parts, backslashes or NUL.

    Raises ScrubError otherwise. This keeps every read inside the source root.
    """
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel or "\x00" in rel:
        raise ScrubError("manifest path must be a non-empty relative POSIX path: %r" % (rel,))
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ScrubError("manifest path may not contain empty, '.' or '..' parts: %r" % (rel,))


def load_manifest(path):
    """Read and validate the manifest JSON.

    Returns (component name, sorted unique file list, sorted unique exclude-exception list).
    Raises ScrubError for unreadable JSON, unknown keys (no globs or extras are allowed), a bad component name,
    an empty file list, or any bad path.
    """
    try:
        m = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ScrubError("cannot read manifest: %s" % type(e).__name__)
    if not isinstance(m, dict):
        raise ScrubError("manifest must be a JSON object")
    unknown = set(m) - {"component", "files", "exclude_exceptions"}
    if unknown:
        raise ScrubError("unknown manifest keys (no globs or extras allowed): %s" % ", ".join(sorted(unknown)))
    comp = m.get("component")
    if not isinstance(comp, str) or not COMPONENT_RE.match(comp) or comp.endswith("."):
        raise ScrubError("bad component name")
    files = m.get("files")
    if not isinstance(files, list) or not files:
        raise ScrubError("manifest needs a non-empty \"files\" list")
    exc = m.get("exclude_exceptions", [])
    if not isinstance(exc, list):
        raise ScrubError("exclude_exceptions must be a list")
    for f in files + exc:
        check_rel(f)
    return comp, sorted(set(files)), sorted(set(exc))


def natural_key(s):
    """Sort key that orders embedded numbers numerically ("HOST_2" before "HOST_10") by zero-padding digit runs."""
    return re.sub(r"\d+", lambda m: m.group(0).zfill(8), s)


# Folder that holds the private files by default; nothing under it may ever be published.
DEFAULT_CONFIG_DIR = DEFAULT_VALUES.parent


def private_file_guard(values_path, restore_path, release_root):
    """B2: the set of paths a manifest may NEVER list: the values file (holds the salt and every private value), the
    restore map (token -> original), the annotations.private/ folder next to it, and the default config folder
    (~/.config/twu_release).

    Returns (files, dirs): resolved Path objects.  A manifest entry is refused when its resolved path equals a file,
    lies under a dir, or is the same inode as a file (hard-link copy).  Without this guard the scrubber would copy the
    values file with only its VALUES replaced, publishing the salt in clear (every hash is then guessable).
    """
    files, dirs = [], [DEFAULT_CONFIG_DIR.expanduser()]
    for f in (values_path, restore_path):
        if f:
            files.append(Path(f).expanduser())
    rp = Path(restore_path).expanduser() if restore_path else None
    if rp is not None:
        dirs.append(rp.parent / PRIVATE_ANN_DIR)
    out_f, out_d = [], []
    for x in files:
        out_f.append(Path(os.path.abspath(str(x))))
        out_f.append(x.resolve())
    for x in dirs:
        out_d.append(Path(os.path.abspath(str(x))))
        out_d.append(x.resolve())
    return out_f, out_d


def _is_private_file(src, guard):
    """True if SRC (a Path inside the source root) is, resolves to, or hard-links a guarded private file / folder."""
    files, dirs = guard
    cands = [Path(os.path.abspath(str(src)))]
    try:
        cands.append(src.resolve())
    except OSError:
        pass
    for c in cands:
        if c in files or any(c == d or d in c.parents for d in dirs):
            return True
    try:
        st = os.stat(str(src))
        for f in files:
            if f.exists():
                fs = os.stat(str(f))
                if (fs.st_dev, fs.st_ino) == (st.st_dev, st.st_ino):
                    return True      # a hard link / copy-by-link of the values file
    except OSError:
        pass
    return False


def build_component(manifest_path, values_path, release_root, source_root, restore_path, stage_root=None, allow=None):
    """Scrub one manifest into <stage_root>/<component>/ (default <release_root>/staging).

    stage_root: alternative output parent (release.py passes its --out here).  allow: an allowlist.Allowlist
    (fixture strings are left untouched; hand-approved binaries are copied verbatim, renamed if their NAME leaks).
    Returns a dict that also carries file_map (output path -> source path) for the syntax gate.

    Args:
        manifest_path: JSON manifest (see load_manifest).
        values_path: private values file.
        release_root: release tree root (holds _privacy/EXCLUDE_LIST.txt and, by default, staging/).
        source_root: folder the manifest's relative paths refer to.
        restore_path: private restore map to update (must live outside the release tree).
        stage_root: optional alternative output parent.
        allow: optional allowlist.Allowlist; defaults to an empty one.
    Returns:
        dict with component, copied, refused (counts), records (all replacements), refused_list, file_map, comp_dir.
    Raises:
        ScrubError for any setup problem; this happens before the component folder is touched. Per-file problems
        (excluded, binary, symlink, too large, ambiguous...) only add to the refused list.
    Phases: 1) validate inputs, 2) classify and plan every file in memory, 3) allocate tokens deterministically,
    4) only then clear and write the component folder and the reports.
    """
    allow = allow or al.Allowlist()
    release_root = Path(release_root).resolve()
    source_root = Path(source_root).resolve()
    pv = load_values(values_path, release_root)
    comp, files, exceptions = load_manifest(manifest_path)
    restore_path = Path(restore_path).expanduser()
    # The restore map holds real originals, so it must never be placed inside the publishable tree.
    for cand in (Path(os.path.abspath(str(restore_path))), restore_path.resolve()):
        if cand == release_root or release_root in cand.parents:
            raise ScrubError("restore map must live OUTSIDE the release tree")
    if restore_path.exists():   # an existing map must already be private; a new one is created with mode 600 later
        check_private_file(restore_path, release_root, "restore map")
    pats = parse_excludes(release_root / "_privacy" / "EXCLUDE_LIST.txt")
    stage_root = Path(stage_root).resolve() if stage_root else release_root / "staging"
    comp_dir = stage_root / comp
    if not source_root.is_dir():
        raise ScrubError("source root missing")

    # B2: refuse the WHOLE run (nothing written) when the manifest lists a private file.  This is not a per-file
    # refusal: listing the values file is a setup mistake that must not be waved through with --allow-refused.
    guard = private_file_guard(values_path, restore_path, release_root)
    for rel in files:
        if _is_private_file(source_root / rel, guard):
            raise ScrubError("manifest lists a private file (values file, restore map, annotations.private/ or the "
                             "config folder); it must never be published: entry #%d" % (files.index(rel) + 1))

    state = State(pv)
    refused = []          # {"path": display, "reason": str}
    accepted = []         # (rel, out_rel, data text, name_spans, content_spans, mode)
    used_out = {}
    unprintable = 0   # counter for refused paths whose scrubbed name cannot be computed

    def display(rel):
        """Scrubbed, safe-to-print version of a source path, or None if its name is itself ambiguous."""
        try:
            parts, _ = _apply_name(rel, pv, State(pv))
            return "/".join(parts)
        except Ambiguous:
            return None

    # ---- phase 2: classify every manifest entry; the first failing check gives the refusal reason
    for rel in files:
        why = None
        src = source_root / rel
        if excluded(rel, pats) and rel not in exceptions:
            why = "path matches EXCLUDE_LIST.txt"
        else:
            why = refused_type(rel)
        text = None
        if why is None:
            try:
                st = os.lstat(str(src))   # lstat: do not follow symlinks
            except OSError:
                st = None
            if st is None:
                why = "missing"
            elif stat.S_ISLNK(st.st_mode):
                why = "symlink"
            elif not stat.S_ISREG(st.st_mode):
                why = "not a regular file"
            elif st.st_size > MAX_FILE_BYTES:
                why = "file too large"
            else:
                # defend against symlinked parent directories escaping the source root
                try:
                    real = src.resolve()
                    if source_root != real and source_root not in real.parents:
                        why = "resolves outside source root"
                except OSError:
                    why = "unresolvable"
        data = None
        binary_ok = False           # True when a hand-approved binary is copied verbatim
        if why is None:
            data = src.read_bytes()
            why = refused_type(rel, data)   # content-based checks (magic bytes, NUL, UTF-8, private key block)
            if why is None and pv.salt.encode("utf-8") in data:
                # B2: a file that holds the SALT (a copy of the values file under another name, a pasted config).
                # The salt makes every private hash guessable, so such a file is never copied.
                why = "contains the private salt"
            # A binary/archive/db/pdf is copied ONLY if its exact bytes were hand-approved in the allowlist.  Private
            # key blocks, sensitive file names and backup copies are never approvable.
            if why is not None and "private key" not in why and "sensitive" not in why and "backup" not in why \
                    and allow.binary_approved(hashlib.sha256(data).hexdigest()):
                binary_ok = True
                why = None
        if why is None:
            try:
                name_plan = scrub_name_parts(rel, pv)
                if binary_ok:
                    text, content_plan = None, []          # bytes pass through untouched; names are still renamed
                else:
                    text = apply_prefixes(data.decode("utf-8"), pv)
                    content_plan = plan_spans(text, pv, allow.fixture_strings(rel))
            except Ambiguous as e:
                why = "ambiguous: %s" % e
        if why is not None:
            shown = display(rel)   # never print the raw path: it could contain a private value
            if shown is None:
                unprintable += 1
                shown = "<unprintable path #%d>" % unprintable
            refused.append({"path": shown, "reason": why})
            continue
        mode = 0o755 if (st.st_mode & 0o111) else 0o644   # keep "executable" but normalise everything else
        accepted.append((rel, name_plan, content_plan, text if not binary_ok else data, mode))

    # ---- phase 3: allocate tokens in deterministic (sorted manifest) order and render
    records, outputs, file_map = [], [], {}
    for rel, name_plan, content_plan, text, mode in accepted:
        parts, nrecs = [], []
        offset = 0
        for part, spans in name_plan:
            new, recs = apply_spans(part, spans, state)
            for r in recs:
                r["off"] += offset   # shift to the position inside the full path string
            nrecs.extend(recs)
            parts.append(new)
            offset += len(new) + 1   # +1 for the "/" separator
        out_rel = "/".join(parts)
        # Two sources mapping to one scrubbed name, or a name reserved for generated pages, would silently clobber.
        if out_rel in used_out or out_rel in META_FILES or any(out_rel.startswith(x + "/") for x in META_FILES):
            refused.append({"path": out_rel, "reason": "staged path collision"})
            continue
        used_out[out_rel] = rel
        for r in nrecs:
            r.update({"file": out_rel, "line": 0, "column": r.pop("off") + 1, "kind": "filename"})   # line 0 = file name
        if isinstance(text, bytes):                 # approved binary: no content records, bytes untouched
            outputs.append((out_rel, text, mode))
            records.extend(nrecs)
            file_map[out_rel] = rel
            continue
        new_text, crecs = apply_spans(text, content_plan, state)
        for r in crecs:
            line, col = _line_col(new_text, r.pop("off"))
            r.update({"file": out_rel, "line": line, "column": col})
        records.extend(nrecs)
        records.extend(crecs)
        outputs.append((out_rel, new_text, mode))
        file_map[out_rel] = rel

    records.sort(key=lambda r: (r["file"], r["line"], r["column"]))
    refused.sort(key=lambda r: (r["path"], r["reason"]))

    # ---- phase 4: everything validated; now write (staging only, plus private restore map)
    if comp_dir.is_symlink():
        # F8: rmtree refuses a symlink with an OSError traceback; fail cleanly instead (nothing has been written yet).
        raise ScrubError("staging/<component> is a symlink; refusing to write through it (remove the link)")
    if comp_dir.exists():
        # Only ever delete inside the staging parent (guards against a component name resolving elsewhere).
        if stage_root.resolve() not in comp_dir.resolve().parents:
            raise ScrubError("refusing to clear a directory outside staging")
        shutil.rmtree(str(comp_dir))
    comp_dir.mkdir(parents=True)
    for out_rel, new_text, mode in outputs:
        dst = comp_dir / out_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(new_text if isinstance(new_text, bytes) else new_text.encode("utf-8"))
        os.chmod(str(dst), mode)
    write_annotations(comp_dir, comp, sorted(o[0] for o in outputs), exceptions, records, refused, restore_path)
    (comp_dir / "ANNOTATIONS.md").write_text(render_annotations_md(comp, records, refused, exceptions), encoding="utf-8")
    (comp_dir / "REFUSED.md").write_text(render_refused_md(comp, refused), encoding="utf-8")
    write_index(stage_root)
    write_restore(restore_path, comp, state.restore)
    return {"component": comp, "copied": len(outputs), "refused": len(refused), "records": records, "refused_list": refused,
            "file_map": file_map, "comp_dir": str(comp_dir)}


# Folder name (next to the restore map, outside the release tree) for annotation files that include salted hashes.
PRIVATE_ANN_DIR = "annotations.private"


def public_refused(refused):
    """F3: the PUBLISHED view of the refused list: item number + reason only, NO path.

    A refused path ("private/notes.txt", "taxes_2025.xlsx") is itself information; the public ANNOTATIONS.json and
    REFUSED.md therefore carry only "item N" and the reason.  The full list (scrubbed paths) goes to the private
    annotations copy, and the scrubber prints it on the operator's screen.  Item numbers follow the sorted order of the
    full list, so the private copy maps each item back to its path.
    """
    return [{"item": n, "reason": r["reason"]} for n, r in enumerate(refused, 1)]


def write_annotations(comp_dir, comp, files, exceptions, records, refused, restore_path):
    """Public ANNOTATIONS.json (placeholder/file/line/column only, no hashes) + a private copy WITH salted hashes.

    The private copy lives next to the restore map (outside the release tree), chmod 600, and is what hotswap.py
    uses to verify restored values.
    """
    pub_keys = ("class", "column", "file", "key", "kind", "line", "placeholder", "variant")
    pub = {"version": 2, "component": comp, "files": files, "exclude_exceptions": exceptions,
           "replacements": [{k: r[k] for k in pub_keys} for r in records], "refused": public_refused(refused)}
    (Path(comp_dir) / "ANNOTATIONS.json").write_text(json.dumps(pub, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    priv = dict(pub, salt_note="hashes are sha256(salt NUL original)[:32]; salt is private", replacements=records,
                refused_paths=[dict(r, item=n) for n, r in enumerate(refused, 1)])   # full list: private copy only
    pdir = Path(restore_path).parent / PRIVATE_ANN_DIR
    parent_existed = pdir.parent.is_dir()
    pdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(pdir), 0o700)
    if not parent_existed:
        os.chmod(str(pdir.parent), 0o700)   # a config folder we just created must also be owner-only
    target = pdir / (comp + ".json")
    # Write atomically: temp file with mode 600 in the same folder, then rename over the target.
    fd, tmp = tempfile.mkstemp(prefix=".ann.", dir=str(pdir))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(priv, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, str(target))
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)   # do not leave a half-written private file behind
        raise


def _apply_name(rel, pv, state):
    """Scrub every part of a relative path. Returns (list of new parts, list of records)."""
    parts, recs = [], []
    for part, spans in scrub_name_parts(rel, pv):
        new, r = apply_spans(part, spans, state)
        parts.append(new)
        recs.extend(r)
    return parts, recs


# ----------------------------------------------------------------------------------------------- reports
def meaning_for(token_key, cls):
    """Return (meaning, what-to-put hint) for a token key.

    Pattern classes use CLASS_MEANING. Exact keys are looked up in KEY_MEANING by full name, then with a trailing
    "_<n>" removed, then by the first word; otherwise a generic description naming the key is returned.
    """
    if cls != "EXACT":
        m, h = CLASS_MEANING[cls]
        return m, h
    base = re.sub(r"_\d+$", "", token_key)   # "HOST_2" -> "HOST"
    for k in (token_key, base):
        if k in KEY_MEANING:
            return KEY_MEANING[k], "your own value for this item"
    first = base.split("_")[0]
    if first in KEY_MEANING:
        return KEY_MEANING[first], "your own value for this item"
    return "a private value kept in the owner's values file (key %s)" % token_key, "your own value for this item"


def _locations(recs):
    """Format occurrences as "file:line,line (file name)" entries joined by <br>, for a Markdown table cell."""
    by = {}
    for r in recs:
        by.setdefault(r["file"], []).append(r)
    chunks = []
    for f in sorted(by):
        lines = sorted(set(r["line"] for r in by[f] if r["line"] > 0))
        s = f
        if lines:
            s += ":" + ",".join(str(n) for n in lines)
        if any(r["line"] == 0 for r in by[f]):
            s += " (file name)"
        chunks.append(s)
    return "<br>".join(chunks)


def render_annotations_md(comp, records, refused, exceptions):
    """Render the component's ANNOTATIONS.md: a table of placeholders, their meaning and where they occur.

    Contains placeholders only, never the original values. Also mentions granted exclude exceptions and the number
    of refused files.
    """
    by = {}
    for r in records:
        by.setdefault(r["key"], []).append(r)
    L = ["# Placeholders in component `%s`" % comp, "",
         "Generated by scrub_release.py. This page holds placeholders only, never the real values.",
         "Fill the placeholders with your own values using `tools/hotswap.py` (see tools/README.md).", "",
         "Tokens like `{{KEY.lower}}`, `{{KEY.upper}}`, `{{KEY.title}}` mean the original was that case variant of KEY's value.", "",
         "| placeholder | meaning | what to put | file:line list |", "|---|---|---|---|"]
    for key in sorted(by, key=natural_key):
        rs = by[key]
        meaning, hint = meaning_for(key, rs[0]["class"])
        toks = sorted(set(r["placeholder"] for r in rs))
        L.append("| %s | %s | %s | %s |" % (" ".join("`%s`" % t for t in toks), meaning, hint, _locations(rs)))
    if not by:
        L.append("| (none) | | | |")
    if exceptions:
        L += ["", "EXCLUDE_LIST exceptions granted by the manifest: " + ", ".join("`%s`" % e for e in exceptions)]
    L += ["", "Files refused (not copied): %d. See REFUSED.md." % len(refused), ""]
    return "\n".join(L)


def render_refused_md(comp, refused):
    """Render REFUSED.md: the files that were not copied and why (paths already scrubbed)."""
    L = ["# Refused files in component `%s`" % comp, "",
         "These manifest entries were NOT copied (fail closed). Their names are withheld on purpose: a refused file's",
         "name can itself be private.  The scrubber prints the list on the operator's screen and keeps it in the",
         "private annotations copy (`refused_paths`).", ""]
    if not refused:
        L.append("(none)")
    else:
        L += ["| item | reason |", "|---|---|"] + ["| %d | %s |" % (n, r["reason"]) for n, r in enumerate(refused, 1)]
    return "\n".join(L) + "\n"


def write_index(stage_root):
    """Rebuild PLACEHOLDERS_INDEX.md from every component's public ANNOTATIONS.json under stage_root.

    Lists each placeholder key with its class and per-component counts, then a files copied/refused table.
    """
    comps = {}   # component name -> parsed ANNOTATIONS.json
    for d in sorted(Path(stage_root).iterdir()):
        a = d / "ANNOTATIONS.json"
        if d.is_dir() and a.is_file():
            comps[d.name] = json.loads(a.read_text(encoding="utf-8"))
    agg = {}
    for c, ann in comps.items():
        for r in ann["replacements"]:
            e = agg.setdefault(r["key"], {"class": r["class"], "comps": {}})
            e["comps"][c] = e["comps"].get(c, 0) + 1
    L = ["# Placeholders index (all components)", "",
         "Generated. Pattern-class tokens such as `HOST_1` are numbered per component: the same name in two components",
         "can mean different values, so hot-swap one component at a time.", "",
         "| placeholder key | class | component (occurrences) |", "|---|---|---|"]
    for k in sorted(agg, key=natural_key):
        e = agg[k]
        L.append("| `%s` | %s | %s |" % (k, e["class"], ", ".join("%s (%d)" % (c, n) for c, n in sorted(e["comps"].items()))))
    if not agg:
        L.append("| (none) | | |")
    L += ["", "| component | files copied | files refused |", "|---|---|---|"]
    for c in sorted(comps):
        L.append("| %s | %d | %d |" % (c, len(comps[c]["files"]), len(comps[c]["refused"])))
    (Path(stage_root) / "PLACEHOLDERS_INDEX.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def write_restore(path, comp, mapping):
    """Merge one component's token -> original map into the private restore file.

    Other components' sections are preserved. Refuses to overwrite a file that is not valid JSON. Written atomically
    with mode 600 (folder 700). Contains real values, so it must stay outside the release tree.
    """
    path = Path(path)
    # F8: two scrubs of different components run at the same time would each read the file, add their own section and
    # write it back, and the second write could drop the first one's section.  An exclusive flock on a small lock file
    # next to the map makes the read-merge-write atomic with respect to other copies of this tool.
    lock_fh = None
    existed = path.parent.is_dir()      # remembered BEFORE the lock file creates the folder (see the chmod below)
    if fcntl is not None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not existed:
            os.chmod(str(path.parent), 0o700)   # a config folder WE created is owner-only
        lock_fh = open(str(path.parent / ".restore.lock"), "a")
        os.chmod(str(path.parent / ".restore.lock"), 0o600)
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
    try:
        _write_restore_locked(path, comp, mapping)
    finally:
        if lock_fh is not None:
            lock_fh.close()      # closing releases the lock


def _write_restore_locked(path, comp, mapping):
    """The read-merge-write body of write_restore (the caller holds the lock)."""
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:   # never clobber a file we cannot understand: it may hold other components' data
            raise ScrubError("existing restore map is not valid JSON; refusing to overwrite it")
    data[comp] = dict(sorted(mapping.items(), key=lambda kv: natural_key(kv[0])))
    existed = path.parent.is_dir()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not existed:
        # mkdir(mode=) is filtered by the umask and applies to the leaf only: make the claim "folder 700" true for a
        # folder WE created.  A pre-existing folder (e.g. a shared one the user chose) is never re-moded.
        os.chmod(str(path.parent), 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".restore.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, str(path))
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    os.chmod(str(path), 0o600)


def main(argv=None):
    """Command-line entry point.

    Args:
        argv: optional argument list (defaults to sys.argv[1:]).
    Returns:
        0 all files copied, 3 some files refused, 2 fatal error. Prints a count summary per class and one line per
        refused (scrubbed) path; never prints original values.
    """
    ap = argparse.ArgumentParser(description="Scrub an allowlisted component into staging/")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--values", default=str(DEFAULT_VALUES))
    ap.add_argument("--release-root", default=str(DEFAULT_RELEASE_ROOT))
    ap.add_argument("--source-root", default=str(DEFAULT_SOURCE_ROOT))
    ap.add_argument("--restore-map", default=str(DEFAULT_RESTORE))
    a = ap.parse_args(argv)
    try:
        res = build_component(a.manifest, a.values, a.release_root, a.source_root, a.restore_map)
    except ScrubError as e:
        print("scrub_release: FATAL: %s" % e, file=sys.stderr)
        return 2
    counts = {}
    for r in res["records"]:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    print("component=%s copied=%d refused=%d replacements=%d" % (res["component"], res["copied"], res["refused"], len(res["records"])))
    for k in sorted(counts):
        print("  %s: %d" % (k, counts[k]))
    for r in res["refused_list"]:
        print("  REFUSED %s: %s" % (r["path"], r["reason"]))
    return 3 if res["refused"] else 0


if __name__ == "__main__":
    sys.exit(main())
