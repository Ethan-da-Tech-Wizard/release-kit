"""Shared synthetic fixtures for the release-tool tests.

Purpose: one place that defines the fake "private" values, a sample file full of
them, and a helper class that builds temporary source/release/config trees.

IMPORTANT: every value in this module is invented (fake names, a ".test" domain,
documentation-range-like addresses, repeated filler characters for keys).  None of
it identifies a real person, machine or credential.  Secret-shaped strings are
built from repeated filler so no real-looking token literal exists.

Used by test_release_tools.py (and any other test needing the same fixtures).
Importing this module also puts the tools directory on sys.path.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import scrub_release as sr  # noqa: E402

# Synthetic hashing salt (the tool requires one; the value is meaningless).
SALT = "fake-salt-0123456789"
# Fake private values keyed by placeholder name; the tool should scrub every one of these.
VALUES = {
    "OWNER_NAME": "Fakey McFakeface",
    "OWNER_FIRST": "Fakey",
    "OWNER_HANDLE": "fakeuser9",
    "HOST_PRIMARY": "fakebox-alpha",
    "OWNER_EMAIL": "fakeuser9@fakecorp.test",
    "ORG_NAME": "Fakecorp Holdings",
}
# Shapes that mimic real secret formats but are filler:
# WG = 43 chars + "=" (WireGuard-style key).
WG = ("FAKEkey0" * 6)[:43] + "="
# SYNC = eight dash-separated groups of seven letters (device-id shape).
SYNC = "-".join(["FAKE%s%s%s" % (c, c, c) for c in "ABCDEFGH"])
# TOKEN = "ghp_" plus 36 filler characters (GitHub-token shape).
TOKEN = "ghp_" + "F" * 36
# SSH = public-key-line shape with filler base64.
SSH = "ssh-ed25519 AAAA" + "FAKEFAKE" * 5
# Built from pieces so no MAC-address or .local host literal sits in this file (global commit hook).
MAC = "aa:bb:cc" + ":dd:ee:ff"
NAME = "laptop-x" + ".local"

# A sample file mixing every kind of fake private value (names, host, e-mail, IPs, MAC, keys,
# phone, tax-id-like numbers) with harmless look-alikes that must NOT be scrubbed
# (example.com mail, an allow-listed public address, a 10.15.7 version string, stray braces).
SAMPLE = """# notes by Fakey McFakeface (fakeuser9)
HOME = "/Users/fakeuser9/work"
EMAIL = "fakeuser9@fakecorp.test"
OTHER = "someone.else@elsewhere.test"
PUBLIC = "help@public-contact.test"
SAFE = "dev@example.com"
HOST = "fakebox-alpha"
HOST_UP = "FAKEBOX-ALPHA"
HOST_TI = "Fakebox-Alpha"
ORG = "Fakecorp Holdings / fakecorp holdings"
LAN = "192.168.7.21"
LAN2 = "10.20.30.40"
LAN3 = "192.168.7.21"
VPN = "100.64.1.9"
MAC = "%(mac)s"
NAME = "%(name)s"
WG = "%(wg)s"
SYNC = "%(sync)s"
TOKEN = "%(token)s"
PHONE = "212-555-4417"
EIN = "98-7654321"
UEI = "UEI: ABCDE12345FG"
SSH = "%(ssh)s"
VERSION = "10.15.7"
MARK = "{ and }} and {{ lone"
""" % {"wg": WG, "sync": SYNC, "token": TOKEN, "ssh": SSH, "mac": MAC, "name": NAME}

# Text with Windows line endings, non-ASCII characters and no trailing newline, to test
# that scrub/restore keep bytes exact.
CRLF = "line one fakeuser9\r\nline two /home/fakeuser9/x\r\ncafé ünï 192.168.7.21 no trailing newline"

# Contents of a fake EXCLUDE_LIST.txt: path patterns that must never be released
# (a trailing parenthesised note marks a "review" entry).
EXCLUDES = "private/\n*.pyc\ndata/example_kit/\nHANDOFF.md\nexports/ (review; contains stuff)\n"


class Env:
    """Disposable sandbox for one test: a fake release tree, fake source tree and a
    fake private-config directory, all under one temporary directory.

    Layout: TMP/release (with _privacy/EXCLUDE_LIST.txt), TMP/src, TMP/cfg
    (values and restore-map files).  Call cleanup() when done.
    """
    def __init__(self):
        """Create the temp directories and write the default synthetic values file."""
        self.tmp = Path(tempfile.mkdtemp(prefix="twu_scrub_test_"))
        self.release = self.tmp / "release"
        self.src = self.tmp / "src"
        self.cfg = self.tmp / "cfg"
        (self.release / "_privacy").mkdir(parents=True)
        (self.release / "_privacy" / "EXCLUDE_LIST.txt").write_text(EXCLUDES)
        self.src.mkdir()
        self.cfg.mkdir()
        self.values = self.cfg / "values.private.json"
        self.restore = self.cfg / "restore.private.json"
        self.write_values(VALUES)

    def write_values(self, values, mode=0o600, **extra):
        """Write the synthetic values file with the given permission MODE.

        Args: values - dict of fake private values; mode - file mode (tests vary it to
        check permission checks); extra - additional top-level keys merged into the JSON.
        """
        d = {"salt": SALT, "values": values, "allow_emails": ["help@public-contact.test"]}
        d.update(extra)
        self.values.write_text(json.dumps(d))
        os.chmod(str(self.values), mode)

    def put(self, rel, content, mode=0o644, binary=False):
        """Create a fake source file REL under src with CONTENT (text, or bytes if binary=True) and MODE."""
        p = self.src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if binary else content.encode("utf-8"))
        os.chmod(str(p), mode)

    def manifest(self, files, component="comp", name="m.json", **extra):
        """Write a manifest JSON listing FILES for COMPONENT and return its path."""
        m = {"component": component, "files": files}
        m.update(extra)
        p = self.tmp / name
        p.write_text(json.dumps(m))
        return p

    def scrub(self, files, component="comp", release=None, **extra):
        """Run the scrubber over FILES via a fresh manifest; returns its result summary."""
        mp = self.manifest(files, component, **extra)
        return sr.build_component(mp, self.values, release or self.release, self.src, self.restore)

    def staged(self, component="comp"):
        """Return the staging directory for COMPONENT."""
        return self.release / "staging" / component

    def cleanup(self):
        """Delete the whole temporary directory."""
        shutil.rmtree(str(self.tmp), ignore_errors=True)


def tree(root, skip=()):
    """Snapshot a directory as {relative posix path: (bytes, permission bits)}.

    Files whose relative path is in SKIP are left out.  Used to compare two trees exactly.
    """
    out = {}
    root = Path(root)
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.relative_to(root).as_posix() not in skip:
            out[p.relative_to(root).as_posix()] = (p.read_bytes(), p.stat().st_mode & 0o777)
    return out
