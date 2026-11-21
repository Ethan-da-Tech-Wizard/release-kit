"""Tests for the component release tools: scrub_release, hotswap and release_gate.

Three groups:
  TestScrub   - copying an allow-listed set of files into a staging tree while
                replacing private values with placeholders (and refusing unsafe files).
  TestHotswap - restoring real values from the private map or a user-supplied
                file, byte for byte, failing closed when values are missing.
  TestGate    - the final release gate that must flag any leftover private value,
                secret shape, forbidden file type or bad structure.

All fixtures come from _fx.py and are SYNTHETIC: invented names, hosts and
".test" domains, filler keys.  Nothing here is a real person, machine or secret.

Run (from the tools directory):  python3 -B -m unittest discover -s tests
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import _fx
from _fx import Env, SAMPLE, CRLF, VALUES, SALT, tree

import scrub_release as sr
import hotswap
import release_gate

# Lower-cased fragments of the synthetic private values; none may ever appear in any report
# or gate output.  Everything here is invented (see _fx.py).
PRIVATE_STRINGS = ["fakeuser9", "fakebox-alpha", "fakey", "mcfakeface", "fakecorp", "192.168.7.21",
                   _fx.MAC, "laptop-x", _fx.TOKEN, _fx.WG, _fx.SYNC]


def lines_of(path):
    """Return the lines of the file at PATH decoded as UTF-8, split on newline characters only (so a carriage return stays visible)."""
    return path.read_bytes().decode("utf-8").split("\n")


class Base(unittest.TestCase):
    """Common setup: a fresh synthetic environment per test, removed afterwards."""
    @staticmethod
    def quiet_main(argv):
        """Run scrub_release.main(ARGV) with stdout and stderr silenced; return its exit code."""
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return sr.main(argv)

    def setUp(self):
        """Create the synthetic Env (fake release tree, source tree and config dir) and schedule cleanup."""
        self.e = Env()
        self.addCleanup(self.e.cleanup)


class TestScrub(Base):
    """Scrubber behaviour: input validation, matching rules, refusals, reports."""
    def test_refuses_bad_permissions(self):
        """Proves the values file must be owner-only (0600): any group/other access is rejected, nothing is staged, and the CLI exits 2."""
        self.e.put("a.py", "x = 1\n")
        for mode in (0o644, 0o640, 0o604, 0o666):   # every group/other-accessible mode
            self.e.write_values(VALUES, mode=mode)
            with self.assertRaises(sr.ScrubError):
                self.e.scrub(["a.py"])
        self.assertFalse((self.e.release / "staging" / "comp").exists())
        self.e.write_values(VALUES, mode=0o644)
        mp = self.e.manifest(["a.py"])      # CLI path: loose permissions must give exit code 2
        code = self.quiet_main(["--manifest", str(mp), "--values", str(self.e.values), "--release-root", str(self.e.release),
                        "--source-root", str(self.e.src), "--restore-map", str(self.e.restore)])
        self.assertEqual(code, 2)

    def test_refuses_values_inside_release_tree(self):
        """Proves a values file located inside the release tree is rejected, since it could be published."""
        self.e.put("a.py", "x = 1\n")
        inside = self.e.release / "values.json"
        inside.write_text(json.dumps({"salt": SALT, "values": VALUES}))
        os.chmod(str(inside), 0o600)
        with self.assertRaises(sr.ScrubError):
            sr.build_component(self.e.manifest(["a.py"]), inside, self.e.release, self.e.src, self.e.restore)

    def test_requires_salt_and_rejects_short_or_duplicate_values(self):
        """Proves a values file is rejected when a value is too short, two values collide case-insensitively, or the salt is missing."""
        self.e.put("a.py", "x = 1\n")
        for bad in ({"A_KEY": "ab"}, {"A_KEY": "same-value", "B_KEY": "SAME-value"}):
            self.e.write_values(bad)
            with self.assertRaises(sr.ScrubError):
                self.e.scrub(["a.py"])
        self.e.values.write_text(json.dumps({"values": VALUES}))
        os.chmod(str(self.e.values), 0o600)
        with self.assertRaises(sr.ScrubError):
            self.e.scrub(["a.py"])

    def test_allowlist_only_copy(self):
        """Proves only files named in the manifest are copied (plus generated report files); unlisted files are never swept in."""
        self.e.put("keep.py", "print('hi')\n")
        self.e.put("other.py", "print('not listed')\n")
        self.e.put("sub/also.py", "print('not listed either')\n")
        self.e.scrub(["keep.py"])
        got = sorted(p.relative_to(self.e.staged()).as_posix() for p in self.e.staged().rglob("*") if p.is_file())
        self.assertEqual(got, ["ANNOTATIONS.json", "ANNOTATIONS.md", "REFUSED.md", "keep.py"])

    def test_manifest_rejects_globs_dirs_and_unknown_keys(self):
        """Proves manifests take literal file names only: globs are not expanded, absolute or parent-relative paths error, unknown keys error, and a directory entry is refused."""
        self.e.put("d/a.py", "1\n")
        # Glob, absolute path, parent escape and non-normalised path.
        for files in (["d/*.py"], ["/etc/passwd"], ["../x"], ["d/../d/a.py"]):
            if files == ["d/*.py"]:
                res = self.e.scrub(files)  # a literal name that does not exist: refused, never expanded
                self.assertEqual(res["copied"], 0)
                self.assertEqual(res["refused"], 1)
            else:
                with self.assertRaises(sr.ScrubError):
                    self.e.scrub(files)
        with self.assertRaises(sr.ScrubError):
            self.e.scrub(["d/a.py"], globs=["*"])
        res = self.e.scrub(["d"])  # a directory entry is refused
        self.assertEqual(res["copied"], 0)

    def test_longest_match_first(self):
        """Proves overlapping values resolve to the longest one (full name before first name)."""
        self.e.put("a.txt", "Fakey McFakeface and Fakey alone\n")
        self.e.scrub(["a.txt"])
        out = (self.e.staged() / "a.txt").read_text()
        self.assertEqual(out, "{{OWNER_NAME}} and {{OWNER_FIRST}} alone\n")

    def test_case_variants_handled_and_recorded(self):
        """Proves lower, UPPER and Title spellings of a value get distinct placeholder variants and the variants are recorded in the annotations."""
        self.e.put("a.txt", "fakebox-alpha FAKEBOX-ALPHA Fakebox-Alpha\n")
        self.e.scrub(["a.txt"])
        out = (self.e.staged() / "a.txt").read_text()
        self.assertEqual(out, "{{HOST_PRIMARY}} {{HOST_PRIMARY.upper}} {{HOST_PRIMARY.title}}\n")
        ann = json.loads((self.e.staged() / "ANNOTATIONS.json").read_text())
        self.assertEqual(sorted(r["variant"] for r in ann["replacements"]), ["", "title", "upper"])

    def test_mixed_case_variant_is_refused(self):
        """Proves an oddly cased spelling that no variant can restore exactly causes the file to be refused as ambiguous."""
        self.e.put("a.txt", "fAkEbOx-alpha\n")
        res = self.e.scrub(["a.txt"])
        self.assertEqual(res["copied"], 0)
        self.assertIn("ambiguous", res["refused_list"][0]["reason"])
        self.assertFalse((self.e.staged() / "a.txt").exists())

    def test_filename_and_dirname_scrub(self):
        """Proves private values inside directory and file NAMES are replaced, annotated as filename entries, and absent from the staged paths."""
        self.e.put("notes_fakeuser9/readme_FAKEBOX-ALPHA.md", "hello\n")
        res = self.e.scrub(["notes_fakeuser9/readme_FAKEBOX-ALPHA.md"])
        self.assertEqual(res["copied"], 1)
        self.assertTrue((self.e.staged() / "notes_{{OWNER_HANDLE}}" / "readme_{{HOST_PRIMARY.upper}}.md").is_file())
        ann = json.loads((self.e.staged() / "ANNOTATIONS.json").read_text())
        fn = [r for r in ann["replacements"] if r["kind"] == "filename"]
        self.assertEqual(len(fn), 2)
        for r in fn:
            self.assertEqual(r["line"], 0)
            self.assertEqual(r["file"][r["column"] - 1:r["column"] - 1 + len(r["placeholder"])], r["placeholder"])
        for p in self.e.staged().rglob("*"):
            self.assertNotIn("fakeuser9", p.as_posix().lower())

    def test_binary_and_unsafe_files_refused_and_listed(self):
        """Proves images, databases, NUL-containing files, disguised PDFs, bytecode, model weights and private-key text are refused, listed in REFUSED.md, and cause exit code 3."""
        # Binary/unsafe fixtures: PNG header, SQLite magic, NUL byte, PDF magic with .txt name,
        # bytecode, model-weights file and an (empty-body) private-key block.
        self.e.put("pic.png", b"\x89PNG\r\n\x1a\nxx", binary=True)
        self.e.put("db.sqlite", b"SQLite format 3\x00", binary=True)
        self.e.put("noext", b"abc\x00def", binary=True)
        self.e.put("renamed.txt", b"%PDF-1.4 stuff", binary=True)
        self.e.put("mod.pyc", b"\x00\x01", binary=True)
        self.e.put("weights.gguf", b"GGUF", binary=True)
        self.e.put("k.txt", "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
        self.e.put("ok.txt", "fine\n")
        names = ["pic.png", "db.sqlite", "noext", "renamed.txt", "mod.pyc", "weights.gguf", "k.txt", "ok.txt"]
        res = self.e.scrub(names)
        self.assertEqual(res["copied"], 1)
        self.assertEqual(res["refused"], 7)
        staged = sorted(p.name for p in self.e.staged().iterdir())
        self.assertEqual(staged, ["ANNOTATIONS.json", "ANNOTATIONS.md", "REFUSED.md", "ok.txt"])
        refused = (self.e.staged() / "REFUSED.md").read_text()
        # F3: the PUBLISHED page lists one numbered row per refused file with its reason, and NOT the names.
        self.assertEqual(refused.count("\n| "), 7 + 1)          # 7 items + the header row
        for n in names[:-1]:
            self.assertNotIn(n, refused)
        self.assertEqual({r["path"] for r in res["refused_list"]}, set(names[:-1]))   # the operator still sees names
        mp = self.e.manifest(names)         # CLI path: refusals give exit code 3
        code = self.quiet_main(["--manifest", str(mp), "--values", str(self.e.values), "--release-root", str(self.e.release),
                        "--source-root", str(self.e.src), "--restore-map", str(self.e.restore)])
        self.assertEqual(code, 3)

    def test_exclude_list_enforced_with_explicit_exception(self):
        """Proves paths on the exclude list are skipped unless a manifest names them as an explicit exception."""
        self.e.put("private/x.txt", "x\n")
        self.e.put("data/example_kit/y.txt", "y\n")
        self.e.put("exports/z.txt", "z\n")
        self.e.put("HANDOFF.md", "h\n")
        names = ["private/x.txt", "data/example_kit/y.txt", "exports/z.txt", "HANDOFF.md"]
        res = self.e.scrub(names)
        self.assertEqual(res["copied"], 0)
        res = self.e.scrub(names, exclude_exceptions=["exports/z.txt"])
        self.assertEqual(res["copied"], 1)

    def test_refused_report_does_not_leak_private_file_names(self):
        """Proves the refusal and annotation reports do not echo a private value that appears in a refused file name."""
        self.e.put("fakeuser9_secret.png", b"\x89PNG", binary=True)
        self.e.scrub(["fakeuser9_secret.png"])
        for f in ("REFUSED.md", "ANNOTATIONS.md", "ANNOTATIONS.json"):
            self.assertNotIn("fakeuser9", (self.e.staged() / f).read_text())

    def test_preexisting_placeholder_text_is_refused(self):
        """Proves text that already looks like a placeholder is refused because restoring it would be ambiguous."""
        self.e.put("t.md", "use {{OWNER_NAME}} here\n")
        res = self.e.scrub(["t.md"])
        self.assertEqual(res["copied"], 0)

    def test_partial_overlap_is_refused(self):
        """Proves two values that partially overlap in the text cause refusal instead of a corrupted replacement."""
        # "alpha beta" and "beta gamma" overlap on the word "beta" in "alpha beta gamma".
        self.e.write_values({"AAA_KEY": "alpha beta", "BBB_KEY": "beta gamma"})
        self.e.put("t.txt", "x alpha beta gamma y\n")
        res = self.e.scrub(["t.txt"])
        self.assertEqual(res["copied"], 0)

    def test_pattern_classes_and_nonmatches(self):
        """Proves generic shapes (home paths, e-mails, IPs, MAC, keys, phone, ids) are scrubbed into indexed placeholders while allow-listed and look-alike text is kept; identical values share a token."""
        self.e.put("sample.py", SAMPLE)
        self.e.scrub(["sample.py"])
        out = (self.e.staged() / "sample.py").read_text()
        for needle in ("/Users/fakeuser9", "someone.else@elsewhere.test", "10.20.30.40", "100.64.1.9", _fx.MAC,
                       _fx.NAME, _fx.WG, _fx.SYNC, _fx.TOKEN, "212-555-4417", "98-7654321", "ABCDE12345FG", _fx.SSH):
            self.assertNotIn(needle, out)
        for kept in ("help@public-contact.test", "dev@example.com", "10.15.7", "{ and }} and {{ lone"):
            self.assertIn(kept, out)
        for tok in ("{{HOME_DIR_1}}", "{{EMAIL_1}}", "{{LAN_IP_1}}", "{{LAN_IP_2}}", "{{VPN_IP_1}}", "{{MAC_1}}", "{{HOST_1}}",
                    "{{WG_KEY_1}}", "{{SYNCTHING_DEVICE_1}}", "{{API_TOKEN_1}}", "{{PHONE_1}}", "{{EIN_1}}", "{{UEI_1}}", "{{SSH_KEY_1}}"):
            self.assertIn(tok, out)
        self.assertEqual(out.count("{{LAN_IP_1}}"), 2)  # same value -> same indexed token

    def test_pattern_index_skips_exact_key_collisions(self):
        """Proves auto-numbered placeholders skip a name already used by an explicit rule (HOST_1 is taken, so the next is HOST_2)."""
        self.e.write_values({"HOST_1": "fakebox-alpha"})
        self.e.put("t.txt", "fakebox-alpha " + _fx.NAME + "\n")
        self.e.scrub(["t.txt"])
        self.assertEqual((self.e.staged() / "t.txt").read_text(), "{{HOST_1}} {{HOST_2}}\n")

    def test_annotation_file_line_really_contains_placeholder(self):
        """Proves every annotation points to a real line/column holding its placeholder, public files carry no hashes or values, the private copy has hashes with mode 0600, and no private string appears in reports."""
        self.e.put("sample.py", SAMPLE)
        self.e.put("sub/other.txt", CRLF)
        self.e.scrub(["sample.py", "sub/other.txt"])
        ann = json.loads((self.e.staged() / "ANNOTATIONS.json").read_text())
        self.assertGreater(len(ann["replacements"]), 20)
        for r in ann["replacements"]:
            self.assertNotIn("hash", r)  # hashes stay private
            self.assertNotIn("value", r)
            if r["line"] == 0:
                continue
            line = lines_of(self.e.staged() / r["file"])[r["line"] - 1]
            self.assertEqual(line[r["column"] - 1:r["column"] - 1 + len(r["placeholder"])], r["placeholder"])
        priv = json.loads((self.e.restore.parent / "annotations.private" / "comp.json").read_text())
        self.assertEqual(len(priv["replacements"]), len(ann["replacements"]))
        for r in priv["replacements"]:
            self.assertEqual(len(r["hash"]), 32)
        self.assertEqual((self.e.restore.parent / "annotations.private" / "comp.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("hash", (self.e.staged() / "ANNOTATIONS.json").read_text())
        md = (self.e.staged() / "ANNOTATIONS.md").read_text()
        self.assertIn("| placeholder | meaning | what to put | file:line list |", md)
        for r in ann["replacements"]:
            if r["line"] > 0:
                self.assertIn("%s:" % r["file"], md)
                self.assertIn("{{%s" % r["key"], md)
        idx = (self.e.release / "staging" / "PLACEHOLDERS_INDEX.md").read_text()
        self.assertIn("`OWNER_NAME`", idx)
        for s in PRIVATE_STRINGS:
            for f in ("ANNOTATIONS.json", "ANNOTATIONS.md"):
                self.assertNotIn(s.lower(), (self.e.staged() / f).read_text().lower())
            self.assertNotIn(s.lower(), idx.lower())

    def test_deterministic_output(self):
        """Proves scrubbing is deterministic: manifest order and release location do not change the output bytes or modes."""
        self.e.put("sample.py", SAMPLE)
        self.e.put("sub/other.txt", CRLF)
        self.e.scrub(["sample.py", "sub/other.txt"])
        first = tree(self.e.staged())
        other = self.e.tmp / "release2"
        (other / "_privacy").mkdir(parents=True)
        (other / "_privacy" / "EXCLUDE_LIST.txt").write_text(_fx.EXCLUDES)
        self.e.scrub(["sub/other.txt", "sample.py"], release=other)
        self.assertEqual(first, tree(other / "staging" / "comp"))

    def test_restore_map_is_private_and_outside_release(self):
        """Proves the restore map is mode 0600, no secret is written inside the release tree, and a restore map path inside the release tree is rejected."""
        self.e.put("sample.py", SAMPLE)
        self.e.scrub(["sample.py"])
        self.assertEqual(self.e.restore.stat().st_mode & 0o777, 0o600)
        for p in self.e.release.rglob("*"):
            if p.is_file():
                self.assertNotIn(_fx.TOKEN, p.read_text())
        with self.assertRaises(sr.ScrubError):
            sr.build_component(self.e.manifest(["sample.py"]), self.e.values, self.e.release, self.e.src,
                               self.e.release / "restore.json")


class TestHotswap(Base):
    """Restore behaviour: round trips, partial values, safety checks."""
    def _full(self):
        """Scrub a representative set of synthetic files (incl. CRLF, an executable, an empty file, private names in paths); return the file list."""
        self.e.put("sample.py", SAMPLE)
        self.e.put("sub/other.txt", CRLF)
        self.e.put("notes_fakeuser9/readme_FAKEBOX-ALPHA.md", "# hi fakeuser9\n")
        self.e.put("bin/run.sh", "#!/bin/sh\necho Fakey McFakeface 10.20.30.40\n", mode=0o755)
        self.e.put("empty.txt", "")
        files = ["sample.py", "sub/other.txt", "notes_fakeuser9/readme_FAKEBOX-ALPHA.md", "bin/run.sh", "empty.txt"]
        self.e.scrub(files)
        return files

    def run_swap(self, out, values=None, **kw):
        """Call hotswap.run with the fixture paths; OUT is the target and keyword arguments override options."""
        return hotswap.run(self.e.staged(), values or self.e.values, out, kw.pop("restore", self.e.restore),
                           self.e.release, **kw)

    def test_round_trip_is_byte_identical(self):
        """Proves scrub followed by restore reproduces every original file byte for byte, with the same permission bits and no extra files, and that hashes verified."""
        files = self._full()
        out = self.e.tmp / "restored"
        code, summary = self.run_swap(out)
        self.assertEqual(code, 0)
        self.assertTrue(summary["verified_with_hashes"])
        self.assertEqual(summary["unresolved"], {})
        for rel in files:
            orig = self.e.src / rel
            got = out / rel
            self.assertTrue(got.is_file(), rel)
            self.assertEqual(got.read_bytes(), orig.read_bytes(), rel)
            # Owner bits (incl. executable) are kept; group/other bits are deliberately dropped (output holds real values).
            self.assertEqual(got.stat().st_mode & 0o700, (orig.stat().st_mode & 0o700) | 0o600, rel)
            self.assertEqual(got.stat().st_mode & 0o077, 0, rel)
        self.assertEqual(sorted(tree(out)), sorted(files))
        for d in [out] + [p for p in out.rglob("*") if p.is_dir()]:
            self.assertEqual(d.stat().st_mode & 0o777, 0o700, d)

    def test_public_example_salt_is_refused(self):
        """Proves a values file that still carries the public example salt is refused at load time."""
        self.e.write_values(VALUES, salt="EXAMPLE-ONLY-DO-NOT-USE-generate-your-own")
        with self.assertRaises(sr.ScrubError):
            sr.load_values(self.e.values, self.e.release)

    def test_output_is_private_even_with_a_permissive_umask(self):
        """Proves restored files and folders are 0600/0700 even when the process umask is 0 (real values inside)."""
        self._full()
        old = os.umask(0)
        try:
            code, _ = self.run_swap(self.e.tmp / "priv_out")
        finally:
            os.umask(old)
        self.assertEqual(code, 0)
        out = self.e.tmp / "priv_out"
        self.assertEqual((out / "sample.py").stat().st_mode & 0o777, 0o600)
        self.assertEqual((out / "bin" / "run.sh").stat().st_mode & 0o777, 0o700)
        self.assertEqual((out / "sub").stat().st_mode & 0o777, 0o700)

    def test_public_annotations_as_private_copy_is_a_clean_fatal(self):
        """Proves pointing --private-annotations at a folder holding a PUBLIC (hash-less) page gives a ScrubError, not a traceback."""
        self._full()
        bad = self.e.tmp / "badann"
        bad.mkdir()
        (bad / "comp.json").write_text('{"replacements": [{"key": "OWNER_HANDLE"}]}')
        with self.assertRaises(sr.ScrubError):
            self.run_swap(self.e.tmp / "o2", private_annotations=str(bad))

    def test_round_trip_through_cli(self):
        """Proves the hotswap command-line interface performs the same restore as the library call."""
        self._full()
        out = self.e.tmp / "restored_cli"
        r = subprocess.run([sys.executable, str(_fx.TOOLS / "hotswap.py"), "--component-dir", str(self.e.staged()),
                            "--values", str(self.e.values), "--restore", str(self.e.restore), "--out", str(out),
                            "--release-root", str(self.e.release)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((out / "sub/other.txt").read_bytes(), (self.e.src / "sub/other.txt").read_bytes())

    def test_refuses_unresolved_tokens_unless_allow_partial(self):
        """Proves missing values abort the restore (exit 1, nothing written) unless partial mode is requested, in which case unresolved placeholders are left in place."""
        self._full()
        flat = {"OWNER_NAME": "Some Other Person"}   # only one of many keys supplied
        vf = self.e.cfg / "mine.json"
        vf.write_text(json.dumps(flat))
        os.chmod(str(vf), 0o600)
        out = self.e.tmp / "partial"
        code, summary = self.run_swap(out, vf, restore=None)
        self.assertEqual(code, 1)
        self.assertIn("HOST_PRIMARY", summary["unresolved"])
        self.assertFalse(out.exists())
        code, summary = self.run_swap(out, vf, restore=None, allow_partial=True)
        self.assertEqual(code, 0)
        text = (out / "sample.py").read_text()
        self.assertIn("Some Other Person", text)
        self.assertIn("{{HOST_PRIMARY}}", text)

    def test_user_values_replace_and_case_variants_follow(self):
        """Proves user-chosen replacement values are applied and the upper/title variants follow from the base value."""
        self.e.put("a.txt", "x fakebox-alpha FAKEBOX-ALPHA y\n")
        self.e.scrub(["a.txt"])
        vf = self.e.cfg / "mine.json"
        vf.write_text(json.dumps({"{{HOST_PRIMARY}}": "my-host"}))   # key written in braces form
        os.chmod(str(vf), 0o600)
        out = self.e.tmp / "mine"
        code, _ = self.run_swap(out, vf, restore=None)
        self.assertEqual(code, 0)
        self.assertEqual((out / "a.txt").read_text(), "x my-host MY-HOST y\n")

    def test_dry_run_writes_nothing(self):
        """Proves a dry run counts replacements but creates no output."""
        self._full()
        out = self.e.tmp / "dry"
        code, summary = self.run_swap(out, dry_run=True)
        self.assertEqual(code, 0)
        self.assertGreater(summary["replacements"], 10)
        self.assertFalse(out.exists())

    def test_refuses_out_in_release_tree_nonempty_out_and_bad_perms(self):
        """Proves the restore refuses an output inside the release tree, a non-empty output directory, and a values file with loose permissions."""
        self._full()
        with self.assertRaises(sr.ScrubError):
            self.run_swap(self.e.release / "leak")
        with self.assertRaises(sr.ScrubError):
            self.run_swap(self.e.staged() / "inside")
        busy = self.e.tmp / "busy"
        busy.mkdir()
        (busy / "keep").write_text("x")
        with self.assertRaises(sr.ScrubError):
            self.run_swap(busy)
        os.chmod(str(self.e.values), 0o644)
        with self.assertRaises(sr.ScrubError):
            self.run_swap(self.e.tmp / "o2")

    def test_hash_verification_catches_wrong_value(self):
        """Proves a wrong replacement value for a restore-by-hash is detected and rejected."""
        self._full()
        wrong = dict(VALUES, HOST_PRIMARY="not-the-host")   # differs from what was scrubbed
        self.e.write_values(wrong)
        with self.assertRaises(sr.ScrubError):
            self.run_swap(self.e.tmp / "wrong")


class TestGate(Base):
    """Release gate behaviour on a clean staged tree and on tampered copies."""
    def _scrub_clean(self):
        """Scrub synthetic files into staging so the gate has a clean baseline."""
        self.e.put("sample.py", SAMPLE)
        self.e.put("sub/other.txt", CRLF)
        self.e.put("notes_fakeuser9/readme.md", "# hi fakeuser9\nplain text\n")
        self.e.scrub(["sample.py", "sub/other.txt", "notes_fakeuser9/readme.md"])

    def gate(self):
        """Run the gate in-process; return (exit code, captured stdout)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = release_gate.main(["--staging", str(self.e.release / "staging"), "--values", str(self.e.values),
                                      "--release-root", str(self.e.release)])
        return code, buf.getvalue()

    def inject(self, rel, text, binary=False):
        """Add content (text appended, or raw bytes written) to a staged file to simulate a leak."""
        p = self.e.staged() / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            p.write_bytes(text)
        else:
            with open(str(p), "a", encoding="utf-8") as fh:
                fh.write(text)

    def test_clean_fixture_passes(self):
        """Proves a correctly scrubbed tree passes the gate."""
        self._scrub_clean()
        code, out = self.gate()
        self.assertEqual(code, 0, out)
        self.assertIn("PASS", out)

    def test_catches_injected_private_value_without_printing_it(self):
        """Proves a private value hidden in a longer word is caught at the right file:line, and the gate output never repeats private strings."""
        self._scrub_clean()
        n = len(lines_of(self.e.staged() / "sub" / "other.txt"))
        self.inject("sub/other.txt", "\nsomething_FakeBox-Alpha_else")   # value embedded inside a word
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("sub/other.txt:%d: PRIVATE_VALUE[HOST_PRIMARY]" % (n + 1), out)
        for s in PRIVATE_STRINGS:
            self.assertNotIn(s.lower(), out.lower())

    def test_catches_single_word_of_a_value(self):
        """Proves a single word of a multi-word value (a surname alone) is also caught."""
        self._scrub_clean()
        self.inject("sample.py", "\nthanks mcfakeface!\n")
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("PRIVATE_VALUE[OWNER_NAME]", out)

    def test_catches_leftover_pattern_classes(self):
        """Proves leftover IPs, MACs, home paths and hostnames are flagged by class without printing them."""
        self._scrub_clean()
        self.inject("sample.py", "\nip 172.16.4.5 mac 11:22:33" + ":44:55:66 path /Users/somebody/x box" + ".local\n")
        code, out = self.gate()
        self.assertEqual(code, 1)
        for cls in ("LAN_IP", "MAC", "HOME_PATH", "HOSTNAME"):
            self.assertIn("PATTERN[%s]" % cls, out)
        self.assertNotIn("172.16.4.5", out)
        self.assertNotIn("somebody", out)

    def test_catches_private_key_block_binary_type_and_excluded_path(self):
        """Proves the gate flags private-key blocks, forbidden binary types and files under excluded paths."""
        self._scrub_clean()
        self.inject("key.txt", "-----BEGIN RSA " + "PRIVATE KEY-----\nzzz\n")
        self.inject("img.png", b"\x89PNG\r\n", binary=True)
        self.inject("blob.dat", b"ab\x00cd", binary=True)
        self.inject("private/ok.txt", "plain\n")
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("key.txt:1: PRIVATE_KEY", out)
        self.assertIn("img.png:0: REFUSED_TYPE", out)
        self.assertIn("blob.dat:0: REFUSED_TYPE", out)
        self.assertIn("private/ok.txt:0: EXCLUDE_LIST", out)

    def test_catches_private_value_in_file_name_and_annotations_tamper(self):
        """Proves a private value in a staged file NAME is flagged."""
        self._scrub_clean()
        self.inject("copy_of_fakeuser9.txt", "plain\n")
        code, out = self.gate()
        self.assertEqual(code, 1)
        # The gate must NOT echo a name that holds a private value: it prints a masked "path#<n>" instead.
        self.assertNotIn("fakeuser9", out)
        self.assertRegex(out, r"path#\d+:0: PRIVATE_VALUE\[OWNER_HANDLE\]")

    def test_gate_allow_strings_blanks_whole_words_only(self):
        """Proves the allow-strings setting forgives only the exact whole word, not longer words containing a private value."""
        self._scrub_clean()
        self.e.write_values(VALUES, gate_allow_strings=["fakeuser9tool"])
        self.inject("ok.txt", "run fakeuser9tool now\n")
        code, out = self.gate()
        self.assertEqual(code, 0, out)
        self.inject("bad.txt", "run fakeuser9tools now and fakeuser9\n")
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("bad.txt:1: PRIVATE_VALUE", out)

    def test_public_annotations_with_hash_fail_gate(self):
        """Proves the gate fails when the public annotation file contains hashes."""
        self._scrub_clean()
        ap = self.e.staged() / "ANNOTATIONS.json"
        ann = json.loads(ap.read_text())
        ann["replacements"].append({"key": "X", "hash": "0" * 32, "file": "a", "line": 1, "column": 1})
        ap.write_text(json.dumps(ann))
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("ANNOTATIONS.json:0: STRUCTURE[ANNOTATIONS.json contains hashes", out)

    def test_exclude_exception_from_manifest_is_honoured(self):
        """Proves a path that is excluded by policy but listed as an explicit exception passes the gate."""
        self.e.put("exports/z.txt", "plain\n")
        self.e.scrub(["exports/z.txt"], exclude_exceptions=["exports/z.txt"])
        code, out = self.gate()
        self.assertEqual(code, 0, out)

    def test_gate_refuses_bad_values_perms(self):
        """Proves the gate CLI exits 2 when the values file has loose permissions."""
        self._scrub_clean()
        os.chmod(str(self.e.values), 0o644)
        r = subprocess.run([sys.executable, str(_fx.TOOLS / "release_gate.py"), "--staging", str(self.e.release / "staging"),
                            "--values", str(self.e.values), "--release-root", str(self.e.release)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

class TestGatePublicPhrases(Base):
    """gate_public_phrases: whole, case-sensitive, word-bounded public phrases that overlap only WORKSPACE_NAME."""
    WS = dict(VALUES, WORKSPACE_NAME="Zorp_Works")   # the workspace key; the public company name is "Zorp Works"
    PH = ["Zorp Works", "Zorp Works Inc"]

    def setUp(self):
        """Scrub a clean baseline, then enable the phrase list for the workspace-name key."""
        super().setUp()
        self.e.put("a.txt", "plain\n")
        self.e.scrub(["a.txt"])
        self.e.write_values(self.WS, gate_public_phrases=self.PH)

    def run_gate(self, name, text):
        """Inject NAME with TEXT into staging, run the gate in-process; return (code, stdout)."""
        (self.e.staged() / name).write_text(text)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = release_gate.main(["--staging", str(self.e.release / "staging"), "--values", str(self.e.values),
                                      "--release-root", str(self.e.release)])
        return code, buf.getvalue()

    def test_phrase_allowed_in_license_line(self):
        """Proves the public phrase in a copyright line passes, and the split-punctuation hit is gone."""
        code, out = self.run_gate("LICENSE", "Copyright (c) 2026 Zorp Works\n")
        self.assertEqual(code, 0, out)
        # without the phrase list the same line is a WORKSPACE_NAME finding (baseline proves the feature is what fixes it)
        self.e.write_values(self.WS)
        code, out = self.run_gate("LICENSE", "Copyright (c) 2026 Zorp Works\n")
        self.assertEqual(code, 1)
        self.assertIn("PRIVATE_VALUE[WORKSPACE_NAME", out)

    def test_owner_and_host_still_caught_adjacent_to_phrase(self):
        """Proves an owner name or host written right next to the phrase is still found."""
        for text in ("Zorp Works Fakey McFakeface\n", "Fakey McFakeface Zorp Works\n", "Zorp Works fakebox-alpha\n",
                     "fakebox-alpha-Zorp Works\n", "Zorp Works fakeuser9\n"):
            code, out = self.run_gate("n.txt", text)
            self.assertEqual(code, 1, text)
            self.assertIn("n.txt:1: PRIVATE_VALUE", out)
            self.assertNotIn("WORKSPACE_NAME", out)

    def test_overlapping_phrase_refused(self):
        """Proves a phrase containing, inside, or sharing a word with a non-workspace value stops the gate (exit 2)."""
        for bad in ("Fakey McFakeface", "McFakeface", "Fakey McFakeface Zorp Works", "my fakebox-alpha box",
                    "Fakecorp Group"):
            self.e.write_values(self.WS, gate_public_phrases=[bad])
            with self.assertRaises(sr.ScrubError, msg=bad):
                sr.load_values(str(self.e.values), str(self.e.release))
        for bad in ("short", "", " Zorp Works", "Zorp Works "):
            self.e.write_values(self.WS, gate_public_phrases=[bad])
            with self.assertRaises(sr.ScrubError, msg=repr(bad)):
                sr.load_values(str(self.e.values), str(self.e.release))
        self.e.write_values(self.WS, gate_public_phrases=["Zorp Works"])
        self.assertTrue(sr.load_values(str(self.e.values), str(self.e.release)).public_re)

    def test_case_sensitive(self):
        """Proves only the exact case is blanked; other cases are still findings."""
        for text in ("zorp works\n", "ZORP WORKS\n", "Zorp works\n"):
            code, out = self.run_gate("c.txt", text)
            self.assertEqual(code, 1, text)
            self.assertIn("PRIVATE_VALUE[WORKSPACE_NAME", out)

    def test_word_boundaries(self):
        """Proves the phrase is never blanked inside a longer token, but is blanked next to punctuation."""
        for text in ("Zorp Worksx\n", "xZorp Works\n", "Zorp Works9\n", "9Zorp Works\n", "Zorp_Works\n"):
            code, out = self.run_gate("b.txt", text)
            self.assertEqual(code, 1, text)
        for text in ("(Zorp Works)\n", "\"Zorp Works\",\n", "Zorp Works.\n"):
            code, out = self.run_gate("b.txt", text)
            self.assertEqual(code, 0, (text, out))

    def test_longer_phrase_wins(self):
        """Proves 'Zorp Works Inc' is blanked as a whole (longest phrase first)."""
        code, out = self.run_gate("l.txt", "Zorp Works Inc\n")
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
