"""Tests for the unified release pipeline: allowlist, prefix renames, structural patterns, carrier scanning in the
verifier, syntax gate, the one-command runner (release.py), the placeholder-leak script and the fresh git init.

ALL fixtures are SYNTHETIC (invented names, hosts, numbers).  Secret shapes are assembled from pieces so this file
itself contains no real-looking credential.  Run from the tools directory:

    python3 -m unittest discover -s tests -v

Several tests here are ports of the scenarios of the retired first stack (scrub.py/verify.py/test_toolchain.py):
variants (url-encoded, base64, split-by-punctuation), "git directory flagged", "harmless values pass", "source tree
never modified", "rules/map must live outside the output".  They now run against release_gate.py / release.py.
"""
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from urllib.parse import quote

import _fx
from _fx import Env, VALUES, SALT, tree

import allowlist as al
import release
import release_gate
import scrub_release as sr
import syntax_check

# A fake secret that is deliberately present in a test fixture (shape of a GitHub token, all one repeated letter).
FIX = "ghp_" + "Q" * 36
FIX2 = "AKIA" + "QQQQQQQQQQQQQQQQ"


def sha(b):
    """sha256 hex of bytes B."""
    return hashlib.sha256(b).hexdigest()


def write_allow(env, **doc):
    """Write an allowlist JSON next to the env and return its path."""
    p = env.tmp / "allow.json"
    doc.setdefault("version", 1)
    p.write_text(json.dumps(doc))
    return p


class PipelineBase(unittest.TestCase):
    """Env plus helpers to run the gate and the one-command runner quietly."""

    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.cleanup)
        self.out = self.e.tmp / "OUT"

    def args(self, files, allow=None, extra=(), component="comp"):
        """Argument list for release.py over FILES."""
        mp = self.e.manifest(files, component)
        argv = ["--manifest", str(mp), "--rules", str(self.e.values), "--out", str(self.out),
                "--source-root", str(self.e.src), "--release-root", str(self.e.release),
                "--restore-map", str(self.e.restore)]
        if allow:
            argv += ["--allowlist", str(allow)]
        return argv + list(extra)

    def release(self, files, allow=None, extra=()):
        """Run release.main; -> (exit code, printed text)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = release.main(self.args(files, allow, extra))
        return code, buf.getvalue()

    def gate_dir(self, root, allow=None, **kw):
        """Run the gate library function on ROOT; -> findings list."""
        pv = sr.load_values(self.e.values, self.e.release)
        a = al.load_allowlist(allow, pv.flat.values()) if allow else None
        return release_gate.gate(root, pv, self.e.release, (), a, **kw)[1]

    def cats(self, findings):
        """Set of 'CATEGORY[detail]' strings for quick membership asserts."""
        return {"%s[%s]" % (f[0], f[1]) if f[1] else f[0] for f in findings}


# ------------------------------------------------------------------------------------------------ allowlist (d)
class TestAllowlist(PipelineBase):
    def test_fixture_string_survives_scrub_and_gate_but_only_where_listed(self):
        """A listed fake secret stays byte-for-byte in the listed file; the same string elsewhere is replaced."""
        self.e.put("tests/test_scan.py", 'FAKE = "%s"\nHOME = "/Users/fakeuser9/x"\n' % FIX)
        self.e.put("src/other.py", 'LEAK = "%s"\n' % FIX)
        allow = write_allow(self.e, fixtures=[{"path": "tests/test_scan.py", "strings": [FIX], "reason": "detector input"}])
        pv_allow = al.load_allowlist(allow)
        sr.build_component(self.e.manifest(["tests/test_scan.py", "src/other.py"]), self.e.values, self.e.release,
                           self.e.src, self.e.restore, stage_root=self.out, allow=pv_allow)
        fixture = (self.out / "comp" / "tests" / "test_scan.py").read_text()
        self.assertIn(FIX, fixture)                       # untouched: the test keeps working
        self.assertIn("{{HOME_DIR_1}}", fixture)          # but real-shaped data in the same file is still scrubbed
        self.assertNotIn(FIX, (self.out / "comp" / "src" / "other.py").read_text())

    def test_gate_ignores_fixture_but_flags_same_string_in_unlisted_file(self):
        """Verification treats a listed fixture as fixture and the identical string in another file as a leak."""
        self.e.put("a.py", "x = 1\n")
        self.e.scrub(["a.py"])
        comp = self.e.staged()
        (comp / "t.py").write_text('F = "%s"\n' % FIX)
        (comp / "u.py").write_text('F = "%s"\n' % FIX)
        allow = write_allow(self.e, fixtures=[{"path": "t.py", "strings": [FIX], "reason": "fixture"}])
        found = release_gate.gate(comp.parent, sr.load_values(self.e.values, self.e.release), self.e.release, (),
                                  al.load_allowlist(allow))[1]
        files = {f[2] for f in found}
        self.assertIn("comp/u.py", files)
        self.assertNotIn("comp/t.py", files)

    def test_allowlist_cannot_whitelist_a_private_value(self):
        """A fixture string overlapping an owner value is refused at load time."""
        bad = write_allow(self.e, fixtures=[{"path": "a.py", "strings": ["fakebox-alpha-extra"], "reason": "x"}])
        with self.assertRaises(al.AllowlistError):
            al.load_allowlist(bad, VALUES.values())

    def test_allowlist_rejects_unknown_keys_missing_reason_and_short_strings(self):
        for doc in ({"bogus": 1}, {"fixtures": [{"path": "a", "strings": ["abcdefgh"]}]},
                    {"fixtures": [{"path": "a", "strings": ["abc"], "reason": "r"}]},
                    {"approved_binaries": [{"sha256": "zz", "reason": "r"}]}):
            with self.subTest(doc=doc), self.assertRaises(al.AllowlistError):
                al.Allowlist(doc)

    def test_private_value_partly_overlapping_fixture_refuses_file(self):
        """Cannot both keep a fixture intact and replace part of it: the file is refused, not half-scrubbed."""
        fx = "xx_fakeuser9_yyyy"      # contains the private handle
        self.e.put("t.py", "A = '%s'\n" % fx)
        # the allowlist loader itself refuses this (overlap), so go through Allowlist without private values
        allow = al.Allowlist({"fixtures": [{"path": "t.py", "strings": [fx], "reason": "r"}]})
        res = sr.build_component(self.e.manifest(["t.py"]), self.e.values, self.e.release, self.e.src, self.e.restore,
                                 stage_root=self.out, allow=allow)
        self.assertEqual(res["copied"], 1)       # whole private value lies INSIDE the fixture: left alone
        # now a private value that only PARTLY overlaps the fixture string (fixture starts inside the value)
        self.e.put("t3.py", "C = 'fakeuser9_yyyy_zz'\n")
        allow3 = al.Allowlist({"fixtures": [{"path": "t3.py", "strings": ["user9_yyyy_zz"], "reason": "r"}]})
        res = sr.build_component(self.e.manifest(["t3.py"]), self.e.values, self.e.release, self.e.src, self.e.restore,
                                 stage_root=self.out, allow=allow3)
        self.assertEqual(res["copied"], 0)
        self.assertIn("overlaps an allowlisted fixture", res["refused_list"][0]["reason"])


# ------------------------------------------------------------------------------------------------ prefix rename (1)
class TestRenamePrefixes(PipelineBase):
    def setUp(self):
        super().setUp()
        self.e.write_values(VALUES, rename_prefixes={"zorvin_": "zv_", "acme-zorvin-": "zv-"})

    def test_names_dirs_and_content_follow_the_prefix_rules(self):
        """File, directory and every reference to the namespace are renamed consistently; counts and tokens intact."""
        self.e.put("scripts/zorvin_cli.py", "import zorvin_util\nfrom zorvin_util import f\nUNIT='acme-zorvin-sync'\n")
        self.e.put("scripts/zorvin_util.py", "def f(): pass\n")
        self.e.put("zorvin_pkg/zorvin_mod.py", "ZORVIN_FLAG = 1\nname = 'fakeuser9'\n")
        res = self.e.scrub(["scripts/zorvin_cli.py", "scripts/zorvin_util.py", "zorvin_pkg/zorvin_mod.py"])
        self.assertEqual(res["refused"], 0)
        c = self.e.staged()
        self.assertTrue((c / "scripts" / "zv_cli.py").is_file())
        self.assertTrue((c / "zv_pkg" / "zv_mod.py").is_file())
        txt = (c / "scripts" / "zv_cli.py").read_text()
        self.assertEqual(txt, "import zv_util\nfrom zv_util import f\nUNIT='zv-sync'\n")
        self.assertEqual((c / "zv_pkg" / "zv_mod.py").read_text(), "ZV_FLAG = 1\nname = '{{OWNER_HANDLE}}'\n")
        for p in c.rglob("*"):
            self.assertNotIn("zorvin", p.as_posix().lower())

    def test_prefix_only_at_word_start(self):
        """'nzorvin_x' (prefix inside a longer word) is not touched."""
        self.e.put("a.txt", "nzorvin_x and zorvin_y\n")
        self.e.scrub(["a.txt"])
        self.assertEqual((self.e.staged() / "a.txt").read_text(), "nzorvin_x and zv_y\n")

    def test_mixed_case_prefix_is_refused(self):
        self.e.put("a.txt", "Zorvin_Thing\n")
        res = self.e.scrub(["a.txt"])
        self.assertEqual(res["copied"], 0)
        self.assertIn("mixed-case variant of a rename prefix", res["refused_list"][0]["reason"])

    def test_replacement_may_not_carry_a_private_value(self):
        self.e.write_values(VALUES, rename_prefixes={"zorvin_": "fakeuser9_"})
        self.e.put("a.txt", "x\n")
        with self.assertRaises(sr.ScrubError):
            self.e.scrub(["a.txt"])

    def test_bad_rule_shapes(self):
        for bad in ({"ab": "x"}, {"zorvin_": "bad/char"}, ["zorvin_"]):
            self.e.write_values(VALUES, rename_prefixes=bad)
            self.e.put("a.txt", "x\n")
            with self.subTest(bad=bad), self.assertRaises(sr.ScrubError):
                self.e.scrub(["a.txt"])


# ------------------------------------------------------------------------------------------------ structural regexes (c)
class TestStructuralPatterns(PipelineBase):
    def scrub_text(self, text):
        self.e.put("t.txt", text)
        self.e.scrub(["t.txt"])
        return (self.e.staged() / "t.txt").read_text()

    def test_phone_ein_uei_duns_variants(self):
        out = self.scrub_text("call (415) 867-5309 or +14155550123 or tel: 4155550123\n"
                              "EIN 12-3456789 / EIN: 123456789\nUEI: ABCDE12345FG\nDUNS number 123456789 and D-U-N-S 12-345-6789\n")
        for raw in ("415) 867-5309", "+14155550123", "4155550123", "12-3456789", "123456789", "ABCDE12345FG", "12-345-6789"):
            self.assertNotIn(raw, out)
        for tok in ("{{PHONE_1}}", "{{PHONE_2}}", "{{PHONE_3}}", "{{EIN_1}}", "{{EIN_2}}", "{{UEI_1}}", "{{DUNS_1}}", "{{DUNS_2}}"):
            self.assertIn(tok, out)

    def test_local_and_tailnet_names(self):
        out = self.scrub_text("ssh box-a" + ".local\nhttps://mini.tailnet-1234.ts.net:8443/x\nold node.foo.beta.tailscale.net\n")
        self.assertNotIn(".local", out)
        self.assertNotIn("ts.net", out)
        self.assertNotIn("tailscale.net", out)
        self.assertIn("{{HOST_1}}", out)
        self.assertIn("{{TAILNET_HOST_1}}", out)
        self.assertIn("{{TAILNET_HOST_2}}", out)

    def test_syncthing_device_id_shape(self):
        did = "-".join(["ABCDEF%d" % i for i in range(8)])
        self.assertIn("{{SYNCTHING_DEVICE_1}}", self.scrub_text("device %s ok\n" % did))

    def test_things_that_must_not_match(self):
        keep = "version 1.2.3 build 20261121 pid 1234567890123 example.com localhost phone 555 EIN\n"
        self.assertEqual(self.scrub_text(keep), keep)

    def test_backup_and_conflict_copies_are_refused(self):
        for n in ("x.sync-conflict-20260101-ABC.py", "cfg.before", "cfg.json.candidate", "n.prior", "a.py~"):
            self.e.put(n, "x = 1\n")
        res = self.e.scrub(["x.sync-conflict-20260101-ABC.py", "cfg.before", "cfg.json.candidate", "n.prior", "a.py~"])
        self.assertEqual(res["copied"], 0)
        self.assertEqual(res["refused"], 5)


# ------------------------------------------------------------------------------------------------ verifier: variants
class TestVerifyVariants(PipelineBase):
    """Ports of the retired verify.py variant tests."""

    def planted(self, line):
        self.e.put("a.txt", "fine\n")
        self.e.scrub(["a.txt"])
        (self.e.staged() / "planted.txt").write_text("ok line\n" + line + "\n")
        return self.gate_dir(self.e.release / "staging")

    def assert_hit(self, line, label):
        found = self.planted(line)
        hits = [f for f in found if f[2] == "comp/planted.txt" and f[0] == "PRIVATE_VALUE"]
        self.assertTrue(any(label in f[1] for f in hits), (label, found))
        self.assertTrue(all(f[3] == 2 for f in hits))

    def test_urlencoded(self):
        self.assert_hit("?q=" + quote(_fx.VALUES["OWNER_NAME"]), "urlencoded")

    def test_base64_aligned_and_embedded(self):
        v = _fx.VALUES["ORG_NAME"].encode()
        self.assert_hit(base64.b64encode(v).decode(), "base64")
        self.assert_hit(base64.b64encode(b"xx" + v + b"yyy").decode(), "base64")
        self.assert_hit(base64.urlsafe_b64encode(b"?" + v).decode(), "base64")

    def test_split_by_punctuation(self):
        self.assert_hit("fakey.mcfakeface", "split-punctuation")
        self.assert_hit("fakey_mcfakeface", "split-punctuation")
        self.assert_hit("FakeyMcFakeface", "split-punctuation")

    def test_harmless_values_pass(self):
        """example.com mail, loopback, shared home folder are not findings."""
        self.assertEqual([f for f in self.planted("me@example.com 127.0.0.1 /Users/Shared") if f[2].endswith("planted.txt")], [])

    def test_git_directory_is_flagged(self):
        self.e.put("a.txt", "fine\n")
        self.e.scrub(["a.txt"])
        (self.e.staged() / ".git").mkdir()
        (self.e.staged() / ".git" / "config").write_text("[core]\n")
        self.assertIn("STRUCTURE[git metadata in tree]", self.cats(self.gate_dir(self.e.release / "staging")))


# ------------------------------------------------------------------------------------------------ verifier: carriers (a)
class TestCarriers(PipelineBase):
    def setUp(self):
        super().setUp()
        self.e.put("a.txt", "fine\n")
        self.e.scrub(["a.txt"])
        self.root = self.e.release / "staging"
        self.comp = self.e.staged()

    def check(self, **kw):
        return self.gate_dir(self.root, **kw)

    def test_gzip_is_decompressed_and_scanned(self):
        (self.comp / "x.txt.gz").write_bytes(gzip.compress(b"hello fakebox-alpha there\n"))
        c = self.cats(self.check())
        self.assertIn("PRIVATE_VALUE[HOST_PRIMARY]", c)
        self.assertIn("REFUSED_TYPE[refused file type (.gz)]", c)

    def test_nested_gzip_in_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("inner.txt.gz", gzip.compress(b"owner fakeuser9@fakecorp.test\n"))
        (self.comp / "n.zip").write_bytes(buf.getvalue())
        c = self.cats(self.check())
        self.assertTrue(any(x.startswith("PRIVATE_VALUE[member#1:") for x in c), c)

    def test_docx_and_xlsx_contents_and_author_metadata(self):
        for name, member in (("d.docx", "word/document.xml"), ("s.xlsx", "xl/sharedStrings.xml")):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("[Content_Types].xml", "<Types/>")
                z.writestr(member, "<t>contact fakey mcfakeface today</t>")
                z.writestr("docProps/core.xml", '<cp:coreProperties xmlns:cp="x" xmlns:dc="y"><dc:creator>Some Person</dc:creator>'
                           '<cp:lastModifiedBy>Some Person</cp:lastModifiedBy></cp:coreProperties>')
            (self.comp / name).write_bytes(buf.getvalue())
        c = self.cats(self.check())
        self.assertIn("METADATA[office:dc:creator]", c)
        self.assertIn("METADATA[office:cp:lastModifiedBy]", c)
        self.assertTrue(any(x.startswith("PRIVATE_VALUE[member#2:OWNER_NAME") for x in c), c)

    def test_neutral_author_is_not_flagged(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("docProps/core.xml", "<c><dc:creator>Release</dc:creator><cp:lastModifiedBy></cp:lastModifiedBy></c>")
        (self.comp / "ok.docx").write_bytes(buf.getvalue())
        self.assertNotIn("METADATA", " ".join(self.cats(self.check())))

    def test_zip_member_name_is_never_printed_and_zip_slip_flagged(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("notes_fakeuser9.txt", "x")
            z.writestr("../evil.txt", "x")
        (self.comp / "z.zip").write_bytes(buf.getvalue())
        found = self.check()
        c = self.cats(found)
        self.assertIn("PRIVATE_VALUE[member#1:OWNER_HANDLE]", c)
        self.assertIn("CARRIER[member#2:unsafe member name]", c)
        self.assertNotIn("fakeuser9", repr(found).lower())

    def test_gzip_bomb_is_capped(self):
        old = release_gate.MAX_MEMBER_BYTES
        release_gate.MAX_MEMBER_BYTES = 1024 * 1024
        try:
            (self.comp / "bomb.gz").write_bytes(gzip.compress(b"\0" * (8 * 1024 * 1024)))
            self.assertIn("CARRIER[gzip expands beyond the size cap]", self.cats(self.check()))
        finally:
            release_gate.MAX_MEMBER_BYTES = old

    def test_sqlite_flagged_and_strings_scanned(self):
        db = self.comp / "d.sqlite"
        con = sqlite3.connect(str(db))
        con.execute("create table t(x text)")
        con.execute("insert into t values ('fakebox-alpha')")
        con.commit()
        con.close()
        c = self.cats(self.check())
        self.assertIn("REFUSED_TYPE[refused file type (.sqlite)]", c)
        self.assertIn("PRIVATE_VALUE[HOST_PRIMARY]", c)

    def test_pdf_flagged_metadata_and_inflated_stream(self):
        body = zlib_compress(b"BT (call fakeuser9 now) Tj ET")
        pdf = (b"%PDF-1.4\n1 0 obj << /Author (Some Person) /Title () >> endobj\n2 0 obj stream\n" + body + b"\nendstream\n%%EOF\n")
        (self.comp / "p.pdf").write_bytes(pdf)
        c = self.cats(self.check())
        self.assertIn("REFUSED_TYPE[refused file type (.pdf)]", c)
        self.assertIn("METADATA[pdf:/Author]", c)
        self.assertIn("PRIVATE_VALUE[OWNER_HANDLE]", c)

    def test_other_binary_flagged_unless_hand_approved_by_hash(self):
        data = b"\x00\x01\x02 harmless bytes"
        (self.comp / "b.dat").write_bytes(data)
        self.assertIn("REFUSED_TYPE[binary content (NUL byte)]", self.cats(self.check()))
        allow = write_allow(self.e, approved_binaries=[{"sha256": sha(data), "path": "b.dat", "reason": "reviewed"}])
        self.assertEqual(self.check(allow=allow), [])
        # approval is by content hash: changed bytes are no longer approved
        (self.comp / "b.dat").write_bytes(data + b"!")
        self.assertIn("REFUSED_TYPE[binary content (NUL byte)]", self.cats(self.check(allow=allow)))

    def test_approved_binary_is_still_searched_for_private_values(self):
        data = b"\x00\x01 contains fakebox-alpha inside"
        (self.comp / "b.dat").write_bytes(data)
        allow = write_allow(self.e, approved_binaries=[{"sha256": sha(data), "reason": "reviewed"}])
        c = self.cats(self.check(allow=allow))
        self.assertIn("PRIVATE_VALUE[HOST_PRIMARY]", c)
        self.assertFalse(any(x.startswith("REFUSED_TYPE") for x in c))

    def test_approved_binary_is_copied_by_scrub_with_renamed_name(self):
        data = b"\x00\x01 clean bytes"
        self.e.put("blobs/fakeuser9_data.dat", data, binary=True)
        allow = al.Allowlist({"approved_binaries": [{"sha256": sha(data), "reason": "reviewed"}]})
        res = sr.build_component(self.e.manifest(["blobs/fakeuser9_data.dat"], "c2"), self.e.values, self.e.release,
                                 self.e.src, self.e.restore, stage_root=self.out, allow=allow)
        self.assertEqual((res["copied"], res["refused"]), (1, 0))
        self.assertEqual((self.out / "c2" / "blobs" / "{{OWNER_HANDLE}}_data.dat").read_bytes(), data)
        # an unapproved binary is still refused
        self.e.put("other.dat", b"\x00zz", binary=True)
        res = sr.build_component(self.e.manifest(["other.dat"], "c3"), self.e.values, self.e.release, self.e.src,
                                 self.e.restore, stage_root=self.out, allow=allow)
        self.assertEqual(res["refused"], 1)


def zlib_compress(b):
    import zlib
    return zlib.compress(b)


# ------------------------------------------------------------------------------------------------ syntax gate (e)
class TestSyntax(PipelineBase):
    def test_each_validator_accepts_good_and_rejects_bad(self):
        good = {"python": "x = '{{HOST_1}}'\n", "json": '{"a": "{{HOST_1}}"}', "bash": "echo '{{HOST_1}}'\n",
                "plist": '<?xml version="1.0"?><plist version="1.0"><dict><key>a</key><string>{{HOST_1}}</string></dict></plist>',
                "xml": "<a>{{HOST_1}}</a>"}
        bad = {"python": "def (:\n", "json": '{"a": }', "bash": "if then fi (\n", "plist": "<plist><dict></plist>", "xml": "<a><b></a>"}
        for k in good:
            with self.subTest(kind=k):
                self.assertTrue(syntax_check.validate(k, syntax_check.render(good[k]))[0])
                self.assertFalse(syntax_check.validate(k, bad[k])[0])

    def test_xml_dtd_is_refused(self):
        self.assertFalse(syntax_check.validate("xml", '<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>')[0])

    def test_rewrite_that_breaks_code_is_caught_and_blamed(self):
        """A private value used as a bare identifier: source parses, scrubbed output would not."""
        self.e.put("m.py", "fakeuser9 = 1\nprint(fakeuser9 + 1)\n")
        # source parses; after scrub it is "{{OWNER_HANDLE}} = 1": rendered 'placeholderx = 1' still parses!  So use
        # a position where a value can never work: inside a number literal context.
        self.e.put("n.py", "x = 3.fakeuser9\n")
        self.e.put("j.json", '{"k": fakeuser9}\n')
        res = self.e.scrub(["m.py", "n.py", "j.json"])
        n, bad = syntax_check.check_tree(res["comp_dir"], self.e.src, res["file_map"])
        kinds = {(b[0], b[2]) for b in bad}
        self.assertNotIn(("BROKEN_BY_REWRITE", "m.py"), kinds)       # identifier swap stays valid
        self.assertIn(("SOURCE_INVALID", "n.py"), kinds)              # source was already broken
        self.assertIn(("SOURCE_INVALID", "j.json"), kinds)

    def test_rewrite_breaking_valid_source_is_BROKEN_BY_REWRITE(self):
        """json: a string value that is a bare token ('"{{X}}"' ok) vs a prefix rename producing an invalid name."""
        self.e.write_values(VALUES, rename_prefixes={"zorvin_": "zv-"})
        self.e.put("p.py", "import zorvin_x\n")             # becomes 'import zv-x' : invalid Python
        res = self.e.scrub(["p.py"])
        n, bad = syntax_check.check_tree(res["comp_dir"], self.e.src, res["file_map"])
        self.assertEqual([(b[0], b[2]) for b in bad], [("BROKEN_BY_REWRITE", "p.py")])

    def test_exempt_by_allowlist(self):
        self.e.put("n.py", "x = 3.fakeuser9\n")
        res = self.e.scrub(["n.py"])
        allow = al.Allowlist({"syntax_exempt": [{"path": "n.py", "reason": "deliberately invalid"}]})
        self.assertEqual(syntax_check.check_tree(res["comp_dir"], self.e.src, res["file_map"], allow)[1], [])

    def test_shebang_script_without_extension_is_checked(self):
        self.e.put("tool", "#!/bin/bash\nif [ 1 ]; then\n")
        res = self.e.scrub(["tool"])
        bad = syntax_check.check_tree(res["comp_dir"], self.e.src, res["file_map"])[1]
        self.assertEqual([b[1] for b in bad], ["bash"])


# ------------------------------------------------------------------------------------------------ release.py (f, g)
class TestReleaseRunner(PipelineBase):
    def good_src(self):
        self.e.put("tests/test_det.py", 'FAKE = "%s"\n' % FIX)
        self.e.put("scripts/zorvin_run.sh", "#!/bin/bash\necho hi from fakebox-alpha\n", mode=0o755)
        self.e.put("docs/notes.md", "# notes\nowner fakeuser9 at 10.20.30.40\n")
        self.e.put("cfg/app.json", '{"host": "fakebox-alpha"}\n')
        self.e.write_values(VALUES, rename_prefixes={"zorvin_": "zv_"})
        return ["tests/test_det.py", "scripts/zorvin_run.sh", "docs/notes.md", "cfg/app.json"]

    def allow(self):
        return write_allow(self.e, fixtures=[{"path": "tests/*.py", "strings": [FIX], "reason": "detector fixture"}])

    def test_full_pass_makes_one_neutral_commit_and_never_touches_source(self):
        files = self.good_src()
        before = tree(self.e.src)
        code, out = self.release(files, self.allow())
        self.assertEqual(code, 0, out)
        for name in ("scrub", "annotations", "syntax", "verify", "placeholders", "git"):
            self.assertRegex(out, r"step %s\s+PASS" % name)
        self.assertEqual(before, tree(self.e.src))                       # source byte-identical, modes included
        self.assertTrue((self.out / "comp" / "scripts" / "zv_run.sh").is_file())
        self.assertIn(FIX, (self.out / "comp" / "tests" / "test_det.py").read_text())
        # git: exactly one commit, neutral identity, fixed date, no remote
        g = lambda *a: subprocess.run(["git", "-C", str(self.out)] + list(a), capture_output=True, text=True).stdout.strip()
        self.assertEqual(g("rev-list", "--all", "--count"), "1")
        self.assertEqual(g("log", "-1", "--format=%an|%ae|%cn|%ce|%s|%aI"),
                         "Release Author|release@example.invalid|Release Author|release@example.invalid|"
                         "Initial release snapshot|2000-01-01T00:00:00Z")
        self.assertEqual(g("remote"), "")
        self.assertEqual(g("status", "--porcelain"), "")
        # private restore data never landed in the repo
        self.assertNotIn("fakeuser9", g("ls-files").lower())

    def test_leak_fails_every_gate_and_skips_git(self):
        """A mixed-case variant makes the scrub refuse the file: nonzero exit, no repo."""
        files = self.good_src()
        self.e.put("docs/notes.md", "FaKeUsEr9 here\n")
        code, out = self.release(files, self.allow())
        self.assertEqual(code, 1, out)
        self.assertRegex(out, r"step scrub\s+FAIL")
        self.assertRegex(out, r"step git\s+FAIL.*not run")
        self.assertFalse((self.out / ".git").exists())
        self.assertNotIn("fakeuser9", out.lower())

    def test_allow_refused_flag(self):
        files = self.good_src()
        self.e.put("docs/notes.md", "FaKeUsEr9 here\n")
        code, out = self.release(files, self.allow(), ["--allow-refused"])
        self.assertEqual(code, 0, out)

    def test_verify_failure_is_nonzero(self):
        """A value the scrubber cannot know (word of a value in a new spelling) but the gate does: fails verify."""
        files = self.good_src()
        self.e.put("docs/notes.md", "thanks to mcfakeface\n")      # last word of OWNER_NAME alone: not an exact value
        code, out = self.release(files, self.allow())
        self.assertEqual(code, 1, out)
        self.assertRegex(out, r"step verify\s+FAIL")
        self.assertIn("PRIVATE_VALUE[OWNER_NAME]", out)
        self.assertFalse((self.out / ".git").exists())

    def test_syntax_failure_is_nonzero(self):
        files = self.good_src()
        self.e.put("cfg/app.json", '{"host": }\n')
        code, out = self.release(files, self.allow())
        self.assertEqual(code, 1, out)
        self.assertRegex(out, r"step syntax\s+FAIL")

    def test_setup_errors_exit_2_and_write_nothing(self):
        files = self.good_src()
        os.chmod(str(self.e.values), 0o644)                         # bad rules permissions
        code, out = self.release(files, self.allow())
        self.assertEqual(code, 2)
        self.assertFalse(self.out.exists())
        os.chmod(str(self.e.values), 0o600)
        self.out.mkdir()
        (self.out / "x").write_text("x")                            # non-empty OUT is never overwritten
        self.assertEqual(self.release(files, self.allow())[0], 2)

    def test_rules_inside_out_and_overlap_refused(self):
        """Ports of 'rules/map must be outside the output' and 'out nested in source'."""
        files = self.good_src()
        inside = self.out / "rules.json"
        self.out.mkdir()
        inside.write_text(self.e.values.read_text())
        os.chmod(str(inside), 0o600)
        buf = io.StringIO()
        argv = self.args(files, self.allow())
        argv[argv.index("--rules") + 1] = str(inside)
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
            self.assertEqual(release.main(argv), 2)
        inside.unlink()
        self.out = self.e.src / "nested_out"                        # OUT inside the source
        self.assertEqual(self.release(files, self.allow())[0], 2)

    def test_cli_runs_as_one_command(self):
        files = self.good_src()
        r = subprocess.run([sys.executable, str(_fx.TOOLS / "release.py")] + self.args(files, self.allow()),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("release: PASS", r.stdout)

    def test_no_git_flag(self):
        files = self.good_src()
        code, out = self.release(files, self.allow(), ["--no-git"])
        self.assertEqual(code, 0, out)
        self.assertFalse((self.out / ".git").exists())

    def test_git_identity_ignores_user_config(self):
        """Even with a hostile global git config the commit carries only the neutral identity."""
        files = self.good_src()
        cfg = self.e.tmp / "gitconfig"
        cfg.write_text("[user]\n\tname = Real Person\n\temail = real@person.test\n")
        old = os.environ.get("GIT_CONFIG_GLOBAL")
        os.environ["GIT_CONFIG_GLOBAL"] = str(cfg)
        try:
            code, out = self.release(files, self.allow())
        finally:
            if old is None:
                del os.environ["GIT_CONFIG_GLOBAL"]
            else:
                os.environ["GIT_CONFIG_GLOBAL"] = old
        self.assertEqual(code, 0, out)
        who = subprocess.run(["git", "-C", str(self.out), "log", "-1", "--format=%an %ae"], capture_output=True, text=True,
                             env={"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": os.devnull}).stdout.strip()
        self.assertEqual(who, "Release Author release@example.invalid")


# ------------------------------------------------------------------------------------------------ shell leak check
class TestPlaceholderScript(PipelineBase):
    SCRIPT = str(_fx.TOOLS / "templates" / "check_placeholders.sh")

    def run_script(self, root, *extra, env=None):
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run(["bash", self.SCRIPT, str(root)] + list(extra), capture_output=True, text=True, env=e)

    def test_path_argument_and_plain_mode_flags_any_token(self):
        d = self.e.tmp / "t"
        d.mkdir()
        (d / "a.md").write_text("hello {{HOST_1}}\n")
        r = self.run_script(d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("unfilled", r.stdout)
        # run from a different cwd: the path argument alone decides what is scanned
        self.assertEqual(subprocess.run(["bash", self.SCRIPT, str(self.e.tmp)], capture_output=True, text=True,
                                        cwd="/").returncode, 1)

    def test_clean_directory_passes_and_bad_path_is_usage_error(self):
        d = self.e.tmp / "clean"
        d.mkdir()
        (d / "a.md").write_text("nothing here\n")
        self.assertEqual(self.run_script(d).returncode, 0)
        self.assertEqual(self.run_script(self.e.tmp / "missing").returncode, 2)

    def test_registered_mode_accepts_only_registered_tokens(self):
        comp = self.e.tmp / "r" / "comp"
        comp.mkdir(parents=True)
        (comp / "ANNOTATIONS.json").write_text(json.dumps({"replacements": [{"placeholder": "{{HOST_1}}"}]}))
        (comp / "a.md").write_text("x {{HOST_1}}\n")
        self.assertEqual(self.run_script(comp.parent, "--allow-registered").returncode, 0)
        (comp / "b.md").write_text("typo {{HOST_9}}\n")
        r = self.run_script(comp.parent, "--allow-registered")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unregistered", r.stdout)

    def test_secret_shapes_and_private_paths_still_fail_and_ignore_file_works(self):
        d = self.e.tmp / "s"
        d.mkdir()
        (d / "a.py").write_text('K = "%s"\nP = "/Users/zed/x"\n' % FIX)
        r = self.run_script(d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("token-like", r.stdout)
        self.assertIn("private home paths", r.stdout)
        ign = self.e.tmp / "ign.txt"
        ign.write_text(FIX + "\n/Users/zed/x\n")
        self.assertEqual(self.run_script(d, env={"CHECK_PLACEHOLDERS_IGNORE_FILE": str(ign)}).returncode, 0)


if __name__ == "__main__":
    unittest.main()
