"""Regression tests for the findings of red-team review #6 of the release kit (B1-B3, F1-F10, LOW-1, LOW-2).

Every test here failed against the code as it was when the review was written (see the finding id in each
docstring); each one pins a single behaviour so it cannot silently return.

All values are invented (the fixtures in _fx.py plus a few obviously fake strings).  Secret-shaped strings are built
from repeated filler so no real-looking token literal exists in this file.  Non-ASCII text is written as \\u escapes.
"""
import contextlib
import io
import json
import multiprocessing
import os
import subprocess
import sys
import unittest
from pathlib import Path

import _fx
from _fx import Env, SALT

import hotswap
import normalize
import release_gate
import scrub_release as sr
from test_gate_hardening import GateBase

SCRIPT = str(_fx.TOOLS / "templates" / "check_placeholders.sh")
H = "fakeuser9"   # the invented owner handle from _fx.VALUES


def gate_cli(staging, env, extra=()):
    """Run release_gate.main with the Env's values file; -> (exit code, stdout text)."""
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = release_gate.main(["--staging", str(staging), "--values", str(env.values),
                                  "--release-root", str(env.release)] + list(extra))
    return code, out.getvalue() + err.getvalue()


def spans(text):
    """Pattern classes found in TEXT by the shared detector (what both the scrubber and the gate use)."""
    return sorted(c for _s, _e, c in sr.pattern_spans(text))


# ------------------------------------------------------------------------------------------------------- B1
class TestB1EmptyTreeFails(GateBase):
    """B1: a gate that scanned nothing must FAIL, not print PASS."""

    def test_empty_staging_dir_fails_with_clear_message(self):
        empty = self.e.tmp / "empty_stage"
        empty.mkdir()
        code, out = gate_cli(empty, self.e)
        self.assertEqual(code, 1)
        self.assertIn("scanned 0 files", out)
        self.assertIn("release_gate: FAIL", out)
        self.assertNotIn("release_gate: PASS", out)

    def test_staging_without_any_component_folder_fails(self):
        """Only a loose file in the root: no component folder exists, so nothing was really verified."""
        loose = self.e.tmp / "loose_stage"
        loose.mkdir()
        (loose / "README.md").write_text("hello\n")
        code, out = gate_cli(loose, self.e)
        self.assertEqual(code, 1)
        self.assertIn("no component folder", out)

    def test_normal_tree_still_passes(self):
        self.put("a.txt", "fine\n")
        code, out = gate_cli(self.stg, self.e)
        self.assertEqual(code, 0, out)


# ------------------------------------------------------------------------------------------------------- B2
class TestB2PrivateFilesNeverShip(GateBase):
    """B2: the values file / salt must never reach the staging tree."""

    def test_manifest_listing_the_values_file_is_refused(self):
        with self.assertRaises(sr.ScrubError):
            mp = self.e.manifest(["values.private.json"])
            sr.build_component(mp, self.e.values, self.e.release, self.e.cfg, self.e.restore)
        self.assertFalse((self.e.release / "staging" / "comp").exists(), "nothing may be written")

    def test_hard_link_copy_of_values_file_is_refused(self):
        os.link(str(self.e.values), str(self.e.src / "innocent.json"))
        with self.assertRaises(sr.ScrubError):
            self.e.scrub(["innocent.json"])

    def test_restore_map_and_annotations_private_are_refused(self):
        self.e.put("a.txt", "x %s y\n" % H)
        self.e.scrub(["a.txt"])      # creates the restore map and annotations.private/comp.json beside it
        for rel in ("restore.private.json", "annotations.private/comp.json"):
            with self.assertRaises(sr.ScrubError, msg=rel):
                mp = self.e.manifest([rel], name="m2.json")
                sr.build_component(mp, self.e.values, self.e.release, self.e.cfg, self.e.restore)

    def test_plain_copy_of_the_values_file_is_refused_because_it_holds_the_salt(self):
        (self.e.src / "copy.json").write_bytes(self.e.values.read_bytes())
        res = self.e.scrub(["copy.json"])
        self.assertEqual(res["copied"], 0)
        self.assertIn("salt", res["refused_list"][0]["reason"])

    def test_gate_fails_when_the_salt_is_in_the_tree(self):
        self.put("cfg.json", '{"salt": "%s"}\n' % SALT)
        pv = sr.load_values(self.e.values, self.e.release)
        found = release_gate.gate(self.stg, pv, self.e.release, (), None, (), values_path=self.e.values)[1]
        self.assertIn(("PRIVATE_VALUE", "SALT", "comp/cfg.json", 1), found)
        self.assertNotIn(SALT, repr(found), "the salt itself must never be printed")

    def test_gate_fails_when_the_values_file_path_is_in_the_tree(self):
        self.put("notes.md", "keys live in %s\n" % self.e.values)
        pv = sr.load_values(self.e.values, self.e.release)
        found = release_gate.gate(self.stg, pv, self.e.release, (), None, (), values_path=self.e.values)[1]
        self.assertTrue(any(f[1] == "VALUES_FILE_PATH" for f in found), found)

    def test_salt_in_the_file_name_is_found_too(self):
        self.put("x_%s.txt" % SALT, "hi\n")
        pv = sr.load_values(self.e.values, self.e.release)
        found = release_gate.gate(self.stg, pv, self.e.release, (), None, (), values_path=self.e.values)[1]
        self.assertTrue(any(f[1] == "SALT" for f in found), found)


# ------------------------------------------------------------------------------------------------------- B3 patterns
class TestB3PatternExtensions(unittest.TestCase):
    """B3: the cheap evasions are now detected; ordinary look-alikes stay untouched."""

    def assertHit(self, text, cls):
        self.assertIn(cls, spans(text), text)

    def assertClean(self, text):
        self.assertEqual(spans(text), [], text)

    def test_home_paths_glued_to_a_prefix(self):
        for t in ("file:///Users/jdoe/x", "/System/Volumes/Data/Users/jdoe/x", "/Volumes/Disk/Users/jdoe",
                  "/mnt/c/Users/jdoe/x", "/usr/home/jdoe", "/USERS/jdoe/x", "/HOME/jdoe", "/Volumes/D/users/jdoe"):
            self.assertHit(t, "HOME_PATH")

    def test_only_the_path_part_is_replaced(self):
        t = "file:///Users/jdoe/x"
        s, e, _c = sr.pattern_spans(t)[0]
        self.assertEqual(t[s:e], "/Users/jdoe")

    def test_generic_names_and_routes_stay_clean(self):
        for t in ("/Users/guest/x", "/Users/you/p", "/home/user/p", "GET /users/42", "see /api/users/alice",
                  "https://example.com/home/dashboard", "/Users/Shared/x"):
            self.assertClean(t)

    def test_quoted_passwords_of_any_length(self):
        for t in ('password = "hunter2"', "pwd='S3cret!'", 'DB_PASSWORD: "p@ss"', '"passwd": "ab1"'):
            self.assertHit(t, "API_TOKEN")

    def test_password_lookalikes_stay_clean(self):
        for t in ('"password": "Password"', 'type="password"', 'password="your-password-here"', 'password: "{{X}}"',
                  'password = ""', 'password = "${DB_PASS}"', "password_confirm = 'abc1'", 'password = input("Password: ")'):
            self.assertClean(t)

    def test_vendor_tokens(self):
        for t in ("sk_live_" + "a" * 20, "pk_live_" + "a" * 20, "ASIA" + "A" * 16, "npm_" + "a" * 36,
                  "glpat-" + "a" * 20, "SG." + "a" * 16 + "." + "b" * 16,
                  "https://hooks.slack.com/services/T0000000/B0000000/" + "X" * 16,
                  "Authorization: Bearer " + "a" * 24, "pypi-" + "A" * 52):
            self.assertHit(t, "API_TOKEN")

    def test_vendor_token_lookalikes_stay_clean(self):
        for t in ("npm_config_cache", "sk_live_mode = 1", "Bearer token", "Authorization: Bearer ${TOKEN}", "glpat-short"):
            self.assertClean(t)

    def test_macs(self):
        self.assertHit("aabb.ccdd.eeff", "MAC")
        self.assertHit("mac: aabbccddeeff", "MAC")
        self.assertHit("HWADDR=AABBCCDDEEFF", "MAC")
        for t in ("1234.5678.9012", "commit aabbccddeeff", "sha 0123456789ab"):
            self.assertClean(t)

    def test_leading_zero_ips(self):
        for t in ("010.001.002.003", "192.168.001.005", "172.016.000.001", "100.064.001.001"):
            self.assertTrue({"LAN_IP", "VPN_IP"} & set(spans(t)), t)
        for t in ("1.04.0.2", "8.08.8.8", "010.300.1.1"):
            self.assertClean(t)

    def test_uppercase_host_suffixes(self):
        self.assertHit("BOX.LAN", "HOSTNAME")
        self.assertHit("Printer.Home.Arpa", "HOSTNAME")
        self.assertHit("A.TAIL1234.TS.NET", "TAILNET_HOST")

    def test_private_key_header_variants(self):
        for t in ("-----begin private key-----", "-----BEGIN  RSA   PRIVATE  KEY-----", "----- BEGIN PRIVATE KEY -----",
                  "-----Begin Openssh Private Key-----"):
            self.assertTrue(sr.has_private_key_block(t), t)
        self.assertFalse(sr.has_private_key_block("-----BEGIN PUBLIC KEY-----"))

    def test_private_key_header_hidden_by_invisible_or_fullwidth_characters(self):
        self.assertTrue(sr.has_private_key_block("-----BEGIN PRIV​ATE KEY-----"))
        self.assertTrue(sr.has_private_key_block("-----BEGIN PRIVATE KEＹ-----"))

    def test_phone_spellings(self):
        for t in ("(212)123-4567", "212–123–4567"):
            self.assertHit(t, "PHONE")


class TestB3GateSeesTheNewForms(GateBase):
    """B3: the gate reuses the same detectors, and the PEM header is also checked after folding."""

    def kinds(self, text):
        self.put("a.txt", text)
        got = {(f[0], f[1]) for f in self.findings()}
        (self.comp / "a.txt").unlink()
        return got

    def test_glued_home_path_is_a_pattern_finding(self):
        self.assertIn(("PATTERN", "HOME_PATH"), self.kinds("open file:///Users/jdoe/x\n"))

    def test_pem_header_variants_are_private_key_findings(self):
        self.assertIn(("PRIVATE_KEY", ""), self.kinds("-----begin private key-----\n"))
        self.assertIn(("PRIVATE_KEY", ""), self.kinds("-----BEGIN PRIV​ATE KEY-----\n"))

    def test_ordinary_code_does_not_false_fail(self):
        """~300 lines of ordinary Python/JS/JSON/YAML/shell/HTML/Markdown: zero findings."""
        py = '''
import os, sys, json, re
from urllib.parse import urlparse

__version__ = "1.4.2.0"
UUID = "123e4567-e89b-12d3-a456-426614174000"
SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
COLOR = "#a1b2c3"
LOCAL = "127.0.0.1"
ANY = "0.0.0.0"
DOCIP = "192.0.2.10"
VER_IP = "1.04.0.2"

def route(path):
    """Handle GET /users/42 and /api/users/alice."""
    if path.startswith("/users/"):
        return path.split("/")[2]
    return None

def check(password, token=None):
    label = {"password": "Password", "username": "Username"}
    if password == "":
        raise ValueError("password is empty")
    return label

class Client:
    def __init__(self, base="https://example.com/home/dashboard", npm_config_cache="/tmp/c"):
        self.base = base
        self.password_confirm = None
        self.headers = {"Authorization": "Bearer " + os.environ.get("API_TOKEN", "")}
        self.sk_live_mode = False

    def clone(self):
        return "git@github.com:org/repo.git"
'''
        js = '''
const app = require("express")();
app.get("/users/:id", (req, res) => res.json({ id: req.params.id }));
const tpl = `Hello ${user.name}, your password is ${password}`;
const pkg = { "lodash": "4.17.21", "left-pad": "^1.3.0" };
const re = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}/;
console.log("password:", "Password", "http://localhost:3000/home/x");
'''
        yml = '''
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.1.1
      - uses: actions/setup-python@v5.1.0
        with:
          python-version: "3.11"
      - run: pip install requests==2.31.0 numpy@1.26.4
      - run: echo "${{ secrets.TOKEN }}"
'''
        md = '''
# Title
Install with `npm i lodash@4.17.21` or `git clone git@github.com:org/repo.git`.
Contact: dev@example.com. Version 1.4.2.0 released 2024.01.02.
Use /Users/you/project or /home/user/project as the example path.
| key | value |
|---|---|
| password | Password |
'''
        sh = '''
#!/bin/sh
set -eu
cd "${HOME}/project"
echo "ip 127.0.0.1 and 0.0.0.0 and 10.0.0.x placeholder"
password_prompt="Enter password:"
read -r -p "$password_prompt" pw
'''
        html = '''
<!doctype html><html><body>
<input type="password" name="password" placeholder="Password">
<a href="https://example.com/users/42">me</a><img src="data:image/png;base64,iVBORw0KGgo=">
</body></html>
'''
        js_json = '{"name": "x", "version": "1.4.2.0", "dependencies": {"lodash": "4.17.21"}, "password": "Password"}\n'
        corpus = {"a.py": py * 5, "b.js": js * 5, "c.yml": yml * 5, "d.md": md * 5, "e.sh": sh * 5,
                  "f.html": html * 5, "g.json": js_json * 5}
        total = 0
        for name, body in corpus.items():
            self.put(name, body)
            total += body.count("\n")
        self.assertGreater(total, 300)
        self.assertEqual(self.findings(), [], "false findings on ordinary code")


# ------------------------------------------------------------------------------------------------------- F1
class TestF1PassEnvOverridesAreHonest(unittest.TestCase):
    """F1 is covered in test_hermetic_run.EndToEndSoft.test_pass_env_home_tmpdir_path_mark_layers_not_active; this
    just pins the helper."""

    def test_overridden_layers_helper(self):
        import hermetic_run
        os.environ["HR_F1_OTHER"] = "1"
        try:
            got = {n: l for n, l, _w in hermetic_run.overridden_layers(["HOME", "PATH", "HR_F1_OTHER", "XDG_CACHE_HOME_NOT_SET"])}
        finally:
            del os.environ["HR_F1_OTHER"]
        self.assertEqual(got.get("HOME"), "home_redirect")
        self.assertEqual(got.get("PATH"), "env_scrub")
        self.assertNotIn("HR_F1_OTHER", got)


# ------------------------------------------------------------------------------------------------------- F2 / F9
class TestShellScriptFixes(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.cleanup)

    def run_script(self, root, *args):
        return subprocess.run(["bash", SCRIPT, str(root)] + list(args), capture_output=True, text=True)

    def test_f2_generic_example_home_paths_pass_real_ones_fail(self):
        d = self.e.tmp / "docs"
        d.mkdir()
        (d / "a.md").write_text("cd /Users/you/project && ls /home/user/project /Users/Guest/x /home/Example/y\n")
        self.assertEqual(self.run_script(d).returncode, 0)
        (d / "b.md").write_text("cd /Users/you/p /Users/jdoe/real/\n")      # one generic and one real path on one line
        r = self.run_script(d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("private home paths", r.stdout)

    def test_f9_generated_pages_are_skipped_only_at_their_real_place(self):
        d = self.e.tmp / "tree"
        (d / "comp" / "docs").mkdir(parents=True)
        (d / "comp" / "ANNOTATIONS.json").write_text('{"replacements": []}\n')
        (d / "comp" / "ANNOTATIONS.md").write_text("Tokens like `{{KEY.lower}}`\n")      # real place: skipped
        self.assertEqual(self.run_script(d, "--allow-registered").returncode, 0)
        (d / "comp" / "docs" / "ANNOTATIONS.md").write_text("hand added {{ZQUILL77}}\n")   # nested copy: checked
        r = self.run_script(d, "--allow-registered")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unregistered", r.stdout)

    def test_vendor_tokens_and_pem_variants_fail_the_shell_check_too(self):
        d = self.e.tmp / "v"
        d.mkdir()
        (d / "a.txt").write_text("x = sk_live_" + "a" * 20 + "\n")
        self.assertEqual(self.run_script(d).returncode, 1)
        (d / "a.txt").write_text("-----begin private key-----\n")
        self.assertEqual(self.run_script(d).returncode, 1)
        (d / "a.txt").write_text("npm_config_cache=1\n")
        self.assertEqual(self.run_script(d).returncode, 0)


# ------------------------------------------------------------------------------------------------------- F3
class TestF3RefusedNamesAreNotPublished(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.cleanup)

    def test_public_pages_carry_counts_and_reasons_but_no_paths(self):
        self.e.put("taxes_2025.png", b"\x89PNG", binary=True)
        self.e.put("private/notes_private.md", "x\n")
        self.e.put("ok.txt", "fine\n")
        res = self.e.scrub(["taxes_2025.png", "private/notes_private.md", "ok.txt"])
        self.assertEqual(res["refused"], 2)
        for f in ("REFUSED.md", "ANNOTATIONS.json", "ANNOTATIONS.md"):
            text = (self.e.staged() / f).read_text()
            for secret in ("taxes_2025", "notes_private", "private/"):
                self.assertNotIn(secret, text, f)
        pub = json.loads((self.e.staged() / "ANNOTATIONS.json").read_text())
        self.assertEqual([sorted(r) for r in pub["refused"]], [["item", "reason"], ["item", "reason"]])
        self.assertIn("EXCLUDE_LIST", (self.e.staged() / "REFUSED.md").read_text())
        # the operator still gets the full list: on screen (refused_list) and in the PRIVATE copy
        self.assertEqual({r["path"] for r in res["refused_list"]}, {"taxes_2025.png", "private/notes_private.md"})
        priv = json.loads((self.e.cfg / "annotations.private" / "comp.json").read_text())
        self.assertEqual({r["path"] for r in priv["refused_paths"]}, {"taxes_2025.png", "private/notes_private.md"})


# ------------------------------------------------------------------------------------------------------- F4
class TestF4NotEmails(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.cleanup)

    def test_ssh_urls_npm_pins_and_action_pins_are_untouched(self):
        body = ("git clone git@github.com:org/repo.git\nnpm i lodash@4.17.21 left-pad@1.3.0-beta.2\n"
                "- uses: actions/setup-python@v5.1.0\n- uses: actions/checkout@v4\nssh://git@example.net/x.git\n")
        self.e.put("ci.md", body)
        res = self.e.scrub(["ci.md"])
        self.assertEqual(res["records"], [])
        self.assertEqual((self.e.staged() / "ci.md").read_text(), body)

    def test_real_addresses_are_still_replaced(self):
        self.e.put("c.md", "mail bob@corp.test or bob.smith+x@mail.corp.test\n")
        res = self.e.scrub(["c.md"])
        self.assertEqual(len(res["records"]), 2)


# ------------------------------------------------------------------------------------------------------- F5
class TestF5SpecialFiles(GateBase):
    def test_gate_reports_a_fifo_instead_of_hanging(self):
        os.mkfifo(str(self.comp / "pipe"))
        # A child process with a timeout, so the OLD behaviour (hang forever) fails the test instead of freezing it.
        code = ("import sys; sys.path.insert(0, %r); import release_gate, scrub_release as sr\n"
                "pv = sr.load_values(%r, %r)\n"
                "f = release_gate.gate(%r, pv, %r)[1]\n"
                "print([x for x in f if x[0] == 'STRUCTURE'])\n") % (
            str(_fx.TOOLS), str(self.e.values), str(self.e.release), str(self.stg), str(self.e.release))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("special file", r.stdout)

    def test_scrubber_refuses_a_fifo_in_the_manifest(self):
        os.mkfifo(str(self.e.src / "pipe"))
        res = self.e.scrub(["pipe"])
        self.assertEqual((res["copied"], res["refused"]), (0, 1))

    def test_hotswap_refuses_a_fifo_in_the_component(self):
        os.mkfifo(str(self.comp / "pipe"))
        vals = self.e.tmp / "my.json"
        vals.write_text("{}")
        os.chmod(str(vals), 0o600)
        with self.assertRaises(sr.ScrubError):
            hotswap.run(self.comp, vals, self.e.tmp / "out", None, self.e.release)


# ------------------------------------------------------------------------------------------------------- F6
class TestF6HotswapNameCollision(GateBase):
    def test_two_names_that_collapse_to_one_fail_cleanly_before_writing(self):
        self.put("{{A_NAME}}.txt", "one\n")
        self.put("{{B_NAME}}.txt", "two\n")
        vals = self.e.tmp / "my.json"
        vals.write_text(json.dumps({"A_NAME": "same", "B_NAME": "same"}))
        os.chmod(str(vals), 0o600)
        out = self.e.tmp / "out"
        with self.assertRaises(sr.ScrubError) as cm:
            hotswap.run(self.comp, vals, out, None, self.e.release)
        self.assertIn("same name", str(cm.exception))
        self.assertFalse(out.exists(), "nothing may be written before the collision is detected")

    def test_file_and_folder_with_one_name_also_fail(self):
        self.put("{{A_NAME}}", "file\n")
        self.put("{{B_NAME}}/x.txt", "in folder\n")
        vals = self.e.tmp / "my.json"
        vals.write_text(json.dumps({"A_NAME": "dup", "B_NAME": "dup"}))
        os.chmod(str(vals), 0o600)
        with self.assertRaises(sr.ScrubError):
            hotswap.run(self.comp, vals, self.e.tmp / "out2", None, self.e.release)


# ------------------------------------------------------------------------------------------------------- F7
class TestF7Surrogates(GateBase):
    def test_lone_surrogate_escape_inside_a_candidate_window_does_not_crash(self):
        """The escape sits INSIDE the window the scanner hashes (fake<lone surrogate>user9): the old encode raised."""
        self.put("a.txt", '{"x": "fake\\ud83duser9 and ' + H + '"}\n')
        found = {f[1] for f in self.findings() if f[0] == "PRIVATE_VALUE"}
        self.assertTrue(found, "the plain value on the same line must still be found")

    def test_gate_hash_accepts_lone_surrogates(self):
        self.assertEqual(len(sr.gate_hash("saltsalt", "a\ud83db")), 32)
        self.assertEqual(len(sr.ann_hash("saltsalt", "a\ud83db")), 32)

    def test_surrogate_pair_escape_is_decoded(self):
        """\\ud835\\udc1f is MATHEMATICAL BOLD SMALL F; NFKD maps it to a plain f, so the handle is found."""
        self.assertEqual(normalize.fold("\\ud835\\udc1f"), "f")
        self.assertTrue(self.hits('"\\ud835\\udc1f' + H[1:] + '"\n'))
        self.assertEqual(normalize.fold("\\ud83d\\ude00"), "\U0001F600")

    def test_percent_u_escape_is_decoded(self):
        self.assertEqual(normalize.fold("%u0066%u0061"), "fa")
        self.assertTrue(self.hits("%u0066" + H[1:] + "\n"))


# ------------------------------------------------------------------------------------------------------- F8
class TestF8SymlinkedComponent(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.cleanup)

    def test_component_dir_that_is_a_symlink_inside_staging_gives_a_clean_error(self):
        stg = self.e.release / "staging"
        (stg / "other").mkdir(parents=True)
        os.symlink(str(stg / "other"), str(stg / "comp"))
        self.e.put("a.txt", "x\n")
        with self.assertRaises(sr.ScrubError) as cm:
            self.e.scrub(["a.txt"])
        self.assertIn("symlink", str(cm.exception))
        self.assertTrue((stg / "other").is_dir())


def _restore_worker(args):
    """Child process: write one component's section into the shared restore map."""
    path, comp = args
    for _ in range(5):
        sr.write_restore(Path(path), comp, {"HOST_1": "x-" + comp})
    return comp


class TestF8RestoreMapLock(unittest.TestCase):
    def test_parallel_writers_keep_every_component_section(self):
        e = Env()
        self.addCleanup(e.cleanup)
        comps = ["c%d" % i for i in range(8)]
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(8) as pool:
            pool.map(_restore_worker, [(str(e.restore), c) for c in comps])
        self.assertEqual(sorted(json.loads(e.restore.read_text())), comps)
        self.assertEqual(oct(e.restore.stat().st_mode & 0o777), "0o600")


# ------------------------------------------------------------------------------------------------------- F10 / LOW-1
class TestDocsAndExamples(unittest.TestCase):
    README = (_fx.TOOLS / "docs" / "REFERENCE.md").read_text(encoding="utf-8")  # the full reference moved here from the top-level README

    def test_f10_readme_column_text_matches_the_generated_page(self):
        self.assertNotIn("(placeholder, meaning, what to put, file:line)", self.README)
        self.assertIn("placeholder, meaning, example value, where to swap, file:line:column", self.README)

    def test_low1_scrubber_uses_the_invented_example_name(self):
        text = (_fx.TOOLS / "scrub_release.py").read_text(encoding="utf-8")
        self.assertNotIn("TWU LLC", text)
        self.assertIn("Acme Works", text)

    def test_readme_has_contact_and_states_the_refused_pages_policy(self):
        self.assertIn("Contact: ethan@twu.software", self.README)
        self.assertIn("https://twu.software", self.README)
        self.assertIn("REFUSED.md", self.README)
        self.assertIn("withheld", self.README)

    def test_b3_readme_lists_the_new_limits(self):
        for phrase in ("file:///Users", "UTF-7", "quoted-printable", "rot47", "wrapped", "sk_live_", "glpat-", "Bearer",
                       "lower-case `/users/`", "truncat"):
            self.assertIn(phrase, self.README, phrase)


# ------------------------------------------------------------------------------------------------------- LOW-2
class TestLow2UnregisteredTokens(GateBase):
    def reg(self, *tokens):
        (self.comp / "ANNOTATIONS.json").write_text(json.dumps({"replacements": [{"placeholder": t} for t in tokens]}))

    def test_hand_added_token_named_like_a_value_fails(self):
        self.put("a.txt", "owner {{FAKEUSER9}}\n")
        self.assertIn(("PLACEHOLDER", "unregistered token", "comp/a.txt", 1), self.findings())

    def test_registered_token_passes(self):
        self.reg("{{OWNER_HANDLE}}", "{{HOST_1.lower}}")
        self.put("a.txt", "owner {{OWNER_HANDLE}} on {{HOST_1.lower}}\n")
        self.assertEqual(self.findings(), [])

    def test_token_in_a_file_name_is_checked(self):
        self.put("{{FAKEUSER9}}.txt", "x\n")
        self.assertTrue(any(f[0] == "PLACEHOLDER" for f in self.findings()))

    def test_generated_description_pages_may_quote_token_syntax(self):
        self.put("ANNOTATIONS.md", "Tokens like `{{KEY.lower}}` mean a case variant\n")
        self.put("REFUSED.md", "{{KEY}}\n")
        self.assertEqual(self.findings(), [])
        self.put("docs/ANNOTATIONS.md", "{{ZQ}}\n")      # a nested copy is an ordinary file
        self.assertTrue(any(f[0] == "PLACEHOLDER" for f in self.findings()))


if __name__ == "__main__":
    unittest.main()
