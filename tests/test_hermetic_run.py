"""Tests for hermetic_run.py (layered test isolation with an honest receipt).

What is covered: the scrubbed environment, the Seatbelt profile text, the
isolation-level logic (it must never over-claim), end-to-end runs in "soft" mode
(no OS sandbox), and - where the platform supports it - canary runs proving a
capability works outside the sandbox and is denied inside.

Tests that need an OS sandbox are skipped (not failed) when none is usable.
Fixtures are throwaway temp directories containing tiny synthetic scripts; no
network access outside loopback is attempted and no real personal data is used.

Run (from the tools directory):  python3 -B -m unittest discover -s tests
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# Make the tools directory (parent of tests/) importable.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import hermetic_run as H  # noqa: E402

# Probe once at import time: which OS sandbox (if any) works on this machine.
KIND, NOTE = H.probe_os_sandbox()
# Tests needing the sandbox are skipped when this is False.
OS_AVAILABLE = KIND is not None


def make_src(files):
    """Create a temp directory holding the given {filename: text} files; return its path."""
    d = tempfile.mkdtemp(prefix="hr_test_src_")
    for name, body in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(body)
    return d


class PureTests(unittest.TestCase):
    """Tests of pure helper functions; no subprocesses or sandbox needed."""
    def test_env_allowlist_and_no_leak(self):
        """Proves the child environment is rebuilt from fixed values: host variables do not leak and key settings are pinned."""
        os.environ["HR_SECRETISH"] = "v"   # synthetic variable that must not leak
        try:
            env = H.build_env("/tmp/x")
        finally:
            del os.environ["HR_SECRETISH"]
        self.assertNotIn("HR_SECRETISH", env)
        self.assertEqual(env["PYTHONHASHSEED"], "0")
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(env["HOME"], "/tmp/x/home")
        self.assertEqual(env["PATH"], H.MIN_PATH)

    def test_pass_env_only_names_given(self):
        """Proves a host variable is passed through only when its name is explicitly requested."""
        os.environ["HR_PASS"] = "1"
        try:
            self.assertEqual(H.build_env("/t", ["HR_PASS"])["HR_PASS"], "1")
            self.assertNotIn("HR_PASS", H.build_env("/t"))
        finally:
            del os.environ["HR_PASS"]

    def test_profile_contents(self):
        """Proves the sandbox profile denies network and home reads, and mentions localhost only when loopback is allowed."""
        p = H.build_seatbelt_profile("/private/tmp/r", "/Users/someone", False)
        self.assertIn("(deny network*)", p)
        self.assertNotIn("localhost", p)
        self.assertIn('(deny file-read* (subpath "/Users/someone"))', p)
        q = H.build_seatbelt_profile("/private/tmp/r", "/Users/someone", True)
        self.assertIn('localhost:*', q)

    def test_profile_quotes_escaped(self):
        """Proves a double quote in a path is escaped so it cannot break out of the profile string."""
        p = H.build_seatbelt_profile('/private/tmp/a"b', "/Users/x", False)
        self.assertIn('a\\"b', p)

    def test_real_home_ignores_HOME_env(self):
        """Proves real_home() comes from the passwd database, so overriding $HOME cannot redirect it."""
        import pwd
        want = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
        with mock.patch.dict(os.environ, {"HOME": "/private/tmp/fake_home_for_test"}):
            self.assertEqual(H.real_home(), want)
            homes = H.denied_homes()
        # passwd home first, the overridden $HOME second (both must be hidden).
        self.assertEqual(homes[0], want)
        self.assertIn(os.path.realpath("/private/tmp/fake_home_for_test"), homes)

    def test_profile_denies_every_home_given(self):
        """Proves a list of homes yields one read-deny rule per home, all before the re-allow of the temp root."""
        p = H.build_seatbelt_profile("/private/tmp/r", ["/Users/a", "/Users/b"], False)
        self.assertIn('(deny file-read* (subpath "/Users/a"))', p)
        self.assertIn('(deny file-read* (subpath "/Users/b"))', p)
        self.assertLess(p.index('"/Users/b"'), p.index('(allow file-read* (subpath "/private/tmp/r"))'))

    def test_level_logic_never_overclaims(self):
        """Proves the isolation level is OS_ENFORCED only with every OS layer active, SOFT only with all soft layers, otherwise NONE."""
        # Build a layers dict where only the named layers are ACTIVE.
        act = lambda *n: {k: {"status": "ACTIVE" if k in n else "NOT_ACTIVE"} for k in H.SOFT_LAYERS + H.OS_LAYERS}
        self.assertEqual(H.level_for(act(*H.SOFT_LAYERS)), "SOFT")
        self.assertEqual(H.level_for(act(*H.SOFT_LAYERS, "os_net_deny")), "SOFT")
        self.assertEqual(H.level_for(act(*H.SOFT_LAYERS, *H.OS_LAYERS)), "OS_ENFORCED")
        self.assertEqual(H.level_for(act("os_net_deny", *H.OS_LAYERS)), "NONE")

    def test_env_scrub_selftest(self):
        """Proves the wrapper-free environment self test passes (sentinel hidden, HOME redirected)."""
        self.assertTrue(H.env_scrub_selftest())


class EndToEndSoft(unittest.TestCase):
    """End-to-end runs with --soft-only semantics (no OS sandbox required)."""
    def test_soft_only_label_and_exit_code(self):
        """Proves the child exit code is passed through, the level is labelled SOFT, and OS layers are reported NOT_ACTIVE."""
        src = make_src({"a.py": "import sys; sys.exit(7)"})
        r = H.hermetic_run(["python3", "a.py"], src=src, soft_only=True)
        self.assertEqual(r["exit_code"], 7)
        self.assertEqual(r["isolation_level"], "SOFT")
        for n in H.OS_LAYERS:
            self.assertEqual(r["layers"][n]["status"], "NOT_ACTIVE")
        self.assertTrue(r["source_unchanged"])

    def test_pass_env_home_tmpdir_path_mark_layers_not_active(self):
        """F1: --pass-env HOME/TMPDIR/PATH replaces the redirected value with the host's, so the receipt must NOT
        claim home_redirect / fresh_tmp / env_scrub; an unrelated pass-through leaves them ACTIVE."""
        src = make_src({"a.py": "pass"})
        # HOME and PATH are always set on the host; TMPDIR may not be, so set it for this test only.
        os.environ.setdefault("TMPDIR", "/tmp")
        r = H.hermetic_run(["python3", "a.py"], src=src, soft_only=True, pass_env=["HOME", "TMPDIR", "PATH"])
        self.assertEqual(r["layers"]["home_redirect"]["status"], "NOT_ACTIVE")
        self.assertEqual(r["layers"]["fresh_tmp"]["status"], "NOT_ACTIVE")
        self.assertEqual(r["layers"]["env_scrub"]["status"], "NOT_ACTIVE")
        self.assertNotEqual(r["isolation_level"], "SOFT")
        os.environ["HR_OTHER"] = "1"
        try:
            ok = H.hermetic_run(["python3", "a.py"], src=src, soft_only=True, pass_env=["HR_OTHER"])
        finally:
            del os.environ["HR_OTHER"]
        self.assertEqual(ok["layers"]["home_redirect"]["status"], "ACTIVE")
        self.assertEqual(ok["isolation_level"], "SOFT")

    def test_zero_tests_detected_warned_and_not_a_success(self):
        """A test command that runs 0 tests exits 0 but must be flagged and turned into exit code 4."""
        src = make_src({"test_a.py": "import unittest\nclass T(unittest.TestCase):\n    def test_x(self): pass\n"})
        sub = os.path.join(src, "elsewhere")
        os.mkdir(sub)
        # discovering from the wrong folder: unittest runs nothing and exits 0 on Python < 3.12
        r = H.hermetic_run(["python3", "-B", "-m", "unittest", "discover", "-s", "elsewhere"], src=src, soft_only=True)
        self.assertTrue(r["zero_tests"])
        self.assertIn("0 tests", r["warning"])
        self.assertEqual(r["exit_code"], 4 if r.get("command_exit_code") == 0 else r["exit_code"])
        self.assertNotEqual(r["exit_code"], 0)
        self.assertIn("WARNING", H.render_text(r))
        # the right folder runs 1 test: no warning, exit 0
        ok = H.hermetic_run(["python3", "-B", "-m", "unittest", "discover", "-s", ".", "-p", "test_*.py"], src=src,
                            soft_only=True)
        self.assertFalse(ok["zero_tests"])
        self.assertEqual(ok["exit_code"], 0)
        # explicit opt-out keeps the old behaviour
        off = H.hermetic_run(["python3", "-B", "-m", "unittest", "discover", "-s", "elsewhere"], src=src,
                             soft_only=True, allow_zero_tests=True)
        self.assertNotIn("warning", off)

    def test_ran_zero_tests_phrases(self):
        for text in ("Ran 0 tests in 0.000s\n\nOK", "collected 0 items", "NO TESTS RAN", "no tests ran in 0.01s"):
            self.assertTrue(H.ran_zero_tests(text), text)
        for text in ("Ran 6 tests in 0.1s\nOK", "", "hello", "Ran 10 tests in 1s"):
            self.assertFalse(H.ran_zero_tests(text), text)

    def test_source_never_modified(self):
        """Proves a command that writes a file affects only the copy; the source tree stays unchanged."""
        src = make_src({"w.py": "open('new.txt','w').write('x')"})
        r = H.hermetic_run(["python3", "w.py"], src=src, soft_only=True)
        self.assertEqual(r["exit_code"], 0)
        self.assertFalse(os.path.exists(os.path.join(src, "new.txt")))
        self.assertTrue(r["source_unchanged"])

    def test_timeout(self):
        """Proves a long-running command is killed at the timeout and reported with exit code 124."""
        src = make_src({"s.py": "import time; time.sleep(30)"})
        r = H.hermetic_run(["python3", "s.py"], src=src, soft_only=True, timeout=1)
        self.assertTrue(r["timed_out"])
        self.assertEqual(r["exit_code"], 124)

    def test_require_os_refuses_when_not_verified(self):
        """Proves --require-os refuses to run (exit code 3) when OS layers are not verified."""
        src = make_src({"a.py": "print(1)"})
        r = H.hermetic_run(["python3", "a.py"], src=src, soft_only=True, require_os=True)
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(r["refused"])

    def test_failed_canary_downgrades_label(self):
        """Proves that if the canary fails to verify the OS layers (mocked), the receipt is downgraded to SOFT and says the command was not OS-wrapped."""
        src = make_src({"a.py": "print(1)"})
        bad = ({n: False for n in H.OS_LAYERS + ("env_scrub",)}, {"notes": ["forced"]})
        with mock.patch.object(H, "self_test", return_value=bad), \
                mock.patch.object(H, "probe_os_sandbox", return_value=("seatbelt", "mock")):
            r = H.hermetic_run(["python3", "a.py"], src=src)
        self.assertEqual(r["isolation_level"], "SOFT")
        self.assertFalse(r["wrapped_with_os_sandbox"])

    def test_receipt_is_json_serialisable_and_env_names_only(self):
        """Proves the receipt serialises to JSON and does not embed hidden paths under the real home directory."""
        src = make_src({"a.py": "print(1)"})
        r = H.hermetic_run(["python3", "a.py"], src=src, soft_only=True)
        s = json.dumps(r)
        self.assertNotIn(os.path.expanduser("~") + os.sep + ".", s)


class ChildSeesScrubbedWorld(unittest.TestCase):
    """Checks from inside the child process what environment it actually sees."""
    def test_child_home_and_hash_seed(self):
        """Proves the child sees a fixed hash seed, no canary sentinel variable, and a redirected HOME even though the parent sets the sentinel."""
        src = make_src({"t.py": (
            "import os,sys\n"
            "assert os.environ['PYTHONHASHSEED']=='0'\n"
            "assert 'HERMETIC_CANARY_SENTINEL' not in os.environ\n"
            "assert os.environ['HOME'].endswith('/home')\n"
            "assert os.path.expanduser('~')!=%r\n" % os.path.expanduser("~"))})
        os.environ["HERMETIC_CANARY_SENTINEL"] = "x"
        try:
            r = H.hermetic_run(["python3", "t.py"], src=src, soft_only=True)
        finally:
            del os.environ["HERMETIC_CANARY_SENTINEL"]
        self.assertEqual(r["exit_code"], 0, r.get("output_tail"))


class CanaryBothDirections(unittest.TestCase):
    """Proves both directions. If no OS sandbox works here, the outside direction is
    still checked and the verdict must be honest (no OS layer ACTIVE)."""

    def test_outside_direction_all_succeed(self):
        """Proves that outside any sandbox every canary probe succeeds, so a denial inside means something."""
        out = H.run_canary(None, False, wrapped=False)
        self.assertEqual(out["net_loopback"], "ok")
        self.assertNotEqual(out["net_external"], "denied")
        self.assertEqual(out["read_home"], "ok")
        self.assertEqual(out["write_outside"], "ok")
        self.assertEqual(out["env_sentinel"], "ok")

    @unittest.skipUnless(OS_AVAILABLE, "OS sandbox unavailable here: " + str(NOTE))
    def test_inside_direction_all_denied(self):
        """Proves that inside the OS sandbox every canary probe is denied."""
        inn = H.run_canary(KIND, False, wrapped=True)
        self.assertEqual(inn["net_external"], "denied")
        self.assertEqual(inn["net_loopback"], "denied")
        self.assertEqual(inn["read_home"], "denied")
        self.assertEqual(inn["write_outside"], "denied")
        self.assertEqual(inn["env_sentinel"], "absent")

    @unittest.skipUnless(OS_AVAILABLE, "OS sandbox unavailable here: " + str(NOTE))
    def test_allow_loopback_opens_only_loopback(self):
        """Proves --allow-loopback opens loopback only; the external address stays denied."""
        if KIND != "seatbelt":
            self.skipTest("loopback allow implemented for seatbelt only")
        inn = H.run_canary(KIND, True, wrapped=True)
        self.assertEqual(inn["net_loopback"], "ok")
        self.assertEqual(inn["net_external"], "denied")

    @unittest.skipUnless(OS_AVAILABLE, "OS sandbox unavailable here: " + str(NOTE))
    def test_self_test_verifies_layers(self):
        """Proves the self test marks every layer verified on a macOS-style sandbox."""
        v, ev = H.self_test(KIND, False)
        if KIND == "seatbelt":
            self.assertTrue(all(v.values()), ev)

    @unittest.skipUnless(OS_AVAILABLE and KIND == "seatbelt", "seatbelt needed")
    def test_full_run_is_os_enforced_and_blocks_write_in_target(self):
        """Proves a full run is labelled OS_ENFORCED and a write attempt outside the temp root fails and leaves no file."""
        # The write target is a throw-away directory OUTSIDE the hermetic temp root, never the real home: if the OS
        # sandbox were not enforced (nested, unavailable) the write would succeed, and it must not land in ~.
        outside = tempfile.mkdtemp(prefix="hr_outside_")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        src = make_src({"t.py": (
            "import os,sys\n"
            "try:\n"
            "    open(os.path.join(%r,'leak.txt'),'w'); sys.exit(1)\n"
            "except PermissionError:\n"
            "    sys.exit(0)\n" % outside)})
        r = H.hermetic_run(["python3", "t.py"], src=src)
        self.assertEqual(r["isolation_level"], "OS_ENFORCED")
        self.assertEqual(r["exit_code"], 0, r.get("output_tail"))
        self.assertFalse(os.path.exists(os.path.join(outside, "leak.txt")))
        self.assertFalse(os.path.exists(os.path.join(os.path.expanduser("~"), "leak.txt")))

    @unittest.skipUnless(OS_AVAILABLE and KIND == "seatbelt", "seatbelt needed")
    def test_real_home_denied_even_when_HOME_is_overridden(self):
        """Proves that with $HOME pointed at a scratch folder the sandbox still denies listing the account's real (passwd) home."""
        scratch_home = tempfile.mkdtemp(prefix="hr_fake_home_")
        self.addCleanup(shutil.rmtree, scratch_home, ignore_errors=True)
        # The child rebuilds its environment, so pwd still works inside it.  It must
        # get PermissionError when listing the passwd home (the listing itself is never printed).
        src = make_src({"t.py": (
            "import os,pwd,sys\n"
            "h = pwd.getpwuid(os.getuid()).pw_dir\n"
            "try:\n"
            "    os.listdir(h); print('LISTED'); sys.exit(1)\n"
            "except PermissionError:\n"
            "    print('DENIED'); sys.exit(0)\n")})
        with mock.patch.dict(os.environ, {"HOME": scratch_home}):
            r = H.hermetic_run(["python3", "t.py"], src=src, allow_zero_tests=True)
        self.assertEqual(r["isolation_level"], "OS_ENFORCED", r)
        self.assertEqual(r["exit_code"], 0, r.get("output_tail"))
        self.assertIn("DENIED", "\n".join(r.get("output_tail", [])))

    def test_partial_os_proof_still_wraps_but_stays_soft(self):
        """Proves the code matches its comment: one proved OS layer means the command is wrapped, the label is SOFT, and unproved layers are NOT_ACTIVE."""
        if KIND != "seatbelt":
            self.skipTest("seatbelt needed to actually wrap")
        src = make_src({"a.py": "print(1)"})
        part = ({"os_net_deny": True, "os_fs_write_deny": False, "os_home_read_deny": False,
                 "env_scrub": True}, {"notes": ["forced"]})
        with mock.patch.object(H, "self_test", return_value=part):
            r = H.hermetic_run(["python3", "a.py"], src=src)
        self.assertEqual(r["isolation_level"], "SOFT")
        self.assertTrue(r["wrapped_with_os_sandbox"])
        self.assertEqual(r["os_layers_proved"], ["os_net_deny"])
        self.assertEqual(r["layers"]["os_home_read_deny"]["status"], "NOT_ACTIVE")

    def test_unavailable_sandbox_is_not_claimed(self):
        """Proves that when no OS sandbox is available (mocked) the run still works but is labelled SOFT with OS layers NOT_ACTIVE."""
        src = make_src({"a.py": "print(1)"})
        with mock.patch.object(H, "probe_os_sandbox", return_value=(None, "mock unavailable")):
            r = H.hermetic_run(["python3", "a.py"], src=src)
        self.assertEqual(r["isolation_level"], "SOFT")
        self.assertEqual(r["layers"]["os_net_deny"]["status"], "NOT_ACTIVE")
        self.assertEqual(r["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
