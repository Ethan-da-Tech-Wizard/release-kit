"""Tests for the values-file key gate_public_identity (intentionally PUBLISHED contact handle / email).

The feature blanks each declared token as a WHOLE token before the gate's value scan, and nothing else: a private name
written next to it is still found.  The declaration is refused when it is free text, a bare first name, or when it
contains a private value of a non-owner key (host, IP, workspace ...).  All values are the invented ones from _fx.py
(handle "fakeuser9", name "Fakey McFakeface", host "fakebox-alpha", email "fakeuser9@fakecorp.test").
"""
import unittest

import _fx
import release_gate
import scrub_release as sr
from _fx import VALUES
from test_gate_hardening import GateBase
from test_redteam6_fixes import gate_cli

URL = "https://github.com/fakeuser9/demo-repo"
MAIL = "fakeuser9@contact-pub.example.test"   # (the fixture org "fakecorp" would rightly be refused: ORG_NAME)


class IdentityBase(GateBase):
    def declare(self, *entries, **more_values):
        """Rewrite the values file with a gate_public_identity list (and optionally changed values)."""
        vals = dict(VALUES)
        vals.update(more_values)
        self.e.write_values(vals, gate_public_identity=list(entries))

    def private_hits(self, text):
        self.put("a.txt", text)
        got = [f for f in self.findings() if f[0] in ("PRIVATE_VALUE", "PATTERN")]
        (self.comp / "a.txt").unlink()
        return got


class TestIdentityAllowed(IdentityBase):
    def test_url_is_a_finding_without_the_declaration_and_clean_with_it(self):
        self.assertTrue(self.private_hits("source: %s\n" % URL))
        self.declare(URL)
        self.assertEqual(self.private_hits("source: %s\n" % URL), [])

    def test_url_with_further_path_and_git_suffix(self):
        self.declare("https://github.com/fakeuser9")
        self.assertEqual(self.private_hits("a https://github.com/fakeuser9/other-repo.git b\n"), [])

    def test_email_is_clean_for_value_and_pattern_scans(self):
        self.declare(MAIL)
        self.assertEqual(self.private_hits("Contact: %s\n" % MAIL), [])

    def test_bare_handle_equal_to_a_handle_value(self):
        self.declare("fakeuser9")
        self.assertEqual(self.private_hits("by fakeuser9 here\n"), [])


class TestIdentityIsNarrow(IdentityBase):
    def test_owner_name_next_to_the_declared_url_is_still_caught(self):
        self.declare(URL)
        got = self.private_hits("by Fakey McFakeface, see %s\n" % URL)
        self.assertTrue(any(f[0] == "PRIVATE_VALUE" for f in got), got)

    def test_handle_elsewhere_in_the_same_line_is_still_caught(self):
        self.declare(URL)
        self.assertTrue(self.private_hits("%s and also fakeuser9 wrote it\n" % URL))

    def test_token_boundaries_longer_url_and_glued_text_are_not_blanked(self):
        self.declare(URL)
        self.assertTrue(self.private_hits("%s-fork\n" % URL), "longer repo name is a different token")
        self.assertTrue(self.private_hits("x%s\n" % URL), "glued to a preceding word")

    def test_case_sensitive(self):
        self.declare(URL)
        self.assertTrue(self.private_hits(URL.upper() + "\n"))

    def test_bare_handle_does_not_hide_a_longer_word(self):
        self.declare("fakeuser9")
        self.assertTrue(self.private_hits("xfakeuser9 fakeuser99\n"))


class TestIdentityRefusals(IdentityBase):
    def refused(self, *entries, **more_values):
        with self.assertRaises(sr.ScrubError) as cm:
            self.declare(*entries, **more_values)
            sr.load_values(self.e.values, self.e.release)
        return str(cm.exception)

    def test_bare_first_name_is_refused(self):
        msg = self.refused("Fakeyy", OWNER_FIRST="Fakeyy")      # 6+ chars, a name, not a handle
        self.assertIn("handle", msg)
        self.refused("Fakey")                                    # also too short / not a handle

    def test_bare_word_that_is_not_a_handle_value_is_refused(self):
        self.refused("somethingelse")

    def test_free_text_and_spaces_are_refused(self):
        self.refused("Fakey McFakeface")
        self.refused("contact me at fakeuser9@fakecorp.test")

    def test_entry_containing_a_hostname_value_is_refused(self):
        msg = self.refused("https://fakebox-alpha.example.net/fakeuser9")
        self.assertIn("HOST_PRIMARY", msg)
        self.assertNotIn("fakebox-alpha", msg, "the message must not print the phrase or the value")

    def test_entry_containing_the_workspace_name_is_refused(self):
        self.refused("https://github.com/fakeuser9/fakeworkspace1", WORKSPACE_NAME="fakeworkspace1")

    def test_email_with_a_private_host_is_refused(self):
        self.refused("fakeuser9@fakebox-alpha.example.net")

    def test_not_a_list_or_too_many_entries(self):
        self.e.write_values(VALUES, gate_public_identity="https://github.com/x/y")
        with self.assertRaises(sr.ScrubError):
            sr.load_values(self.e.values, self.e.release)


class TestIdentityReport(IdentityBase):
    def test_output_has_counts_and_masked_forms_only(self):
        self.declare(URL, MAIL)
        self.put("README.md", "see %s and %s\nagain %s\n" % (URL, MAIL, URL))
        code, out = gate_cli(self.stg, self.e)
        self.assertEqual(code, 0, out)
        self.assertIn("public identity: 2 declared", out)
        self.assertIn("3 occurrence(s) blanked in 1 file(s)", out)
        self.assertIn("comp/README.md x3", out)
        for secret in (URL, MAIL, "fakeuser9", "github.com"):
            self.assertNotIn(secret, out)
        self.assertIn("url:h***(%d)" % len(URL), out)

    def test_no_identity_line_when_not_declared(self):
        self.put("a.txt", "x\n")
        self.assertNotIn("public identity", gate_cli(self.stg, self.e)[1])

    def test_stats_dict(self):
        self.declare(URL)
        self.put("a.txt", URL + "\n")
        pv = sr.load_values(self.e.values, self.e.release)
        stats = {}
        release_gate.gate(self.stg, pv, self.e.release, stats=stats)
        self.assertEqual(stats["identity_blanked"], {"comp/a.txt": 1})


if __name__ == "__main__":
    unittest.main()
