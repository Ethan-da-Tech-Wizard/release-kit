"""Tests for the hardened release gate and allowlist (text normalisation, fixture allowlist, name masking).

Covers:
  * normalisation before matching: zero-width, soft hyphen, fullwidth, accents, Cyrillic look-alike, \\u / \\x / &#
    escapes, adjacent string literals, value split over two lines (LF and CRLF), rot13, reversed, hex, base64 of
    case variants;
  * file NAMES holding a private value are never printed (masked as path#<n>);
  * an allowlisted fixture hides only itself: a pattern hit next to it is still reported, a fixture containing a
    private WORD is refused at load time, a wildcard-only path is refused;
  * check_placeholders.sh optional extra regex.

All values are the invented ones from _fx.py (owner handle "fakeuser9", host "fakebox-alpha", ...).  Look-alike and
invisible characters are written as \\u escapes so this file stays plain ASCII.
"""
import base64
import codecs
import contextlib
import io
import os
import subprocess
import unittest

import _fx
from _fx import Env, VALUES

import allowlist as al
import normalize
import release_gate
import scrub_release as sr

H = "fakeuser9"          # the invented owner handle (9 chars: long enough for rot13/reversed scanning)


class GateBase(unittest.TestCase):
    """A fake staging tree <tmp>/stg/comp with an ANNOTATIONS.json, scanned through the library gate()."""

    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.cleanup)
        self.stg = self.e.tmp / "stg"
        self.comp = self.stg / "comp"
        self.comp.mkdir(parents=True)
        (self.comp / "ANNOTATIONS.json").write_text('{"replacements": []}\n')

    def put(self, name, text):
        """Write TEXT (str -> utf-8) or bytes to comp/NAME."""
        p = self.comp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))

    def findings(self, allow=None):
        """Run the gate; -> list of (category, detail, shown path, line)."""
        pv = sr.load_values(self.e.values, self.e.release)
        return release_gate.gate(self.stg, pv, self.e.release, (), allow)[1]

    def hits(self, text, name="a.txt"):
        """Details of PRIVATE_VALUE findings when TEXT is the only file's content."""
        self.put(name, text)
        out = {f[1] for f in self.findings() if f[0] == "PRIVATE_VALUE"}
        (self.comp / name).unlink()
        return out


class TestNormalisedMatching(GateBase):
    """Each trick that used to give a false PASS is now a PRIVATE_VALUE finding."""

    def assertCaught(self, text):
        self.assertTrue(self.hits(text), "not detected: %r" % text)

    def test_plain_baseline_is_detected_and_clean_text_is_not(self):
        self.assertIn("OWNER_HANDLE", self.hits("hello %s\n" % H))
        self.assertEqual(self.hits("nothing private here, just words\n"), set())

    def test_zero_width_space_and_joiner_and_bom(self):
        for ch in ("\u200b", "\u200d", "\ufeff", "\u2060"):
            self.assertCaught("fake%suser9\n" % ch)

    def test_soft_hyphen(self):
        self.assertCaught("fake\u00aduser9\n")

    def test_fullwidth_letters(self):
        self.assertCaught("".join(chr(ord(c) + 0xFEE0) if c.isalpha() else c for c in H) + "\n")

    def test_accents(self):
        self.assertCaught("f\u00e1k\u00e9\u00fcser9\n")          # f a-acute k e-acute u-diaeresis s e r 9

    def test_cyrillic_lookalikes(self):
        self.assertCaught("f\u0430k\u0435us\u0435r9\n")          # Cyrillic a, e, e in place of Latin

    def test_unicode_and_hex_escapes_and_html_entities(self):
        self.assertCaught("\\u0066akeuser9\n")                    # \u0066 = f
        self.assertCaught("\\x66akeuser9\n")
        self.assertCaught("&#102;akeuser9\n")
        self.assertCaught("&#x66;akeuser9\n")

    def test_adjacent_string_literals(self):
        self.assertCaught('x = "fake" + "user9"\n')
        self.assertCaught("x = 'fake' 'user9'\n")

    def test_value_split_over_two_lines_lf_and_crlf_and_indented(self):
        self.assertIn("OWNER_HANDLE", self.hits("fake\nuser9\n"))
        self.assertCaught("fake\r\nuser9\r\n")
        self.assertCaught("fake\n      user9\n")

    def test_split_hit_is_reported_at_first_line(self):
        self.put("a.txt", "ok line\nfake\nuser9\n")
        lines = {f[3] for f in self.findings() if f[0] == "PRIVATE_VALUE"}
        self.assertEqual(lines, {2})

    def test_multiword_value_split_over_lines(self):
        self.assertCaught("Fakey\nMcFakeface\n")

    def test_rot13(self):
        self.assertIn("OWNER_HANDLE:rot13", self.hits(codecs.encode(H, "rot13") + "\n"))

    def test_reversed(self):
        self.assertIn("OWNER_HANDLE:reversed", self.hits(H[::-1] + "\n"))

    def test_hex_any_case_and_separators(self):
        raw = H.encode()
        self.assertCaught(raw.hex() + "\n")
        self.assertCaught(raw.hex().upper() + "\n")
        self.assertCaught(" ".join("%02x" % b for b in raw) + "\n")
        self.assertCaught(H.upper().encode().hex() + "\n")        # hex of the UPPER-case spelling

    def test_base64_of_case_variants(self):
        for variant in (H, H.upper(), H.title(), H.capitalize()):
            enc = base64.b64encode(variant.encode()).decode()
            self.assertCaught("token=%s\n" % enc)

    def test_ordinary_text_does_not_trip_rot13_or_reversed(self):
        self.assertEqual(self.hits("The quick brown fox jumps over the lazy dog 0123456789\n"), set())

    def test_pattern_hidden_by_unicode_is_caught(self):
        self.put("a.txt", "mail zed@elsewhere.test\n".replace("@", "\uff20"))   # fullwidth commercial at
        self.assertTrue(any(f[0] == "PATTERN" for f in self.findings()))


    def test_fake_secret_built_from_pieces_is_not_a_pattern_finding(self):
        """Test code builds fake tokens from pieces on purpose; joining literals must not turn them into PATTERN hits
        (regression: the real staging tree has such fixtures)."""
        self.put("t.py", 'KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"\nH = "testbox" + ".local"\n')
        self.assertEqual([f for f in self.findings() if f[0] == "PATTERN"], [])


class TestMoreEvasions(GateBase):
    """Cases that used to slip through: full percent-encoding, odd line separators, more escape syntaxes,
    entities without a semicolon, separators inside a single-word value."""

    def assertCaught(self, text, name="a.txt"):
        self.assertTrue(self.hits(text, name), "not detected: %r" % text)

    def test_full_percent_encoding_and_double_encoding(self):
        enc = "".join("%%%02x" % b for b in H.encode())
        self.assertCaught("q=%s\n" % enc)
        self.assertCaught("q=%s\n" % enc.upper())
        self.assertCaught("q=%s\n" % enc.replace("%", "%25"))      # double encoded

    def test_percent_encoded_name_in_a_path_is_caught_and_masked(self):
        enc = "".join("%%%02x" % b for b in H.encode())
        self.put("dir_%s/f.txt" % enc, "plain\n")
        f = [x for x in self.findings() if x[0] == "PRIVATE_VALUE"]
        self.assertTrue(f)
        self.assertTrue(all(x[2].startswith("path#") for x in f))

    def test_vt_ff_nel_ls_ps_inside_a_word(self):
        for ch in ("\x0b", "\x0c", "\x85", "\u2028", "\u2029"):
            self.assertCaught("fake%suser9\n" % ch)

    def test_big_U_and_braced_u_escapes(self):
        self.assertCaught("\\U00000066akeuser9\n")
        self.assertCaught("\\u{66}akeuser9\n")

    def test_entities_without_semicolon(self):
        self.assertCaught("&#102akeuser9\n")
        self.assertCaught("&#x66;akeuser9\n")                      # hex form, with semicolon
        self.assertCaught("fake&#x75ser9\n")                        # hex, no semicolon, next char is not a hex digit

    def test_separators_inside_a_single_word_value(self):
        for sep in ("-", " ", ".", "_", "+"):
            self.assertCaught(sep.join(H) + "\n")

    def test_percent_decode_keeps_invalid_sequences(self):
        self.assertEqual(normalize.percent_decode("100%zz %ff"), "100%zz %ff")
        self.assertEqual(normalize.percent_decode("%257a%2"), "z%2")

    def test_ordinary_percent_text_stays_clean(self):
        self.assertEqual(self.hits("progress 50% done, url a%20b, format %s %d\n"), set())


class TestNormalizeModule(unittest.TestCase):
    def test_fold_examples(self):
        self.assertEqual(normalize.fold("Ze\u200bb\u00e9\u00adx"), "Zebex")
        self.assertEqual(normalize.fold("&#90;\\u0065"), "Ze")
        self.assertEqual(normalize.fold('"ab" + "cd"'), '"abcd"')
        self.assertEqual(normalize.fold("a\r\nb"), "a\nb")

    def test_rot13_is_involution(self):
        self.assertEqual(normalize.rot13(normalize.rot13("Hello")), "Hello")


class TestNameMasking(GateBase):
    def test_private_value_in_file_and_dir_name_is_never_printed(self):
        self.put("dir_%s/file_%s.txt" % (H, H), "plain\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = release_gate.main(["--staging", str(self.stg), "--values", str(self.e.values),
                                      "--release-root", str(self.e.release)])
        out = buf.getvalue()
        self.assertEqual(code, 1)
        self.assertNotIn(H, out)
        self.assertIn("path#", out)
        self.assertIn("PRIVATE_VALUE[OWNER_HANDLE]", out)

    def test_clean_names_still_printed_in_clear(self):
        self.put("good.txt", "x {{HOST}} 192.168.1.5\n")
        shown = {f[2] for f in self.findings()}
        self.assertEqual(shown, {"comp/good.txt"})

    def test_index_matches_sorted_listing(self):
        self.put("b_%s.txt" % H, "plain\n")
        self.put("a.txt", "plain\n")
        f = [x for x in self.findings() if x[0] == "PRIVATE_VALUE"]
        paths = sorted(p.relative_to(self.stg).as_posix() for p in self.stg.rglob("*"))
        n = [i for i, p in enumerate(paths, 1) if H in p]
        self.assertEqual({x[2] for x in f}, {"path#%d" % n[0]})


class TestFixtureAllowlistHardening(GateBase):
    FIXTURE = "ghp_" + "Q" * 36

    def _allow(self, strings, path="t.py"):
        return al.Allowlist({"fixtures": [{"path": path, "strings": strings, "reason": "test input"}]},
                            VALUES.values())

    def test_fixture_hides_only_itself_from_pattern_scan(self):
        self.put("t.py", 'A = "%s"\nB = "me@elsewhere.test"\n' % self.FIXTURE)
        f = self.findings(self._allow([self.FIXTURE]))
        self.assertEqual({(x[0], x[3]) for x in f}, {("PATTERN", 2)})     # the email on line 2 is still found

    def test_pattern_hit_on_same_line_next_to_fixture_is_still_reported(self):
        self.put("t.py", 'A = "%s" + "me@elsewhere.test"\n' % self.FIXTURE)
        f = self.findings(self._allow([self.FIXTURE]))
        self.assertTrue(any(x[0] == "PATTERN" and x[1] == "EMAIL" for x in f), f)

    def test_fixture_with_private_word_is_refused(self):
        with self.assertRaises(al.AllowlistError):
            self._allow(["fakeuser9-test-data"])
        with self.assertRaises(al.AllowlistError):
            self._allow(["Fakey-sample-str"])           # a word of the owner-name value
        with self.assertRaises(al.AllowlistError):
            self._allow(["f\u00e1keuser9_sample"])      # accented spelling is folded before comparing

    def test_wildcard_only_path_is_refused(self):
        for bad in ("*", "**", "*/*", "?"):
            with self.assertRaises(al.AllowlistError):
                self._allow([self.FIXTURE], path=bad)

    def test_shipped_example_allowlist_loads(self):
        """Proves examples/example_allowlist.json is a valid allowlist (so the README example cannot rot)."""
        a = al.load_allowlist(str(_fx.TOOLS / "examples" / "example_allowlist.json"), VALUES.values())
        self.assertTrue(a.fixture_strings("tests/test_detector.py"))

    def test_ordinary_fixture_is_accepted(self):
        self.assertTrue(self._allow([self.FIXTURE]).fixture_strings("t.py"))


class TestPlaceholderScriptExtra(unittest.TestCase):
    """The shipped templates/check_placeholders.sh: optional extra rule via environment."""
    SCRIPT = str(_fx.TOOLS / "templates" / "check_placeholders.sh")

    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.cleanup)

    def run_script(self, root, extra_env=None):
        e = {k: v for k, v in os.environ.items() if k != "CHECK_PLACEHOLDERS_EXTRA_REGEX"}
        e.update(extra_env or {})
        return subprocess.run(["bash", self.SCRIPT, str(root)], capture_output=True, text=True, env=e)

    def test_extra_regex_off_by_default_and_on_when_set(self):
        d = self.e.tmp / "x"
        d.mkdir()
        (d / "a.md").write_text("project Moonbase notes\n")
        self.assertEqual(self.run_script(d).returncode, 0)
        r = self.run_script(d, {"CHECK_PLACEHOLDERS_EXTRA_REGEX": "Moonbase"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("custom private pattern", r.stdout)

    def test_overclaim_words_rule_is_opt_in(self):
        """A README that says "production-grade" passes by default; the house-style rule runs only when asked for."""
        d = self.e.tmp / "oc"
        d.mkdir()
        (d / "README.md").write_text("A production-grade tool.\n")
        self.assertEqual(self.run_script(d).returncode, 0)
        r = self.run_script(d, {"CHECK_PLACEHOLDERS_OVERCLAIM": "1"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("overclaim words", r.stdout)

    def test_sk_token_needs_a_word_boundary(self):
        """A hyphenated ordinary word ending in "sk-" plus 20+ letters is not a token (same rule as the scrubber);
        a bare token shape is still flagged."""
        d = self.e.tmp / "sk"
        d.mkdir()
        (d / "a.md").write_text("see disk-" + "allocationstrategyinfo2" + " for details\n")
        self.assertEqual(self.run_script(d).returncode, 0)
        (d / "b.md").write_text("key = sk-" + "A" * 24 + "\n")
        self.assertEqual(self.run_script(d).returncode, 1)


if __name__ == "__main__":
    unittest.main()
