"""Tests for reannotate.py: annotations must match the FINAL staged text, with no hashes in the public JSON.

Why: scrubbing writes annotations early, but later edits can move or remove
placeholders.  reannotate.py regenerates them from the staged files, so the
published line/column pointers are always correct and never carry private hashes.

All fixture content is synthetic (a fake licence line and a made-up stale record).

Run (from the tools directory):  python3 -B -m unittest discover -s tests
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import reannotate
import release_gate  # noqa: F401  (import check only)

# The placeholder text "{{COPYRIGHT_HOLDER}}", assembled from pieces so this source file
# itself contains no literal token that other scanners might pick up.
TOK = "{" + "{COPYRIGHT_HOLDER}" + "}"


class TestReannotate(unittest.TestCase):
    """Behaviour tests for reannotate.main on a tiny synthetic staging tree."""
    def setUp(self):
        """Build a staging tree with one component: a LICENSE containing one placeholder, a
        placeholder-free source file, and a STALE annotation file (hash plus a placeholder
        that no longer exists) like an earlier scrub could leave behind.  All content is synthetic.
        """
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.c = self.root / "staging" / "comp"
        self.c.mkdir(parents=True)
        (self.c / "LICENSE").write_text("MIT\n\nCopyright (c) 2026 " + TOK + "\n")
        (self.c / "a.py").write_text("x = 1\n# no placeholder\n")
        # stale annotation with a hash and a phantom token, as left by an earlier scrub
        (self.c / "ANNOTATIONS.json").write_text(json.dumps({"replacements": [
            {"key": "GONE_1", "hash": "0" * 32, "file": "a.py", "line": 1, "column": 1}], "refused": []}))

    def run_tool(self):
        """Run reannotate.main on the temp staging directory with stdout silenced; return its exit code."""
        with contextlib.redirect_stdout(io.StringIO()):
            return reannotate.main(["--staging", str(self.root / "staging")])

    def test_finds_real_token_and_drops_phantom(self):
        """Proves annotations are recomputed from the final text: the real token is listed with
        the correct line and column, the phantom one disappears, and no "hash" field remains
        in the public JSON.
        """
        self.assertEqual(self.run_tool(), 0)
        pub = json.loads((self.c / "ANNOTATIONS.json").read_text())
        self.assertEqual([r["key"] for r in pub["replacements"]], ["COPYRIGHT_HOLDER"])
        r = pub["replacements"][0]
        self.assertEqual((r["file"], r["line"], r["column"]), ("LICENSE", 3, len("Copyright (c) 2026 ") + 1))
        line = (self.c / "LICENSE").read_text().split("\n")[r["line"] - 1]
        self.assertEqual(line[r["column"] - 1:r["column"] - 1 + len(r["placeholder"])], r["placeholder"])
        self.assertNotIn("hash", json.dumps(pub))
        self.assertNotIn("GONE_1", (self.c / "ANNOTATIONS.md").read_text())

    def test_md_has_specific_meaning_and_index(self):
        """Proves the Markdown annotation mentions the token's specific meaning and its
        file:line, and that a cross-component placeholder index is written.
        """
        self.run_tool()
        md = (self.c / "ANNOTATIONS.md").read_text()
        self.assertIn("copyright", md.lower())
        self.assertIn("LICENSE:3:", md)
        idx = (self.root / "staging" / "PLACEHOLDERS_INDEX.md").read_text()
        self.assertIn("COPYRIGHT_HOLDER", idx)

    def test_no_tokens_means_empty_but_valid(self):
        """Proves a component with no placeholders still gets a valid, empty annotation file
        and an explanatory Markdown message.
        """
        (self.c / "LICENSE").write_text("MIT\n")
        self.run_tool()
        pub = json.loads((self.c / "ANNOTATIONS.json").read_text())
        self.assertEqual(pub["replacements"], [])
        self.assertIn("No placeholders remain", (self.c / "ANNOTATIONS.md").read_text())


if __name__ == "__main__":
    unittest.main()
