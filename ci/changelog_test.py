#!/usr/bin/env python3
"""Tests for ci/changelog.py (run: python3 -I ci/changelog_test.py)."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("changelog", Path(__file__).with_name("changelog.py"))
cl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cl)

LOG = """# Changelog

Intro.

## 0.0.2 (unreleased)

### DNS

- an existing DNS entry.

### Updates

- an existing update entry.

## 0.0.1 (unreleased)

- old.
"""


def frag(d: Path, name: str, area: str, kind: str, body: str) -> Path:
    p = d / name
    p.write_text(f"---\narea: {area}\ntype: {kind}\n---\n{body}", encoding="utf-8")
    return p


class Fragments(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cl.CHANGES = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_entries_go_under_their_area_in_type_order_and_new_areas_at_the_end(self):
        d = cl.CHANGES
        frag(d, "207.md", "Updates", "Added", "- jumps\n  across protocols (#207).\n")
        frag(d, "300.md", "Updates", "Fixed", "- a fix.\n")
        frag(d, "301.md", "Updates", "Security", "- a hole closed.\n")
        frag(d, "302.md", "Console", "Added", "- a page.\n")
        by_area, errors = cl.collect()
        self.assertEqual(errors, [])
        out = cl.merge(LOG, "0.0.2", by_area)
        sec = out.split("## 0.0.1")[0]
        self.assertIn(
            "### Updates\n\n- an existing update entry.\n- Security: a hole closed.\n- jumps\n  across protocols (#207).\n- Fixed: a fix.\n",
            sec,
        )
        self.assertIn("### DNS\n\n- an existing DNS entry.\n", sec)
        self.assertTrue(sec.rstrip().endswith("### Console\n\n- a page."), sec)
        self.assertIn("## 0.0.1 (unreleased)\n\n- old.", out, "older releases untouched")

    def test_a_missing_version_gets_its_section_above_the_others(self):
        frag(cl.CHANGES, "1.md", "Updates", "Changed", "- changed.\n")
        out = cl.merge(LOG, "0.0.3", cl.collect()[0])
        self.assertLess(out.index("## 0.0.3 (unreleased)"), out.index("## 0.0.2"))
        self.assertIn("## 0.0.3 (unreleased)\n\n### Updates\n\n- changed.\n", out)

    def test_bad_fragments_are_named(self):
        d = cl.CHANGES
        (d / "a.md").write_text("- no header\n", encoding="utf-8")
        frag(d, "b.md", "Updates", "Improved", "- x\n")
        frag(d, "c.md", "", "Added", "- x\n")
        frag(d, "d.md", "Updates", "Added", "just prose\n")
        (d / "README.md").write_text("not a fragment", encoding="utf-8")
        _, errors = cl.collect()
        self.assertEqual(len(errors), 4, errors)
        for name, why in [("a.md", "header"), ("b.md", "type"), ("c.md", "no area"), ("d.md", "neither an entry")]:
            self.assertTrue(any(e.startswith(name) and why in e for e in errors), (name, errors))


if __name__ == "__main__":
    unittest.main()
