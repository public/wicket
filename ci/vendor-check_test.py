#!/usr/bin/env python3
"""Tests for ci/vendor-check.py: a matching directory passes; an edited, missing or extra file fails."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("vendor_check", Path(__file__).with_name("vendor-check.py"))
vc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc)

SHA_A = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"  # sha256("a")


def make(root: Path, files: dict[str, str], listed: dict[str, str]) -> Path:
    d = root / "vendor" / "pkg"
    d.mkdir(parents=True)
    for rel, text in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text)
    body = 'ecosystem = "npm"\nname = "pkg"\nversion = "1.0.0"\n\n[files]\n' + "".join(f'"{k}" = "{v}"\n' for k, v in listed.items())
    (d / "VENDOR.toml").write_text(body)
    return d / "VENDOR.toml"


class VendorCheck(unittest.TestCase):
    def test_a_matching_directory_passes(self):
        with tempfile.TemporaryDirectory() as t:
            m = make(Path(t), {"a.js": "a"}, {"a.js": SHA_A})
            self.assertEqual(vc.check(m), [])
            self.assertEqual(vc.manifests(Path(t)), [m])

    def test_an_edited_file_fails(self):
        with tempfile.TemporaryDirectory() as t:
            m = make(Path(t), {"a.js": "b"}, {"a.js": SHA_A})
            self.assertIn("records", " ".join(vc.check(m)))

    def test_a_missing_or_unlisted_file_fails(self):
        with tempfile.TemporaryDirectory() as t:
            m = make(Path(t), {"x/extra.js": "x"}, {"a.js": SHA_A})
            errs = " ".join(vc.check(m))
            self.assertIn("missing", errs)
            self.assertIn("not listed", errs)

    def test_experiments_are_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            make(Path(t) / "experiments", {"a.js": "b"}, {"a.js": SHA_A})
            self.assertEqual(vc.manifests(Path(t)), [])


if __name__ == "__main__":
    unittest.main()
