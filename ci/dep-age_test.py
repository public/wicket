#!/usr/bin/env python3
"""Tests for ci/dep-age.py (run: python3 -I ci/dep-age_test.py). No network: publish times are injected."""
import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("dep_age", Path(__file__).with_name("dep-age.py"))
da = importlib.util.module_from_spec(spec)
spec.loader.exec_module(da)

CARGO = """version = 4

[[package]]
name = "serde"
version = "1.0.300"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "00"

[[package]]
name = "wicket-core"
version = "0.0.1"

[[package]]
name = "biscuit-auth"
version = "6.0.0"
source = "git+https://example.invalid/biscuit#abc"

[[package]]
name = "itoa"
version = "1.0.20"
source = "sparse+https://index.crates.io/"
"""

NPM = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "view"},
        "node_modules/vite": {"version": "7.0.0", "resolved": "https://registry.npmjs.org/vite/-/vite-7.0.0.tgz"},
        "node_modules/@scope/pkg": {
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
        },
        "node_modules/a/node_modules/b": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"},
        "node_modules/local": {"resolved": "../local", "link": True},
        "node_modules/elsewhere": {"version": "1.0.0", "resolved": "https://example.invalid/e.tgz"},
    },
}

NOW = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)


class Parsing(unittest.TestCase):
    def test_cargo_registry_only(self):
        self.assertEqual(
            da.cargo_packages(CARGO), {("crates.io", "serde", "1.0.300"), ("crates.io", "itoa", "1.0.20")}
        )

    def test_npm_registry_only_with_nested_and_scoped_names(self):
        self.assertEqual(
            da.npm_packages(json.dumps(NPM)),
            {("npm", "vite", "7.0.0"), ("npm", "@scope/pkg", "1.0.0"), ("npm", "b", "2.0.0")},
        )

    def test_empty_files(self):
        self.assertEqual(da.cargo_packages(""), set())
        self.assertEqual(da.npm_packages(""), set())
        self.assertEqual(da.vendored_packages(""), set())

    def test_vendored_package(self):
        v = 'ecosystem = "npm"\nname = "lit-html"\nversion = "3.3.3"\n\n[files]\n"lit-html.js" = "ab"\n'
        self.assertEqual(da.vendored_packages(v), {("npm", "lit-html", "3.3.3")})
        with self.assertRaises(ValueError):
            da.vendored_packages('ecosystem = "pypi"\nname = "x"\nversion = "1"\n')


class Check(unittest.TestCase):
    def ages(self, days):
        return lambda eco, name, version: NOW - dt.timedelta(days=days[name])

    def test_young_fails_old_passes(self):
        new = {("npm", "vite", "7.0.0"), ("crates.io", "serde", "1.0.300")}
        failures, notes = da.check(new, 7, {}, self.ages({"vite": 2, "serde": 30}), NOW)
        self.assertEqual(len(failures), 1)
        self.assertIn("npm vite 7.0.0: published 2 d", failures[0])
        self.assertEqual(notes, [])

    def test_boundary_is_inclusive(self):
        failures, _ = da.check({("npm", "vite", "7.0.0")}, 7, {}, self.ages({"vite": 7}), NOW)
        self.assertEqual(failures, [])

    def test_exception_allows_and_is_reported(self):
        pkg = ("crates.io", "serde", "1.0.300")
        exc = {pkg: {"advisory": "https://example.invalid/GHSA-1", "reason": "RCE in the wild"}}
        failures, notes = da.check({pkg}, 7, exc, self.ages({"serde": 1}), NOW)
        self.assertEqual(failures, [])
        self.assertIn("GHSA-1", notes[0])

    def test_exception_for_another_version_does_not_apply(self):
        exc = {("crates.io", "serde", "1.0.299"): {"advisory": "a", "reason": "r"}}
        failures, _ = da.check({("crates.io", "serde", "1.0.300")}, 7, exc, self.ages({"serde": 1}), NOW)
        self.assertEqual(len(failures), 1)


class Exceptions(unittest.TestCase):
    def write(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        f.write(text)
        f.close()
        return f.name

    def test_missing_file_is_empty(self):
        self.assertEqual(da.load_exceptions("/nonexistent/x.toml"), {})

    def test_commented_template_is_empty(self):
        self.assertEqual(da.load_exceptions(str(Path(__file__).with_name("dep-age-exceptions.toml"))), {})

    def test_advisory_and_reason_required(self):
        p = self.write('[[exception]]\necosystem = "npm"\nname = "x"\nversion = "1"\nreason = "r"\n')
        with self.assertRaises(SystemExit) as e:
            da.load_exceptions(p)
        self.assertIn("advisory", str(e.exception))

    def test_unknown_ecosystem(self):
        p = self.write('[[exception]]\necosystem = "pypi"\nname = "x"\nversion = "1"\nadvisory = "a"\nreason = "r"\n')
        with self.assertRaises(SystemExit):
            da.load_exceptions(p)

    def test_valid(self):
        p = self.write('[[exception]]\necosystem = "npm"\nname = "x"\nversion = "1"\nadvisory = "a"\nreason = "r"\n')
        self.assertIn(("npm", "x", "1"), da.load_exceptions(p))


if __name__ == "__main__":
    unittest.main()
