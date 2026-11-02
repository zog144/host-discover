"""Fail-closed evidence assembly regressions; no live credentials or network."""
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


wheel = module("tools/inventory_admin_credential_wheel_notices.py", "notice_wheel")



class AdministratorProvenanceTests(unittest.TestCase):
    def test_immutable_source_ledger_must_not_claim_legal_approval(self):
        data = json.loads((ROOT / "verification/admin-credential-source-provenance-2026-11-02.json").read_text())
        self.assertEqual(data["independent_rightsholder_permission"], "not-attested")
        self.assertEqual(data["distributable_notice_clearance"], "not-complete")
        self.assertEqual(data["production_pin_change"], "forbidden")
        self.assertEqual(len(data["revisions"]), 4)
        self.assertTrue(all(x["independent_rightsholder_permission"] == "pending-owner-evidence"
                            for x in data["revisions"]))

    def test_requirement_file_requires_exact_pins(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "requirements.txt"
            p.write_text("Example-Pkg==2.3\n# comment\nFoo_bar==0.1\n")
            self.assertEqual(wheel.expected_packages(p),
                             {"example-pkg": "2.3", "foo-bar": "0.1"})
            p.write_text("example>=2\n")
            with self.assertRaises(ValueError):
                wheel.expected_packages(p)
            p.write_text("foo==1\nfoo==1\n")
            with self.assertRaises(ValueError):
                wheel.expected_packages(p)

    def create_wheel(self, directory, *, name="demo", version="1.0", legal=True):
        location = directory / f"{name}-{version}-py3-none-any.whl"
        with zipfile.ZipFile(location, "w") as z:
            metadata = ("Metadata-Version: 2.4\nName: " + name
                        + "\nVersion: " + version
                        + "\nLicense-Expression: MIT\n")
            z.writestr(f"{name}-{version}.dist-info/METADATA", metadata)
            if legal:
                z.writestr(f"{name}-{version}.dist-info/licenses/LICENSE",
                           "Copyright original upstream author\nMIT terms.\n")
        return location

    def test_wheel_bytes_and_unmodified_notice_text_are_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.create_wheel(root)
            observed = wheel.inspect_wheels(root, {"demo": "1.0"})
            self.assertEqual(len(observed["demo"]["notices"]), 1)
            self.assertIn("original upstream author", observed["demo"]["notices"][0]["text"])
            output = root / "artifacts"
            wheel.write_evidence(observed, output)
            manifest = json.loads((output / "python-wheel-inventory.json").read_text())
            self.assertEqual(manifest["status"],
                             "wheel-artifact-observation-only-no-publication-approval")
            self.assertEqual(manifest["count"], 1)
            self.assertFalse(manifest["manual_review_required"])
            self.assertIn("MIT terms.", (output / "PYTHON-WHEEL-NOTICES.txt").read_text())

    def test_missing_or_substituted_wheel_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.create_wheel(root, version="1.1")
            with self.assertRaises(ValueError):
                wheel.inspect_wheels(root, {"demo": "1.0"})
            with self.assertRaises(ValueError):
                wheel.inspect_wheels(root, {"other": "1.1"})

    def test_missing_license_is_visible_not_assumed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.create_wheel(root, legal=False)
            observed = wheel.inspect_wheels(root, {"demo": "1.0"})
            output = root / "artifacts"
            wheel.write_evidence(observed, output)
            manifest = json.loads((output / "python-wheel-inventory.json").read_text())
            self.assertEqual(manifest["manual_review_required"], ["demo"])


if __name__ == "__main__":
    unittest.main()
