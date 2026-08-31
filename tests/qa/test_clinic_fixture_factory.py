from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FACTORY_PATH = ROOT / "tests" / "fixtures" / "clinic" / "generate_archives.py"


def load_factory():
    spec = importlib.util.spec_from_file_location("clinic_fixture_factory", FACTORY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load fixture factory: {FACTORY_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ClinicFixtureFactoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.output = Path(self.temp_dir.name)

    def test_factory_generates_the_frozen_hostile_archive_corpus(self) -> None:
        factory = load_factory()
        manifest = factory.generate_corpus(self.output)

        expected_ids = {
            "valid_zip",
            "content_attack_zip",
            "zip_parent_traversal",
            "zip_absolute_path",
            "zip_windows_path",
            "zip_symlink",
            "zip_duplicate_name",
            "zip_case_collision",
            "zip_high_ratio",
            "zip_many_entries",
            "zip_nested_archive",
            "zip_truncated",
            "tar_parent_traversal",
            "tar_absolute_path",
            "tar_symlink",
            "tar_hardlink",
            "tar_character_device",
        }

        self.assertEqual({item["id"] for item in manifest["fixtures"]}, expected_ids)
        self.assertEqual(manifest["schemaVersion"], "clinic-corpus/v1")

    def test_content_attack_fixture_covers_untrusted_report_payloads(self) -> None:
        factory = load_factory()
        manifest = factory.generate_corpus(self.output)
        record = next(
            item for item in manifest["fixtures"] if item["id"] == "content_attack_zip"
        )

        self.assertEqual(record["expected"], "accept_as_untrusted")
        with zipfile.ZipFile(self.output / record["file"]) as archive:
            names = set(archive.namelist())
            combined = b"\n".join(archive.read(name) for name in archive.namelist())

        self.assertEqual(
            names,
            {
                "reports/summary.html",
                "exports/findings.csv",
                "reports/template.txt",
                "logs/tidb.log",
                "metrics/labels.json",
                "config/synthetic-secret.txt",
            },
        )
        for marker in (
            b"<script>",
            b"=HYPERLINK(",
            b"{{7*7}}",
            b"IGNORE ALL PREVIOUS INSTRUCTIONS",
            b"QA_CLINIC_EGRESS_CANARY_7F3A",
            b"QA_CLINIC_SECRET_CANARY_91C2",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, combined)
        self.assertNotIn(b".com", combined)

    def test_manifest_hashes_and_sizes_match_generated_files(self) -> None:
        factory = load_factory()
        manifest = factory.generate_corpus(self.output)

        for item in manifest["fixtures"]:
            fixture_path = self.output / item["file"]
            payload = fixture_path.read_bytes()
            self.assertEqual(item["bytes"], len(payload), item["id"])
            self.assertEqual(item["sha256"], hashlib.sha256(payload).hexdigest(), item["id"])

        persisted = json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(persisted, manifest)

    def test_valid_fixture_has_only_bounded_synthetic_evidence(self) -> None:
        factory = load_factory()
        factory.generate_corpus(self.output)

        with zipfile.ZipFile(self.output / "valid-clinic.zip") as archive:
            self.assertEqual(
                set(archive.namelist()),
                {
                    "config/tidb.toml",
                    "logs/tidb.log",
                    "metrics/overview.json",
                    "topology/nodes.json",
                },
            )
            all_text = "\n".join(
                archive.read(name).decode("utf-8") for name in archive.namelist()
            )

        self.assertNotIn("password", all_text.lower())
        self.assertNotIn("token", all_text.lower())
        self.assertNotIn("select ", all_text.lower())

    def test_generation_is_byte_for_byte_deterministic(self) -> None:
        factory = load_factory()
        first = factory.generate_corpus(self.output)
        hashes_before = {item["id"]: item["sha256"] for item in first["fixtures"]}

        second = factory.generate_corpus(self.output)
        hashes_after = {item["id"]: item["sha256"] for item in second["fixtures"]}

        self.assertEqual(hashes_after, hashes_before)


if __name__ == "__main__":
    unittest.main()
