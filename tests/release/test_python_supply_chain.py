import json
import pathlib
import re
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "apps" / "api" / "Dockerfile"
RUNTIME_LOCK = ROOT / "requirements" / "runtime.lock"
BUILD_LOCK = ROOT / "requirements" / "build.lock"
ARTIFACTS = ROOT / "requirements" / "python-artifacts.json"
BASELINE = ROOT / "deploy" / "python-runtime-baseline.json"
VERIFIER = ROOT / "scripts" / "release" / "verify_python_supply_chain.sh"
LOCK_GENERATOR = ROOT / "scripts" / "release" / "update_python_locks.py"


def logical_requirements(path: pathlib.Path) -> list[str]:
    records: list[str] = []
    current = ""
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
            continue
        current += line
        records.append(current)
        current = ""
    if current:
        raise AssertionError(f"unterminated requirement in {path}")
    return records


class PythonSupplyChainTest(unittest.TestCase):
    def test_runtime_and_build_requirements_are_complete_hash_locks(self) -> None:
        for lock in (RUNTIME_LOCK, BUILD_LOCK):
            records = logical_requirements(lock)
            self.assertGreater(len(records), 0, lock)
            for record in records:
                self.assertRegex(record, r"^[A-Za-z0-9_.-]+==[^ ]+ ", record)
                hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", record)
                self.assertGreater(len(hashes), 0, record)
                self.assertEqual(len(hashes), len(set(hashes)), record)

        self.assertEqual(
            [record.split(" ", 1)[0] for record in logical_requirements(BUILD_LOCK)],
            ["setuptools==80.9.0"],
        )

    def test_artifact_evidence_matches_every_allowed_hash_and_platform(self) -> None:
        evidence = json.loads(ARTIFACTS.read_text())
        allowed_hashes = {
            digest
            for lock in (RUNTIME_LOCK, BUILD_LOCK)
            for record in logical_requirements(lock)
            for digest in re.findall(r"--hash=sha256:([0-9a-f]{64})", record)
        }
        artifacts = evidence["artifacts"]
        evidence_hashes = {artifact["sha256"] for artifact in artifacts}

        self.assertEqual(evidence_hashes, allowed_hashes)
        self.assertEqual(
            {platform for artifact in artifacts for platform in artifact["platforms"]},
            {"linux/amd64", "linux/arm64/v8"},
        )
        for artifact in artifacts:
            self.assertRegex(artifact["filename"], r"\.whl$")
            self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
            self.assertIn(artifact["kind"], {"runtime", "build"})

        required_platforms = {"linux/amd64", "linux/arm64/v8"}
        for kind, lock in (("runtime", RUNTIME_LOCK), ("build", BUILD_LOCK)):
            for record in logical_requirements(lock):
                requirement = record.split(" ", 1)[0].lower().replace("_", "-")
                platforms = {
                    platform
                    for artifact in artifacts
                    if artifact["kind"] == kind
                    and artifact["requirement"].lower().replace("_", "-")
                    == requirement
                    for platform in artifact["platforms"]
                }
                self.assertEqual(platforms, required_platforms, requirement)

    def test_project_metadata_is_covered_by_the_hash_locks(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        runtime_records = {
            record.split(" ", 1)[0].lower().replace("_", "-")
            for record in logical_requirements(RUNTIME_LOCK)
        }
        build_records = {
            record.split(" ", 1)[0].lower().replace("_", "-")
            for record in logical_requirements(BUILD_LOCK)
        }
        direct_dependencies = {
            dependency.lower().replace("_", "-").replace("[standard]", "")
            for dependency in project["project"]["dependencies"]
        }
        build_dependencies = {
            dependency.lower().replace("_", "-")
            for dependency in project["build-system"]["requires"]
        }

        self.assertLessEqual(direct_dependencies, runtime_records)
        self.assertEqual(build_dependencies, build_records)

    def test_lock_generator_resolves_the_dependency_closure(self) -> None:
        generator = LOCK_GENERATOR.read_text()

        self.assertIn('"pip",\n        "download",', generator)
        self.assertNotIn('"--no-deps"', generator)

    def test_base_image_evidence_pins_the_current_multiarch_index(self) -> None:
        baseline = json.loads(BASELINE.read_text())
        self.assertEqual(baseline["python_version"], "3.12.14")
        self.assertEqual(
            baseline["image"],
            "python:3.12.14-slim-bookworm@sha256:"
            "0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579",
        )
        self.assertEqual(
            baseline["platforms"]["linux/amd64"]["manifest_digest"],
            "sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab",
        )
        self.assertEqual(
            baseline["platforms"]["linux/arm64/v8"]["manifest_digest"],
            "sha256:457e0286fc132c4531ea071629ae6959095aa4074f172cd271aedb6950714ae6",
        )
        for platform in ("linux/amd64", "linux/arm64/v8"):
            package_evidence = baseline["platforms"][platform]["debian_packages"]
            self.assertEqual(package_evidence["count"], 105)
            self.assertEqual(
                package_evidence["normalized_sha256"],
                "82716765b3f4f2e6288f70414152ab9a8756e612279b88d19140fe04c4b79557",
            )
            self.assertEqual(package_evidence["libc6"], "2.36-9+deb12u14")
            self.assertEqual(package_evidence["libssl3"], "3.0.20-1~deb12u2")
            self.assertEqual(package_evidence["openssl"], "3.0.20-1~deb12u2")
        self.assertEqual(baseline["runtime_versions"]["expat"], "2.8.3")
        self.assertEqual(baseline["runtime_versions"]["openssl"], "3.0.20")

    def test_dockerfile_separates_hashed_downloads_from_offline_installs(self) -> None:
        dockerfile = DOCKERFILE.read_text()

        self.assertIn(
            "ARG PYTHON_BASE=python:3.12.14-slim-bookworm@sha256:"
            "0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579",
            dockerfile,
        )
        self.assertLess(dockerfile.index("ARG PYTHON_BASE="), dockerfile.index("FROM "))
        self.assertIn("AS python-artifacts", dockerfile)
        self.assertGreaterEqual(dockerfile.count("--require-hashes"), 4)
        self.assertGreaterEqual(dockerfile.count("--only-binary=:all:"), 2)
        self.assertGreaterEqual(dockerfile.count("--timeout=120"), 2)
        self.assertGreaterEqual(dockerfile.count("--retries=10"), 2)
        self.assertGreaterEqual(dockerfile.count("--no-index"), 3)
        self.assertIn("--no-build-isolation", dockerfile)
        self.assertIn("--no-deps", dockerfile)

        artifact_stage, offline_stages = dockerfile.split("AS python-app-build", 1)
        self.assertIn("pip download", artifact_stage)
        self.assertNotIn("pip download", offline_stages)
        self.assertNotIn("pip install --no-cache-dir -r", dockerfile)

    def test_verifier_rebuilds_offline_and_compares_two_clean_builds(self) -> None:
        verifier = VERIFIER.read_text()

        self.assertIn("docker buildx build", verifier)
        self.assertIn("--provenance=false", verifier)
        self.assertIn("type=oci", verifier)
        self.assertIn("rewrite-timestamp=true", verifier)
        self.assertIn("--network=none", verifier)
        self.assertIn("--no-cache", verifier)
        self.assertIn('--target "$target"', verifier)
        self.assertIn(
            '"python-artifacts=oci-layout://$PYTHON_ARTIFACT_LAYOUT@'
            '$python_artifact_manifest"',
            verifier,
        )
        self.assertIn(
            '"web-build=oci-layout://$WEB_ARTIFACT_LAYOUT@'
            '$web_artifact_manifest"',
            verifier,
        )
        self.assertLess(
            verifier.index("build_acquisition_stage python-artifacts"),
            verifier.index('build_clean_oci "$FIRST_OCI"'),
        )
        self.assertLess(
            verifier.index("build_acquisition_stage web-build"),
            verifier.index('build_clean_oci "$FIRST_OCI"'),
        )
        self.assertIn('build_clean_oci "$FIRST_OCI"', verifier)
        self.assertIn('build_clean_oci "$SECOND_OCI"', verifier)
        self.assertIn("SQLLENS_OFFLINE_PROOF_NONCE", verifier)
        self.assertIn("-m pip check", verifier)
        self.assertIn("reproducible OCI archive mismatch", verifier)
        self.assertIn("OCI manifest digest mismatch", verifier)
        self.assertIn("filesystem fingerprint mismatch", verifier)


if __name__ == "__main__":
    unittest.main()
