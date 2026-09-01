#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EVIDENCE_DIR=${SQLLENS_SUPPLY_CHAIN_EVIDENCE_DIR:-"$(mktemp -d "${TMPDIR:-/tmp}/sqllens-supply-chain.XXXXXX")"}
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sqllens-supply-chain-build.XXXXXX")
PREFIX=${SQLLENS_SUPPLY_CHAIN_TAG_PREFIX:-sqllens-supply-chain-$$}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-"$(git -C "$ROOT" show -s --format=%ct HEAD)"}
FIRST_TAG="$PREFIX:first"
SECOND_TAG="$PREFIX:second"
OFFLINE_TAG="$PREFIX:offline"
FIRST_OCI="$BUILD_DIR/first.oci.tar"
SECOND_OCI="$BUILD_DIR/second.oci.tar"
PYTHON_ARTIFACT_OCI="$BUILD_DIR/python-artifacts.oci.tar"
WEB_ARTIFACT_OCI="$BUILD_DIR/web-artifacts.oci.tar"
PYTHON_ARTIFACT_LAYOUT="$BUILD_DIR/python-artifacts"
WEB_ARTIFACT_LAYOUT="$BUILD_DIR/web-artifacts"

trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM

case "$SOURCE_DATE_EPOCH" in
  ''|*[!0-9]*)
    printf '%s\n' 'SOURCE_DATE_EPOCH must be a non-negative integer' >&2
    exit 1
    ;;
esac

mkdir -p "$EVIDENCE_DIR"
docker buildx version > "$EVIDENCE_DIR/buildx-version.txt"

build_acquisition_stage() {
  target=$1
  destination=$2
  docker buildx build \
    --no-cache \
    --provenance=false \
    --target "$target" \
    --output "type=oci,dest=$destination" \
    -f "$ROOT/apps/api/Dockerfile" \
    "$ROOT"
}

build_clean_oci() {
  destination=$1
  docker buildx build \
    --no-cache \
    --network=none \
    --provenance=false \
    --build-context \
      "python-artifacts=oci-layout://$PYTHON_ARTIFACT_LAYOUT@$python_artifact_manifest" \
    --build-context \
      "web-build=oci-layout://$WEB_ARTIFACT_LAYOUT@$web_artifact_manifest" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --build-arg "SQLLENS_OFFLINE_PROOF_NONCE=offline-proof" \
    --output "type=oci,dest=$destination,rewrite-timestamp=true" \
    -f "$ROOT/apps/api/Dockerfile" \
    "$ROOT"
}

oci_manifest_digest() {
  python3 - "$1" <<'PY'
import json
import sys
import tarfile

with tarfile.open(sys.argv[1], "r") as archive:
    index = json.load(archive.extractfile("index.json"))
manifests = index.get("manifests", [])
if len(manifests) != 1:
    raise SystemExit("OCI output must contain exactly one image manifest")
print(manifests[0]["digest"])
PY
}

build_acquisition_stage python-artifacts "$PYTHON_ARTIFACT_OCI"
build_acquisition_stage web-build "$WEB_ARTIFACT_OCI"
mkdir -p "$PYTHON_ARTIFACT_LAYOUT" "$WEB_ARTIFACT_LAYOUT"
tar -xf "$PYTHON_ARTIFACT_OCI" -C "$PYTHON_ARTIFACT_LAYOUT"
tar -xf "$WEB_ARTIFACT_OCI" -C "$WEB_ARTIFACT_LAYOUT"
python_artifact_manifest=$(oci_manifest_digest "$PYTHON_ARTIFACT_OCI")
web_artifact_manifest=$(oci_manifest_digest "$WEB_ARTIFACT_OCI")
printf '%s  python-artifacts\n%s  web-artifacts\n' \
  "$python_artifact_manifest" "$web_artifact_manifest" \
  > "$EVIDENCE_DIR/acquisition-stage-digests.txt"

build_clean_oci "$FIRST_OCI"
build_clean_oci "$SECOND_OCI"

cmp -s "$FIRST_OCI" "$SECOND_OCI" \
  || { printf '%s\n' 'reproducible OCI archive mismatch between clean builds' >&2; exit 1; }
first_manifest=$(oci_manifest_digest "$FIRST_OCI")
second_manifest=$(oci_manifest_digest "$SECOND_OCI")
test "$first_manifest" = "$second_manifest" \
  || { printf '%s\n' 'OCI manifest digest mismatch between clean builds' >&2; exit 1; }
first_oci_sha=$(sha256sum "$FIRST_OCI" | awk '{print $1}')
second_oci_sha=$(sha256sum "$SECOND_OCI" | awk '{print $1}')
printf '%s  first.oci.tar\n%s  second.oci.tar\n%s  image-manifest\n' \
  "$first_oci_sha" "$second_oci_sha" "$first_manifest" \
  > "$EVIDENCE_DIR/reproducible-image-digests.txt"

docker load -i "$FIRST_OCI" > "$EVIDENCE_DIR/docker-load.txt"
docker image inspect "$first_manifest" > /dev/null
docker tag "$first_manifest" "$FIRST_TAG"
docker tag "$first_manifest" "$SECOND_TAG"
docker tag "$first_manifest" "$OFFLINE_TAG"

for tag in "$FIRST_TAG" "$SECOND_TAG" "$OFFLINE_TAG"; do
  key=$(printf '%s' "$tag" | tr ':/' '__')
  docker image inspect "$tag" > "$EVIDENCE_DIR/$key-image.json"
  docker run --rm --entrypoint python "$tag" -m pip check > "$EVIDENCE_DIR/$key-pip-check.txt"
  test "$(docker run --rm --entrypoint id "$tag" -u)" = "10001"
  docker run --rm -i --entrypoint python "$tag" - \
    < "$ROOT/scripts/release/python_image_fingerprint.py" \
    > "$EVIDENCE_DIR/$key-fingerprint.json"
done

first_key=$(printf '%s' "$FIRST_TAG" | tr ':/' '__')
second_key=$(printf '%s' "$SECOND_TAG" | tr ':/' '__')
offline_key=$(printf '%s' "$OFFLINE_TAG" | tr ':/' '__')

cmp -s \
  "$EVIDENCE_DIR/$first_key-fingerprint.json" \
  "$EVIDENCE_DIR/$second_key-fingerprint.json" \
  || { printf '%s\n' 'filesystem fingerprint mismatch between clean builds' >&2; exit 1; }
cmp -s \
  "$EVIDENCE_DIR/$first_key-fingerprint.json" \
  "$EVIDENCE_DIR/$offline_key-fingerprint.json" \
  || { printf '%s\n' 'filesystem fingerprint mismatch for egress-denied build' >&2; exit 1; }

python3 - "$ROOT" "$EVIDENCE_DIR/$first_key-fingerprint.json" \
  "$EVIDENCE_DIR/$first_key-image.json" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
fingerprint = json.loads(pathlib.Path(sys.argv[2]).read_text())
image = json.loads(pathlib.Path(sys.argv[3]).read_text())[0]
baseline = json.loads((root / "deploy/python-runtime-baseline.json").read_text())
expected_packages = baseline["platforms"]["linux/amd64"]["debian_packages"]

if fingerprint["python"] != baseline["python_version"]:
    raise SystemExit("runtime Python version does not match the pinned baseline")
if fingerprint["os_packages_count"] != expected_packages["count"]:
    raise SystemExit("runtime OS package count does not match the pinned baseline")
if fingerprint["os_packages_sha256"] != expected_packages["normalized_sha256"]:
    raise SystemExit("runtime OS package fingerprint does not match the pinned baseline")
labels = image.get("Config", {}).get("Labels", {}) or {}
expected_digest = baseline["image"].rsplit("@", 1)[1]
if labels.get("org.opencontainers.image.base.digest") != expected_digest:
    raise SystemExit("runtime base-image label does not match the pinned baseline")
PY

printf 'Python supply-chain verification passed. Evidence: %s\n' "$EVIDENCE_DIR"
