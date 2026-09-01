#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EVIDENCE_DIR=${SQLLENS_SUPPLY_CHAIN_EVIDENCE_DIR:-"$(mktemp -d "${TMPDIR:-/tmp}/sqllens-supply-chain.XXXXXX")"}
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sqllens-supply-chain-build.XXXXXX")
BUILD_ROOT="$BUILD_DIR/source"
PREFIX=${SQLLENS_SUPPLY_CHAIN_TAG_PREFIX:-sqllens-supply-chain-$$}
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

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

ensure_source_clean() {
  source_root=$1
  status=$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)
  if [ -n "$status" ]; then
    first_change=$(printf '%s\n' "$status" | sed -n '1p')
    fail "release source has uncommitted changes: $first_change"
  fi
}

ensure_source_clean "$ROOT"
SOURCE_REVISION=$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')
EXPECTED_REVISION=${SQLLENS_SOURCE_REVISION:-$SOURCE_REVISION}
test "$EXPECTED_REVISION" = "$SOURCE_REVISION" \
  || fail "expected source revision $EXPECTED_REVISION does not match HEAD $SOURCE_REVISION"
test "${#SOURCE_REVISION}" -eq 40 \
  || fail "source revision must be a full 40-character Git commit"
case "$SOURCE_REVISION" in
  *[!0-9a-f]*) fail "source revision must be lowercase hexadecimal" ;;
esac

SOURCE_GIT_TREE=$(git -C "$ROOT" rev-parse --verify "$SOURCE_REVISION^{tree}")
VERIFIER_GIT_BLOB=$(git -C "$ROOT" rev-parse --verify \
  "$SOURCE_REVISION:scripts/release/verify_python_supply_chain.sh")
DOCKERFILE_GIT_BLOB=$(git -C "$ROOT" rev-parse --verify \
  "$SOURCE_REVISION:apps/api/Dockerfile")
FINGERPRINT_GIT_BLOB=$(git -C "$ROOT" rev-parse --verify \
  "$SOURCE_REVISION:scripts/release/python_image_fingerprint.py")

test "$(git -C "$ROOT" hash-object --no-filters \
  "$ROOT/scripts/release/verify_python_supply_chain.sh")" = "$VERIFIER_GIT_BLOB" \
  || fail "supply-chain verifier does not match the source revision"
test "$(git -C "$ROOT" hash-object --no-filters \
  "$ROOT/apps/api/Dockerfile")" = "$DOCKERFILE_GIT_BLOB" \
  || fail "runtime Dockerfile does not match the source revision"
test "$(git -C "$ROOT" hash-object --no-filters \
  "$ROOT/scripts/release/python_image_fingerprint.py")" = "$FINGERPRINT_GIT_BLOB" \
  || fail "runtime fingerprint tool does not match the source revision"

git clone --quiet --no-checkout --no-hardlinks "$ROOT" "$BUILD_ROOT"
git -C "$BUILD_ROOT" checkout --detach --quiet "$SOURCE_REVISION"
test "$(git -C "$BUILD_ROOT" rev-parse --verify 'HEAD^{commit}')" = "$SOURCE_REVISION" \
  || fail "isolated checkout revision mismatch"
test "$(git -C "$BUILD_ROOT" rev-parse --verify 'HEAD^{tree}')" = "$SOURCE_GIT_TREE" \
  || fail "isolated checkout tree mismatch"
test "$(git -C "$BUILD_ROOT" rev-parse --verify \
  "$SOURCE_REVISION:scripts/release/verify_python_supply_chain.sh")" = "$VERIFIER_GIT_BLOB" \
  || fail "isolated verifier blob mismatch"
test "$(git -C "$BUILD_ROOT" rev-parse --verify \
  "$SOURCE_REVISION:apps/api/Dockerfile")" = "$DOCKERFILE_GIT_BLOB" \
  || fail "isolated Dockerfile blob mismatch"
ensure_source_clean "$BUILD_ROOT"

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-"$(git -C "$BUILD_ROOT" show -s --format=%ct "$SOURCE_REVISION")"}
case "$SOURCE_DATE_EPOCH" in
  ''|*[!0-9]*) fail 'SOURCE_DATE_EPOCH must be a non-negative integer' ;;
esac

mkdir -p "$EVIDENCE_DIR"
python3 - "$EVIDENCE_DIR/source-identity.json" \
  "$SOURCE_REVISION" "$SOURCE_GIT_TREE" "$VERIFIER_GIT_BLOB" \
  "$DOCKERFILE_GIT_BLOB" "$FINGERPRINT_GIT_BLOB" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
identity = {
    "dockerfile_git_blob": sys.argv[5],
    "fingerprint_tool_git_blob": sys.argv[6],
    "source_git_tree": sys.argv[3],
    "source_revision": sys.argv[2],
    "verifier_git_blob": sys.argv[4],
}
path.write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n")
PY
docker buildx version > "$EVIDENCE_DIR/buildx-version.txt"

build_acquisition_stage() {
  target=$1
  destination=$2
  docker buildx build \
    --no-cache \
    --provenance=false \
    --target "$target" \
    --output "type=oci,dest=$destination" \
    -f "$BUILD_ROOT/apps/api/Dockerfile" \
    "$BUILD_ROOT"
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
    --build-arg "SOURCE_REVISION=$SOURCE_REVISION" \
    --build-arg "SOURCE_GIT_TREE=$SOURCE_GIT_TREE" \
    --build-arg "DOCKERFILE_GIT_BLOB=$DOCKERFILE_GIT_BLOB" \
    --build-arg "SUPPLY_CHAIN_VERIFIER_GIT_BLOB=$VERIFIER_GIT_BLOB" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --build-arg "SQLLENS_OFFLINE_PROOF_NONCE=offline-proof" \
    --output "type=oci,dest=$destination,rewrite-timestamp=true" \
    -f "$BUILD_ROOT/apps/api/Dockerfile" \
    "$BUILD_ROOT"
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
  || fail 'reproducible OCI archive mismatch between clean builds'
first_manifest=$(oci_manifest_digest "$FIRST_OCI")
second_manifest=$(oci_manifest_digest "$SECOND_OCI")
test "$first_manifest" = "$second_manifest" \
  || fail 'OCI manifest digest mismatch between clean builds'
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
    < "$BUILD_ROOT/scripts/release/python_image_fingerprint.py" \
    > "$EVIDENCE_DIR/$key-fingerprint.json"
done

first_key=$(printf '%s' "$FIRST_TAG" | tr ':/' '__')
second_key=$(printf '%s' "$SECOND_TAG" | tr ':/' '__')
offline_key=$(printf '%s' "$OFFLINE_TAG" | tr ':/' '__')

cmp -s \
  "$EVIDENCE_DIR/$first_key-fingerprint.json" \
  "$EVIDENCE_DIR/$second_key-fingerprint.json" \
  || fail 'filesystem fingerprint mismatch between clean builds'
cmp -s \
  "$EVIDENCE_DIR/$first_key-fingerprint.json" \
  "$EVIDENCE_DIR/$offline_key-fingerprint.json" \
  || fail 'filesystem fingerprint mismatch for egress-denied build'

python3 - "$BUILD_ROOT" "$EVIDENCE_DIR/$first_key-fingerprint.json" \
  "$EVIDENCE_DIR/$first_key-image.json" "$SOURCE_REVISION" \
  "$SOURCE_GIT_TREE" "$DOCKERFILE_GIT_BLOB" "$VERIFIER_GIT_BLOB" <<'PY'
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
expected_labels = {
    "org.opencontainers.image.revision": sys.argv[4],
    "dev.sqllens.source.git-tree": sys.argv[5],
    "dev.sqllens.build.dockerfile.git-blob": sys.argv[6],
    "dev.sqllens.build.verifier.git-blob": sys.argv[7],
}
for name, expected in expected_labels.items():
    if labels.get(name) != expected:
        raise SystemExit(f"runtime source identity label mismatch: {name}")
PY

ensure_source_clean "$BUILD_ROOT"
test "$(git -C "$BUILD_ROOT" rev-parse --verify 'HEAD^{commit}')" = "$SOURCE_REVISION" \
  || fail "isolated checkout revision changed during verification"
test "$(git -C "$BUILD_ROOT" rev-parse --verify 'HEAD^{tree}')" = "$SOURCE_GIT_TREE" \
  || fail "isolated checkout tree changed during verification"
ensure_source_clean "$ROOT"
test "$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')" = "$SOURCE_REVISION" \
  || fail "source revision changed during verification"
test "$(git -C "$ROOT" rev-parse --verify 'HEAD^{tree}')" = "$SOURCE_GIT_TREE" \
  || fail "source tree changed during verification"

printf 'Python supply-chain verification passed. Evidence: %s\n' "$EVIDENCE_DIR"
