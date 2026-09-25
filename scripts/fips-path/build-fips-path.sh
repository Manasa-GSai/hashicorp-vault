#!/usr/bin/env bash
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1
#
# build-fips-path.sh — orchestrate a local FIPS-path Vault build using the
# golang-fips/go toolchain container and emit a machine-readable provenance
# artifact at .release/fips-path-provenance.json.
#
# This script is the LOCAL equivalent of the CI step in
# .github/actions/build-vault/action.yml (fips-path: true).
# It does not replace the default developer build (make dev / make bin).
#
# PREREQUISITES
#   - Docker with BuildKit support
#   - Sufficient disk space for the fips-path-builder image (~2 GB)
#   - Network access to github.com/golang-fips/go releases and apt mirrors
#     (or a pre-pulled local image — see VAULT_FIPS_BUILDER_IMAGE below)
#
# USAGE
#   ./scripts/fips-path/build-fips-path.sh
#
# ENVIRONMENT
#   VAULT_VERSION              Vault version string to embed (default: read from version/)
#   FIPS_PATH_PROVENANCE_OUT   Output path for provenance JSON (default: .release/fips-path-provenance.json)
#   VAULT_FIPS_BUILDER_IMAGE   Pre-built Docker image tag to use instead of building locally.
#                              When set, the Docker build step is skipped and the image is
#                              pulled/used as-is.  The tag must be in the format
#                              "vault-fips-path-builder:<tag>".
#   DOCKER_BUILDKIT            Docker BuildKit flag (default: 1)
#   SKIP_TOOLCHAIN_DETECT      Set to "1" to skip the toolchain detection step (CI use only).
#
# OUTPUT
#   .release/fips-path-provenance.json (or FIPS_PATH_PROVENANCE_OUT)
#
# NON-VALIDATION BOUNDARY STATEMENT
#   This build uses the golang-fips/go toolchain which routes Go crypto operations
#   through system OpenSSL.  The resulting OSS binary is NOT a CMVP-validated or
#   FIPS 140-3 certified cryptographic module.  See FIPS-140-3-COMPLIANCE.md for
#   the full OSS posture boundary.

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate repo root and source toolchain config
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

FIPS_TOOLCHAIN_ENV="${SCRIPT_DIR}/golang-fips-toolchain.env"

if [[ ! -f "${FIPS_TOOLCHAIN_ENV}" ]]; then
  echo "ERROR: ${FIPS_TOOLCHAIN_ENV} not found." >&2
  echo "  Expected at: scripts/fips-path/golang-fips-toolchain.env" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "${FIPS_TOOLCHAIN_ENV}"

# ---------------------------------------------------------------------------
# Resolve runtime parameters
# ---------------------------------------------------------------------------

DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}"
export DOCKER_BUILDKIT

# Default Vault version from the version package if not provided.
if [[ -z "${VAULT_VERSION:-}" ]]; then
  if [[ -f "${REPO_ROOT}/version/version.go" ]]; then
    VAULT_VERSION="$(grep 'Version\s*=' "${REPO_ROOT}/version/version.go" \
      | head -1 | sed 's/.*"\(.*\)".*/\1/')"
  else
    VAULT_VERSION="0.0.0-dev"
  fi
fi

GO_VERSION="$(cat "${REPO_ROOT}/.go-version" 2>/dev/null || echo "unknown")"
COMMIT_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")"
BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

BUILDER_IMAGE_TAG="${VAULT_FIPS_BUILDER_IMAGE:-vault-fips-path-builder:local}"
FIPS_PATH_PROVENANCE_OUT="${FIPS_PATH_PROVENANCE_OUT:-${REPO_ROOT}/.release/fips-path-provenance.json}"

# ---------------------------------------------------------------------------
# Step 1: Build or pull the fips-path-builder Docker image
# ---------------------------------------------------------------------------

if [[ -z "${VAULT_FIPS_BUILDER_IMAGE:-}" ]]; then
  echo "==> Building fips-path-builder Docker image ..."
  echo "    Base Go version : ${GO_VERSION}"
  echo "    golang-fips/go  : ${GOLANG_FIPS_VERSION}"
  echo "    OpenSSL package : ${OPENSSL_FIPS_PACKAGE}"
  echo ""

  docker build \
    --target fips-path-builder \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --build-arg "GOLANG_FIPS_VERSION=${GOLANG_FIPS_VERSION}" \
    --build-arg "OPENSSL_FIPS_PACKAGE=${OPENSSL_FIPS_PACKAGE}" \
    -f "${REPO_ROOT}/Dockerfile" \
    -t "${BUILDER_IMAGE_TAG}" \
    "${REPO_ROOT}"

  echo ""
  echo "    ✓ fips-path-builder image built: ${BUILDER_IMAGE_TAG}"
else
  echo "==> Using pre-built builder image: ${BUILDER_IMAGE_TAG}"
fi

# ---------------------------------------------------------------------------
# Step 2: Toolchain detection inside the container
# ---------------------------------------------------------------------------

if [[ "${SKIP_TOOLCHAIN_DETECT:-0}" != "1" ]]; then
  echo ""
  echo "==> Running toolchain detection inside the builder container ..."

  docker run --rm \
    -v "${SCRIPT_DIR}:/fips-scripts:ro" \
    -e "FIPS_TOOLCHAIN_ENV=/fips-scripts/golang-fips-toolchain.env" \
    "${BUILDER_IMAGE_TAG}" \
    bash /fips-scripts/detect-golang-fips-toolchain.sh

  echo "    ✓ Toolchain detection passed"
fi

# ---------------------------------------------------------------------------
# Step 3: Extract provenance data from the container
# ---------------------------------------------------------------------------

echo ""
echo "==> Extracting provenance metadata from the builder image ..."

GOLANG_FIPS_GO_VERSION="$(docker run --rm "${BUILDER_IMAGE_TAG}" \
  go version 2>/dev/null | awk '{print $3}' || echo "unknown")"

OPENSSL_REPORTED_VERSION="$(docker run --rm "${BUILDER_IMAGE_TAG}" \
  openssl version 2>/dev/null | awk '{print $1, $2}' || echo "openssl-unknown")"

BASE_IMAGE_DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' \
  "${BUILDER_IMAGE_TAG}" 2>/dev/null || echo "digest-unavailable")"

TARGET_PLATFORM="$(docker run --rm "${BUILDER_IMAGE_TAG}" \
  go env GOOS GOARCH 2>/dev/null | tr '\n' '/' | sed 's/\/$//' || echo "linux/amd64")"

echo "    golang-fips/go version  : ${GOLANG_FIPS_GO_VERSION}"
echo "    OpenSSL version         : ${OPENSSL_REPORTED_VERSION}"
echo "    Target platform         : ${TARGET_PLATFORM}"

# ---------------------------------------------------------------------------
# Step 4: Write the machine-readable provenance artifact
# ---------------------------------------------------------------------------
#
# This file is consumed by COMPLIANCE-EVIDENCE.md §4 assembly, the
# check-fips-path validator (scripts/fips-path/validate-oss-posture.sh), and
# downstream CI evidence jobs.
#
# REDACTION NOTICE: This file must not contain tokens, private keys, secrets,
# credentials, connection strings, or cryptographic key material.  If you are
# diffing or logging this file in CI, ensure the token/secret masking is enabled.

echo ""
echo "==> Writing provenance artifact to: ${FIPS_PATH_PROVENANCE_OUT}"

mkdir -p "$(dirname "${FIPS_PATH_PROVENANCE_OUT}")"

cat > "${FIPS_PATH_PROVENANCE_OUT}" <<EOF
{
  "schema_version": "1.1",
  "note": "Vault Community OSS FIPS-path artifact. Internal Go cryptographic operations route through system OpenSSL via golang-fips/go. This OSS binary is NOT a CMVP-validated or FIPS 140-3 certified cryptographic module. See FIPS-140-3-COMPLIANCE.md §2a.",
  "vault_version": "${VAULT_VERSION}",
  "version_metadata": "fips-path",
  "commit_sha": "${COMMIT_SHA}",
  "build_timestamp": "${BUILD_TIMESTAMP}",
  "target_platform": "${TARGET_PLATFORM}",
  "go_base_version": "${GO_VERSION}",
  "golang_fips_go_version": "${GOLANG_FIPS_GO_VERSION}",
  "golang_fips_commit_ref": "${GOLANG_FIPS_COMMIT_REF}",
  "golang_fips_source_digest": "${GOLANG_FIPS_SOURCE_DIGEST}",
  "golang_fips_release_url": "${GOLANG_FIPS_RELEASE_BASE_URL}/go${GOLANG_FIPS_VERSION}/",
  "cgo_enabled": "1",
  "build_flags": "CGO_ENABLED=1",
  "goexperiment": "",
  "gofips140": "",
  "openssl_fips_package": "${OPENSSL_FIPS_PACKAGE}",
  "openssl_reported_version": "${OPENSSL_REPORTED_VERSION}",
  "base_image_digest": "${BASE_IMAGE_DIGEST}",
  "sbom_path": "TO-BE-FILLED-BY-RELEASE-OWNER",
  "provenance_path": "TO-BE-FILLED-BY-RELEASE-OWNER"
}
EOF

# Fail closed: if the file was not written or is empty, abort.
if [[ ! -s "${FIPS_PATH_PROVENANCE_OUT}" ]]; then
  echo "ERROR: Provenance artifact was not written to ${FIPS_PATH_PROVENANCE_OUT}." >&2
  echo "  Check disk space and directory permissions." >&2
  exit 1
fi

echo "    ✓ Provenance artifact written"

# ---------------------------------------------------------------------------
# Step 5: Summary
# ---------------------------------------------------------------------------

echo ""
echo "=========================================================================="
echo "  FIPS-PATH BUILD PROVENANCE"
echo "=========================================================================="
echo "  Vault version   : ${VAULT_VERSION}"
echo "  Commit SHA      : ${COMMIT_SHA}"
echo "  Build timestamp : ${BUILD_TIMESTAMP}"
echo "  golang-fips/go  : ${GOLANG_FIPS_GO_VERSION}"
echo "  OpenSSL         : ${OPENSSL_REPORTED_VERSION}"
echo "  Provenance file : ${FIPS_PATH_PROVENANCE_OUT}"
echo "=========================================================================="
echo ""
echo "  NON-VALIDATION NOTICE: The build above uses the golang-fips/go toolchain."
echo "  The resulting OSS binary is NOT a CMVP-validated cryptographic module."
echo "  See FIPS-140-3-COMPLIANCE.md §2a for the full OSS posture boundary."
echo ""
echo "  To validate the build posture, run: make check-fips-path"
echo "=========================================================================="
