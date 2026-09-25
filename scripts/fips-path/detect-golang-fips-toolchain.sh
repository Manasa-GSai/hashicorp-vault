#!/usr/bin/env bash
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1
#
# detect-golang-fips-toolchain.sh — verify the active Go binary is the expected
# golang-fips/go toolchain before a FIPS-path build begins.
#
# EXIT CODES
#   0  Toolchain verified: golang-fips/go, correct version, CGO_ENABLED=1
#   1  Toolchain absent, wrong version, or CGO disabled — build must not proceed
#
# USAGE
#   detect-golang-fips-toolchain.sh [/path/to/go-binary]
#
#   When the path argument is omitted the script resolves "go" from PATH.
#
# ENVIRONMENT (all optional, override for testing)
#   GOLANG_FIPS_VERSION    Expected version string (default: read from golang-fips-toolchain.env)
#   FIPS_TOOLCHAIN_ENV     Path to the .env config file (default: auto-detected relative to script)
#   GO_CMD                 Explicit path to the go binary being inspected
#
# NON-VALIDATION BOUNDARY STATEMENT
#   Passing this check confirms that the build is using the golang-fips/go
#   toolchain distribution.  It does NOT assert that the resulting OSS binary
#   is a CMVP-validated or FIPS 140-3 certified cryptographic module.
#   See FIPS-140-3-COMPLIANCE.md for the OSS posture boundary.
#
# OPERATOR GUIDANCE
#   This script must not be pointed at a standard Go binary, Alpine/musl builds,
#   or GOEXPERIMENT=boringcrypto builds.  Those alternatives are out of scope
#   for the FIPS-path posture documented in FIPS-140-3-COMPLIANCE.md.

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve script directory and toolchain config
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIPS_TOOLCHAIN_ENV="${FIPS_TOOLCHAIN_ENV:-${SCRIPT_DIR}/golang-fips-toolchain.env}"

if [[ ! -f "${FIPS_TOOLCHAIN_ENV}" ]]; then
  echo "ERROR: toolchain config not found: ${FIPS_TOOLCHAIN_ENV}" >&2
  echo "  Expected: scripts/fips-path/golang-fips-toolchain.env" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "${FIPS_TOOLCHAIN_ENV}"

# ---------------------------------------------------------------------------
# Resolve the go binary to inspect
# ---------------------------------------------------------------------------

if [[ -n "${1:-}" ]]; then
  GO_CMD="${1}"
elif [[ -n "${GO_CMD:-}" ]]; then
  : # already set by caller
else
  GO_CMD="$(command -v go 2>/dev/null || true)"
fi

if [[ -z "${GO_CMD}" ]]; then
  echo "ERROR: go binary not found on PATH and GO_CMD is not set." >&2
  echo "  Install golang-fips/go from ${GOLANG_FIPS_RELEASE_BASE_URL}/go${GOLANG_FIPS_VERSION}/" >&2
  exit 1
fi

if [[ ! -x "${GO_CMD}" ]]; then
  echo "ERROR: ${GO_CMD} is not executable." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Inspect the go binary
# ---------------------------------------------------------------------------

RAW_GO_VERSION="$("${GO_CMD}" version 2>&1 || true)"
# Expected form: "go version go1.22.5-1 linux/amd64"
REPORTED_VERSION="$(echo "${RAW_GO_VERSION}" | awk '{print $3}')"

echo "==> Detected Go version: ${REPORTED_VERSION}"
echo "==> Expected golang-fips/go version: go${GOLANG_FIPS_VERSION}"

# ---------------------------------------------------------------------------
# Check 1: Version must match the pinned golang-fips release
# ---------------------------------------------------------------------------
#
# golang-fips/go releases are tagged with a version suffix (e.g. "1.22.5-1").
# The go binary reports: "go1.22.5-1" — note the absence of a space between
# "go" and the version.  We check for exact equality.

EXPECTED_VERSION="go${GOLANG_FIPS_VERSION}"

if [[ "${REPORTED_VERSION}" != "${EXPECTED_VERSION}" ]]; then
  echo "ERROR: Go version mismatch." >&2
  echo "  Expected : ${EXPECTED_VERSION}" >&2
  echo "  Detected : ${REPORTED_VERSION}" >&2
  echo "" >&2
  echo "  The FIPS-path build requires the golang-fips/go toolchain, not standard Go." >&2
  echo "  Standard Go releases do NOT route crypto through system OpenSSL." >&2
  echo "  Update GOLANG_FIPS_VERSION in scripts/fips-path/golang-fips-toolchain.env" >&2
  echo "  or install the correct golang-fips/go release." >&2
  exit 1
fi

echo "  ✓ Version matches pinned golang-fips/go release"

# ---------------------------------------------------------------------------
# Check 2: CGO must be enabled
# ---------------------------------------------------------------------------
#
# golang-fips/go relies on CGO to call into system OpenSSL via cgo linkage.
# A build with CGO_ENABLED=0 produces a statically-linked binary that does NOT
# route crypto through OpenSSL — rendering the FIPS-path posture invalid.

CGO_ENABLED_VAL="$("${GO_CMD}" env CGO_ENABLED 2>/dev/null || echo "unknown")"

echo "==> CGO_ENABLED=${CGO_ENABLED_VAL}"

if [[ "${CGO_ENABLED_VAL}" != "1" ]]; then
  echo "ERROR: CGO_ENABLED is not 1." >&2
  echo "  FIPS-path builds require CGO_ENABLED=1 so the binary is linked against" >&2
  echo "  system OpenSSL.  A CGO_ENABLED=0 build does not route crypto through the" >&2
  echo "  FIPS-validated OpenSSL provider." >&2
  echo "  Set CGO_ENABLED=1 in the build environment." >&2
  exit 1
fi

echo "  ✓ CGO_ENABLED=1 confirmed"

# ---------------------------------------------------------------------------
# Check 3: GOEXPERIMENT must not include boringcrypto
# ---------------------------------------------------------------------------
#
# GOEXPERIMENT=boringcrypto targets the BoringSSL boundary and is mutually
# exclusive with the golang-fips/go / system-OpenSSL boundary.

GOEXPERIMENT_VAL="$("${GO_CMD}" env GOEXPERIMENT 2>/dev/null || echo "")"

if echo "${GOEXPERIMENT_VAL}" | grep -q "boringcrypto"; then
  echo "ERROR: GOEXPERIMENT contains 'boringcrypto'." >&2
  echo "  boringcrypto is not part of the FIPS-path posture (golang-fips/go uses" >&2
  echo "  system OpenSSL, not BoringSSL). Unset GOEXPERIMENT=boringcrypto." >&2
  exit 1
fi

echo "  ✓ GOEXPERIMENT does not include boringcrypto"

# ---------------------------------------------------------------------------
# Check 4: Verify the binary is on a glibc host (musl/Alpine guard)
# ---------------------------------------------------------------------------
#
# golang-fips/go must be paired with a glibc system to link against the glibc
# OpenSSL shared library.  Alpine Linux uses musl libc which cannot load the
# glibc-compiled OpenSSL FIPS provider.

if command -v ldd &>/dev/null; then
  LIBC_INFO="$(ldd --version 2>&1 | head -1 || true)"
  if echo "${LIBC_INFO}" | grep -qi "musl"; then
    echo "ERROR: musl libc detected. golang-fips/go requires a glibc environment." >&2
    echo "  Use ubuntu:focal, ubi8, ubi9, or another glibc-based image." >&2
    exit 1
  fi
  echo "  ✓ glibc detected: ${LIBC_INFO}"
else
  echo "  ⚠ ldd not found — glibc check skipped (acceptable in restricted CI environments)"
fi

# ---------------------------------------------------------------------------
# All checks passed
# ---------------------------------------------------------------------------

echo ""
echo "==> golang-fips/go toolchain verified successfully."
echo "    Version : ${REPORTED_VERSION}"
echo "    CGO     : ${CGO_ENABLED_VAL}"
echo ""
echo "    NON-VALIDATION NOTICE: This check confirms that the build uses the"
echo "    golang-fips/go distribution. The resulting OSS binary is NOT a"
echo "    CMVP-validated or FIPS 140-3 certified cryptographic module."
echo "    See FIPS-140-3-COMPLIANCE.md §2a for the OSS posture boundary."
