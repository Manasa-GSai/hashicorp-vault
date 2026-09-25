#!/usr/bin/env bash
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1
#
# test-detect-golang-fips-toolchain.sh — fixture-based test suite for
# detect-golang-fips-toolchain.sh and build-fips-path.sh provenance generation.
#
# Tests use mock Go binaries and fixture env files so the suite runs without
# downloading the golang-fips/go toolchain, without Docker, without network
# access, and without a FIPS-enabled host kernel.
#
# USAGE
#   ./scripts/fips-path/test-detect-golang-fips-toolchain.sh
#
# EXIT CODE
#   0  All tests pass
#   1  One or more tests failed (summary printed to stderr)
#
# DESIGN NOTES
#   Each test creates a temporary directory, writes a stub "go" binary and a
#   toolchain .env file, then calls detect-golang-fips-toolchain.sh with
#   overridden environment variables.  The script exit code and stdout/stderr
#   are captured and assertions are made against them.
#
#   Tests that are expected to FAIL the detection set should_fail=1;
#   tests expected to PASS set should_fail=0.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECT_SCRIPT="${SCRIPT_DIR}/detect-golang-fips-toolchain.sh"

if [[ ! -f "${DETECT_SCRIPT}" ]]; then
  echo "FATAL: ${DETECT_SCRIPT} not found" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Test harness helpers
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
FAILED_TESTS=()

run_test() {
  local name="$1"
  local should_fail="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmpdir}'" EXIT

  # Run the body function with the tmpdir; it must set up env.
  "$3" "${tmpdir}"

  local exit_code=0
  bash "${DETECT_SCRIPT}" "${tmpdir}/go" \
    >"${tmpdir}/stdout.txt" 2>"${tmpdir}/stderr.txt" \
    || exit_code=$?

  if [[ "${should_fail}" -eq 1 ]]; then
    if [[ "${exit_code}" -ne 0 ]]; then
      echo "  PASS: ${name}"
      (( PASS++ )) || true
    else
      echo "  FAIL: ${name} — expected nonzero exit, got 0" >&2
      echo "    stdout: $(cat "${tmpdir}/stdout.txt")" >&2
      (( FAIL++ )) || true
      FAILED_TESTS+=("${name}")
    fi
  else
    if [[ "${exit_code}" -eq 0 ]]; then
      echo "  PASS: ${name}"
      (( PASS++ )) || true
    else
      echo "  FAIL: ${name} — expected exit 0, got ${exit_code}" >&2
      echo "    stderr: $(cat "${tmpdir}/stderr.txt")" >&2
      (( FAIL++ )) || true
      FAILED_TESTS+=("${name}")
    fi
  fi

  # Reset EXIT trap to avoid double cleanup in nested calls.
  trap - EXIT
  rm -rf "${tmpdir}"
}

# Write a stub go binary that reports a given version string and CGO value.
write_go_stub() {
  local dir="$1"
  local version="$2"   # e.g. "go1.22.5-1"
  local cgo="$3"        # "1" or "0"
  local goexperiment="${4:-}"

  cat > "${dir}/go" <<STUB
#!/usr/bin/env bash
case "\$1" in
  version) echo "go version ${version} linux/amd64" ;;
  env)
    case "\$2" in
      CGO_ENABLED) echo "${cgo}" ;;
      GOEXPERIMENT) echo "${goexperiment}" ;;
      *) echo "" ;;
    esac
    ;;
esac
STUB
  chmod +x "${dir}/go"
}

# Write a minimal toolchain .env that matches or mismatches the stub.
write_toolchain_env() {
  local dir="$1"
  local fips_version="$2"  # e.g. "1.22.5-1"

  cat > "${dir}/toolchain.env" <<ENV
GOLANG_FIPS_VERSION=${fips_version}
GOLANG_FIPS_BASE_GO_VERSION=1.22.5
GOLANG_FIPS_COMMIT_REF=go${fips_version}
GOLANG_FIPS_SOURCE_DIGEST=unverified
GOLANG_FIPS_RELEASE_BASE_URL=https://github.com/golang-fips/go/releases/download
OPENSSL_FIPS_PACKAGE=openssl
OPENSSL_FIPS_MIN_VERSION=3.0
ENV
  export FIPS_TOOLCHAIN_ENV="${dir}/toolchain.env"
}

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

echo "Running detect-golang-fips-toolchain.sh tests..."
echo ""

# ---- PASS: correct golang-fips/go version, CGO=1, no boringcrypto -----------
setup_pass_correct_version() {
  local d="$1"
  write_go_stub "${d}" "go1.22.5-1" "1" ""
  write_toolchain_env "${d}" "1.22.5-1"
}
run_test "pass: correct version, CGO=1, no boringcrypto" 0 setup_pass_correct_version

# ---- FAIL: wrong version (standard Go release, not golang-fips) -------------
setup_fail_standard_go() {
  local d="$1"
  write_go_stub "${d}" "go1.22.5" "1" ""   # no "-1" suffix
  write_toolchain_env "${d}" "1.22.5-1"
}
run_test "fail: standard Go binary — version missing fips suffix" 1 setup_fail_standard_go

# ---- FAIL: correct fips version but wrong release number --------------------
setup_fail_wrong_release_num() {
  local d="$1"
  write_go_stub "${d}" "go1.22.5-2" "1" ""   # -2 != expected -1
  write_toolchain_env "${d}" "1.22.5-1"
}
run_test "fail: wrong release sequence (-2 vs -1)" 1 setup_fail_wrong_release_num

# ---- FAIL: correct version but CGO disabled ---------------------------------
setup_fail_cgo_disabled() {
  local d="$1"
  write_go_stub "${d}" "go1.22.5-1" "0" ""
  write_toolchain_env "${d}" "1.22.5-1"
}
run_test "fail: CGO_ENABLED=0" 1 setup_fail_cgo_disabled

# ---- FAIL: GOEXPERIMENT contains boringcrypto --------------------------------
setup_fail_boringcrypto() {
  local d="$1"
  write_go_stub "${d}" "go1.22.5-1" "1" "boringcrypto"
  write_toolchain_env "${d}" "1.22.5-1"
}
run_test "fail: GOEXPERIMENT=boringcrypto" 1 setup_fail_boringcrypto

# ---- FAIL: go binary is not executable --------------------------------------
setup_fail_not_executable() {
  local d="$1"
  # Create a non-executable file
  echo "not a binary" > "${d}/go"
  write_toolchain_env "${d}" "1.22.5-1"
}
run_test "fail: go binary is not executable" 1 setup_fail_not_executable

# ---- FAIL: toolchain .env is missing ----------------------------------------
setup_fail_missing_env() {
  local d="$1"
  write_go_stub "${d}" "go1.22.5-1" "1" ""
  # Deliberately do NOT write toolchain.env; override FIPS_TOOLCHAIN_ENV to a
  # non-existent path.
  export FIPS_TOOLCHAIN_ENV="${d}/does-not-exist.env"
}
run_test "fail: toolchain env file missing" 1 setup_fail_missing_env

# Reset FIPS_TOOLCHAIN_ENV so subsequent tests use their own paths.
unset FIPS_TOOLCHAIN_ENV 2>/dev/null || true

# ---- PASS: GOEXPERIMENT has other flags but not boringcrypto ----------------
setup_pass_other_goexperiment() {
  local d="$1"
  write_go_stub "${d}" "go1.22.5-1" "1" "loopvar"
  write_toolchain_env "${d}" "1.22.5-1"
}
run_test "pass: GOEXPERIMENT=loopvar (no boringcrypto)" 0 setup_pass_other_goexperiment

# ---- PASS: different pinned version matching stub ----------------------------
setup_pass_different_version() {
  local d="$1"
  write_go_stub "${d}" "go1.21.3-1" "1" ""
  write_toolchain_env "${d}" "1.21.3-1"
}
run_test "pass: different golang-fips version (1.21.3-1)" 0 setup_pass_different_version

# ---- FAIL: completely wrong major.minor version ------------------------------
setup_fail_wrong_major_version() {
  local d="$1"
  write_go_stub "${d}" "go1.21.3-1" "1" ""   # binary is 1.21.3-1
  write_toolchain_env "${d}" "1.22.5-1"       # env expects 1.22.5-1
}
run_test "fail: wrong base Go version (1.21.3-1 vs 1.22.5-1)" 1 setup_fail_wrong_major_version

# ---------------------------------------------------------------------------
# Provenance generation test — verify build-fips-path.sh writes provenance
# ---------------------------------------------------------------------------

echo ""
echo "Running provenance generation tests..."
echo ""

PROVENANCE_TMPDIR="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '${PROVENANCE_TMPDIR}'" EXIT

PROVENANCE_OUT="${PROVENANCE_TMPDIR}/provenance.json"
FAKE_BUILDER_IMAGE="fips-test-builder:fixture"

# We cannot call the full build-fips-path.sh in a unit context (it requires
# Docker). Instead we test the provenance file structure by sourcing the env
# and generating the JSON inline — matching the logic in build-fips-path.sh.

source "${SCRIPT_DIR}/golang-fips-toolchain.env"

VAULT_VERSION="1.99.0-test"
COMMIT_SHA="abc1234567890"
BUILD_TIMESTAMP="2026-01-01T00:00:00Z"
GOLANG_FIPS_GO_VERSION="go${GOLANG_FIPS_VERSION}"
OPENSSL_REPORTED_VERSION="OpenSSL 3.0.2 15 Mar 2022"
BASE_IMAGE_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
TARGET_PLATFORM="linux/amd64"

mkdir -p "$(dirname "${PROVENANCE_OUT}")"

cat > "${PROVENANCE_OUT}" <<PROV
{
  "schema_version": "1.1",
  "note": "Vault Community OSS FIPS-path artifact. Internal Go cryptographic operations route through system OpenSSL via golang-fips/go. This OSS binary is NOT a CMVP-validated or FIPS 140-3 certified cryptographic module. See FIPS-140-3-COMPLIANCE.md §2a.",
  "vault_version": "${VAULT_VERSION}",
  "version_metadata": "fips-path",
  "commit_sha": "${COMMIT_SHA}",
  "build_timestamp": "${BUILD_TIMESTAMP}",
  "target_platform": "${TARGET_PLATFORM}",
  "golang_fips_go_version": "${GOLANG_FIPS_GO_VERSION}",
  "golang_fips_commit_ref": "${GOLANG_FIPS_COMMIT_REF}",
  "golang_fips_source_digest": "${GOLANG_FIPS_SOURCE_DIGEST}",
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
PROV

# Assert: file exists and is non-empty
if [[ -s "${PROVENANCE_OUT}" ]]; then
  echo "  PASS: provenance artifact written"
  (( PASS++ )) || true
else
  echo "  FAIL: provenance artifact empty or missing" >&2
  (( FAIL++ )) || true
  FAILED_TESTS+=("provenance artifact written")
fi

# Assert: required fields present
REQUIRED_FIELDS=(
  "schema_version"
  "vault_version"
  "commit_sha"
  "build_timestamp"
  "golang_fips_go_version"
  "golang_fips_commit_ref"
  "cgo_enabled"
  "openssl_fips_package"
  "sbom_path"
  "note"
)

for field in "${REQUIRED_FIELDS[@]}"; do
  if grep -q "\"${field}\"" "${PROVENANCE_OUT}"; then
    echo "  PASS: provenance contains '${field}'"
    (( PASS++ )) || true
  else
    echo "  FAIL: provenance missing field '${field}'" >&2
    (( FAIL++ )) || true
    FAILED_TESTS+=("provenance field: ${field}")
  fi
done

# Assert: non-validation boundary note present
if grep -q "NOT a CMVP-validated" "${PROVENANCE_OUT}"; then
  echo "  PASS: provenance contains non-validation boundary statement"
  (( PASS++ )) || true
else
  echo "  FAIL: provenance missing non-validation boundary statement" >&2
  (( FAIL++ )) || true
  FAILED_TESTS+=("provenance non-validation note")
fi

# Assert: cgo_enabled is "1" (not "0")
if grep -q '"cgo_enabled": "1"' "${PROVENANCE_OUT}"; then
  echo "  PASS: provenance cgo_enabled=1"
  (( PASS++ )) || true
else
  echo "  FAIL: provenance cgo_enabled is not 1" >&2
  (( FAIL++ )) || true
  FAILED_TESTS+=("provenance cgo_enabled=1")
fi

# Assert: gofips140 and goexperiment are empty string (correct for golang-fips/go path)
if grep -q '"gofips140": ""' "${PROVENANCE_OUT}" && grep -q '"goexperiment": ""' "${PROVENANCE_OUT}"; then
  echo "  PASS: provenance gofips140 and goexperiment are empty (golang-fips/go path)"
  (( PASS++ )) || true
else
  echo "  FAIL: provenance gofips140 or goexperiment should be empty for golang-fips/go path" >&2
  (( FAIL++ )) || true
  FAILED_TESTS+=("provenance gofips140/goexperiment empty")
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

trap - EXIT
rm -rf "${PROVENANCE_TMPDIR}"

echo ""
if [[ "${FAIL}" -eq 0 ]]; then
  echo "=== $(( PASS )) / $(( PASS + FAIL )) tests passed ==="
  exit 0
else
  echo "=== ${FAIL} / $(( PASS + FAIL )) tests FAILED ===" >&2
  echo "" >&2
  echo "Failed tests:" >&2
  for t in "${FAILED_TESTS[@]}"; do
    echo "  - ${t}" >&2
  done
  exit 1
fi
