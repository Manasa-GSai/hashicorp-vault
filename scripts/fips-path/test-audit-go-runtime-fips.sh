#!/usr/bin/env bash
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1
#
# test-audit-go-runtime-fips.sh — fixture-based test suite for
# audit-go-runtime-fips.sh.
#
# Tests run without Docker, network access, cloud credentials, or a
# FIPS-enabled host.  Each test creates an isolated directory tree with
# fixture files and calls the audit script with that directory as the
# repo root.
#
# USAGE
#   ./scripts/fips-path/test-audit-go-runtime-fips.sh
#
# EXIT CODE
#   0  All tests pass
#   1  One or more tests failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SCRIPT="${SCRIPT_DIR}/audit-go-runtime-fips.sh"

if [[ ! -f "${AUDIT_SCRIPT}" ]]; then
  echo "FATAL: ${AUDIT_SCRIPT} not found" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Harness helpers
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
FAILED_TESTS=()

run_test() {
  local name="$1"
  local should_fail="$2"  # 1=expect audit failure, 0=expect audit pass
  local setup_fn="$3"

  local tmpdir
  tmpdir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmpdir}'" EXIT

  "$setup_fn" "${tmpdir}"

  # Copy the toolchain env and crypto allowlist into the fixture tmp dir so the
  # audit script can source them.
  mkdir -p "${tmpdir}/scripts/fips-path"
  cp "${SCRIPT_DIR}/golang-fips-toolchain.env" "${tmpdir}/scripts/fips-path/"
  cp "${SCRIPT_DIR}/crypto-deps-allowlist.txt" "${tmpdir}/scripts/fips-path/"

  local exit_code=0
  bash "${AUDIT_SCRIPT}" "${tmpdir}" \
    >"${tmpdir}/stdout.txt" 2>"${tmpdir}/stderr.txt" \
    || exit_code=$?

  if [[ "${should_fail}" -eq 1 ]]; then
    if [[ "${exit_code}" -ne 0 ]]; then
      echo "  PASS: ${name}"
      (( PASS++ )) || true
    else
      echo "  FAIL: ${name} — expected audit failure (nonzero exit), got 0" >&2
      echo "    stdout: $(cat "${tmpdir}/stdout.txt")" >&2
      (( FAIL++ )) || true
      FAILED_TESTS+=("${name}")
    fi
  else
    if [[ "${exit_code}" -eq 0 ]]; then
      echo "  PASS: ${name}"
      (( PASS++ )) || true
    else
      echo "  FAIL: ${name} — expected audit pass (exit 0), got ${exit_code}" >&2
      echo "    stderr: $(cat "${tmpdir}/stderr.txt")" >&2
      (( FAIL++ )) || true
      FAILED_TESTS+=("${name}")
    fi
  fi

  trap - EXIT
  rm -rf "${tmpdir}"
}

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

write_passing_workflow() {
  local root="$1"
  mkdir -p "${root}/.github/workflows"
  cat > "${root}/.github/workflows/build.yml" <<'YAML'
name: build
on: [push, pull_request]
jobs:
  fips-path-go-audit:
    runs-on: ubuntu-latest
    env:
      GODEBUG: fips140=only
    steps:
      - uses: actions/checkout@v4
      - run: make fips-path-audit
YAML
}

write_failing_workflow_no_godebug() {
  local root="$1"
  mkdir -p "${root}/.github/workflows"
  cat > "${root}/.github/workflows/build.yml" <<'YAML'
name: build
on: [push, pull_request]
jobs:
  fips-path-go-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make fips-path-audit
YAML
}

write_passing_provenance() {
  local root="$1"
  mkdir -p "${root}/.release"
  cat > "${root}/.release/fips-path-provenance.example.json" <<'JSON'
{
  "schema_version": "1.1",
  "note": "This OSS binary is NOT a CMVP-validated or FIPS 140-3 certified cryptographic module.",
  "vault_version": "1.0.0",
  "version_metadata": "fips-path",
  "commit_sha": "abc1234",
  "build_timestamp": "2026-01-01T00:00:00Z",
  "golang_fips_go_version": "go1.22.5-1",
  "golang_fips_commit_ref": "go1.22.5-1",
  "cgo_enabled": "1",
  "build_flags": "CGO_ENABLED=1",
  "openssl_fips_package": "openssl",
  "sbom_path": "TO-BE-FILLED-BY-RELEASE-OWNER"
}
JSON
}

write_failing_provenance_missing_field() {
  local root="$1"
  mkdir -p "${root}/.release"
  # Missing schema_version, golang_fips_go_version, etc.
  cat > "${root}/.release/fips-path-provenance.example.json" <<'JSON'
{
  "vault_version": "1.0.0",
  "note": "incomplete"
}
JSON
}

write_passing_gomod() {
  local root="$1"
  cat > "${root}/go.mod" <<'GOMOD'
module github.com/hashicorp/vault

go 1.22.5

require (
  golang.org/x/crypto v0.27.0
  golang.org/x/net v0.29.0
)
GOMOD
}

write_failing_gomod_pseudo_version() {
  local root="$1"
  cat > "${root}/go.mod" <<'GOMOD'
module github.com/hashicorp/vault

go 1.22.5

require (
  golang.org/x/crypto v0.0.0-20231016080418-aead3a3571e8
)
GOMOD
}

write_failing_gomod_boringcrypto() {
  local root="$1"
  cat > "${root}/go.mod" <<'GOMOD'
module github.com/hashicorp/vault

go 1.22.5

godebug GOEXPERIMENT=boringcrypto
GOMOD
}

write_passing_tls_source() {
  local root="$1"
  mkdir -p "${root}/internal/api"
  cat > "${root}/internal/api/tls.go" <<'GO'
package api

import (
  "crypto/tls"
)

func newTLSConfig() *tls.Config {
  return &tls.Config{
    MinVersion: tls.VersionTLS12,
  }
}
GO
}

write_failing_tls_min_version_zero() {
  local root="$1"
  mkdir -p "${root}/internal/api"
  cat > "${root}/internal/api/tls.go" <<'GO'
package api

import (
  "crypto/tls"
)

func newTLSConfig() *tls.Config {
  return &tls.Config{
    MinVersion: 0,
  }
}
GO
}

write_failing_tls_insecure_skip() {
  local root="$1"
  mkdir -p "${root}/internal/api"
  cat > "${root}/internal/api/tls.go" <<'GO'
package api

import (
  "crypto/tls"
)

func newInsecureConfig() *tls.Config {
  return &tls.Config{
    InsecureSkipVerify: true,
  }
}
GO
}

write_failing_tls_rc4_cipher() {
  local root="$1"
  mkdir -p "${root}/internal/api"
  cat > "${root}/internal/api/tls.go" <<'GO'
package api

import (
  "crypto/tls"
)

func newTLSConfig() *tls.Config {
  return &tls.Config{
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
      tls.TLS_RSA_WITH_RC4_128_SHA,
    },
  }
}
GO
}

# ---------------------------------------------------------------------------
# PASS tests — full passing fixture
# ---------------------------------------------------------------------------

echo "Running audit-go-runtime-fips.sh tests..."
echo ""
echo "--- Gate 1: GODEBUG ---"

setup_pass_full() {
  local d="$1"
  write_passing_workflow "${d}"
  write_passing_provenance "${d}"
  write_passing_gomod "${d}"
  write_passing_tls_source "${d}"
}
run_test "pass: full passing fixture" 0 setup_pass_full

# ---------------------------------------------------------------------------
# FAIL tests — Gate 1: GODEBUG
# ---------------------------------------------------------------------------

setup_fail_no_godebug() {
  local d="$1"
  write_failing_workflow_no_godebug "${d}"
  write_passing_provenance "${d}"
  write_passing_gomod "${d}"
  write_passing_tls_source "${d}"
}
run_test "fail: workflow exists but no GODEBUG=fips140=only" 1 setup_fail_no_godebug

setup_fail_no_workflows() {
  local d="$1"
  # No .github/workflows directory at all
  write_passing_provenance "${d}"
  write_passing_gomod "${d}"
  write_passing_tls_source "${d}"
}
run_test "fail: no .github/workflows directory" 1 setup_fail_no_workflows

echo ""
echo "--- Gate 2: Provenance ---"

setup_fail_provenance_missing_field() {
  local d="$1"
  write_passing_workflow "${d}"
  write_failing_provenance_missing_field "${d}"
  write_passing_gomod "${d}"
  write_passing_tls_source "${d}"
}
run_test "fail: provenance missing required fields" 1 setup_fail_provenance_missing_field

setup_fail_provenance_missing_file() {
  local d="$1"
  write_passing_workflow "${d}"
  # No provenance file written
  write_passing_gomod "${d}"
  write_passing_tls_source "${d}"
}
run_test "fail: provenance file not present" 1 setup_fail_provenance_missing_file

echo ""
echo "--- Gate 3: go.mod ---"

setup_fail_gomod_pseudo() {
  local d="$1"
  write_passing_workflow "${d}"
  write_passing_provenance "${d}"
  write_failing_gomod_pseudo_version "${d}"
  write_passing_tls_source "${d}"
}
run_test "fail: go.mod crypto dep uses pseudo-version" 1 setup_fail_gomod_pseudo

setup_fail_gomod_boringcrypto() {
  local d="$1"
  write_passing_workflow "${d}"
  write_passing_provenance "${d}"
  write_failing_gomod_boringcrypto "${d}"
  write_passing_tls_source "${d}"
}
run_test "fail: go.mod contains boringcrypto" 1 setup_fail_gomod_boringcrypto

echo ""
echo "--- Gate 4: tls.Config ---"

setup_fail_tls_min_version_zero() {
  local d="$1"
  write_passing_workflow "${d}"
  write_passing_provenance "${d}"
  write_passing_gomod "${d}"
  write_failing_tls_min_version_zero "${d}"
}
run_test "fail: tls.Config MinVersion: 0" 1 setup_fail_tls_min_version_zero

setup_fail_tls_insecure_skip() {
  local d="$1"
  write_passing_workflow "${d}"
  write_passing_provenance "${d}"
  write_passing_gomod "${d}"
  write_failing_tls_insecure_skip "${d}"
}
run_test "fail: tls.Config InsecureSkipVerify:true" 1 setup_fail_tls_insecure_skip

setup_fail_tls_rc4() {
  local d="$1"
  write_passing_workflow "${d}"
  write_passing_provenance "${d}"
  write_passing_gomod "${d}"
  write_failing_tls_rc4_cipher "${d}"
}
run_test "fail: tls.Config uses TLS_RSA_WITH_RC4 cipher suite" 1 setup_fail_tls_rc4

# PASS: tls insecure skip in test file should be ignored
setup_pass_tls_insecure_in_test() {
  local d="$1"
  write_passing_workflow "${d}"
  write_passing_provenance "${d}"
  write_passing_gomod "${d}"
  mkdir -p "${d}/internal/api"
  cat > "${d}/internal/api/tls_test.go" <<'GO'
package api

import "crypto/tls"

func testInsecureConfig() *tls.Config {
  // Acceptable in test files
  return &tls.Config{InsecureSkipVerify: true}
}
GO
}
run_test "pass: InsecureSkipVerify:true in _test.go file is ignored" 0 setup_pass_tls_insecure_in_test

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

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
