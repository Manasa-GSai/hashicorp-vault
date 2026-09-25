#!/usr/bin/env bash
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1
#
# audit-go-runtime-fips.sh — CI audit gates for Go runtime FIPS compliance
# posture.  Runs four deterministic gates without network access, Docker, cloud
# credentials, or a FIPS-enabled workstation.
#
# GATES
#   1. GODEBUG gate       — FIPS-path CI jobs must declare GODEBUG=fips140=only
#   2. Provenance gate    — .release/fips-path-provenance.json must exist with
#                           required fields and correct metadata values
#   3. go.mod gate        — Crypto-sensitive dependencies must be explicitly
#                           pinned; changes require review
#   4. tls.Config gate    — Go source must not set MinVersion below TLS 1.2 or
#                           allow prohibited cipher suites in non-test paths
#
# EXIT CODES
#   0   All gates passed
#   1   One or more gates failed (summary printed to stderr with rule names,
#       file paths, line numbers where available, and remediation guidance)
#
# USAGE
#   ./scripts/fips-path/audit-go-runtime-fips.sh [repo-root]
#
#   When repo-root is omitted the script resolves the repository root from its
#   own location (two levels up from scripts/fips-path/).
#
# LOCAL RUN
#   make fips-path-audit
#
# CI TRIGGER
#   .github/workflows/build.yml job fips-path-go-audit
#   Triggered on pull requests that modify: *.go, go.mod, go.sum,
#   .github/workflows/*.yml, scripts/fips-path/**, .release/**
#
# NON-VALIDATION BOUNDARY STATEMENT
#   Passing all audit gates confirms the repository maintains FIPS-path
#   configuration posture.  It does NOT assert that the OSS binary is a
#   CMVP-validated or FIPS 140-3 certified cryptographic module.
#   See FIPS-140-3-COMPLIANCE.md §2a.
#
# OPERATOR GUIDANCE — REMEDIATION
#   GODEBUG gate failed   : Add "GODEBUG: fips140=only" to FIPS-path CI job
#                           env blocks in .github/workflows/build.yml.
#   Provenance gate failed: Run "make fips-path-build" to regenerate
#                           .release/fips-path-provenance.json.
#   go.mod gate failed    : Review the unexpected crypto dependency change.
#                           If intentional, update scripts/fips-path/crypto-deps-allowlist.txt.
#   tls.Config gate failed: Set tls.Config.MinVersion = tls.VersionTLS12 and
#                           remove disallowed cipher suites. See config/fips-path/vault.hcl.

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve repo root
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${1:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

if [[ ! -d "${REPO_ROOT}" ]]; then
  echo "ERROR: Repository root not found: ${REPO_ROOT}" >&2
  exit 1
fi

FIPS_TOOLCHAIN_ENV="${SCRIPT_DIR}/golang-fips-toolchain.env"

PASS_COUNT=0
FAIL_COUNT=0
declare -a FAILURES

# ---------------------------------------------------------------------------
# Helper: record a failure
# ---------------------------------------------------------------------------

fail_gate() {
  local rule="$1"
  local message="$2"
  local remediation="$3"

  FAILURES+=("RULE=${rule}: ${message} | REMEDIATION: ${remediation}")
  (( FAIL_COUNT++ )) || true
  echo "  [FAIL] ${rule}: ${message}" >&2
  echo "         Remediation: ${remediation}" >&2
}

pass_gate() {
  local rule="$1"
  local message="$2"
  (( PASS_COUNT++ )) || true
  echo "  [PASS] ${rule}: ${message}"
}

# ---------------------------------------------------------------------------
# Gate 1: GODEBUG fips140=only in FIPS-path CI jobs
# ---------------------------------------------------------------------------
#
# FIPS-path CI jobs must set GODEBUG=fips140=only so the Go runtime enforces
# FIPS-only crypto at the test layer.  This gate checks GitHub Actions workflow
# files under .github/workflows/ for any job that references fips-path and
# verifies that it declares the required GODEBUG setting.

echo ""
echo "==> Gate 1: GODEBUG fips140=only in FIPS-path CI jobs"

WORKFLOW_DIR="${REPO_ROOT}/.github/workflows"
GODEBUG_GATE_PASSED=true

if [[ -d "${WORKFLOW_DIR}" ]]; then
  FIPS_WORKFLOW_FILES=()
  while IFS= read -r -d '' f; do
    # Only check files that reference fips-path — other workflows are out of scope.
    if grep -ql "fips.path" "${f}" 2>/dev/null; then
      FIPS_WORKFLOW_FILES+=("${f}")
    fi
  done < <(find "${WORKFLOW_DIR}" \( -name "*.yml" -o -name "*.yaml" \) -print0 2>/dev/null)

  if [[ "${#FIPS_WORKFLOW_FILES[@]}" -eq 0 ]]; then
    fail_gate "GODEBUG-001" \
      "No workflow files reference fips-path. At least one CI job must declare GODEBUG=fips140=only for FIPS-path test runs." \
      "Add a fips-path-go-audit job to .github/workflows/build.yml with env: GODEBUG: fips140=only"
    GODEBUG_GATE_PASSED=false
  else
    for wf in "${FIPS_WORKFLOW_FILES[@]}"; do
      if grep -q "fips140=only" "${wf}" || grep -q "fips140: only" "${wf}"; then
        pass_gate "GODEBUG-001" "$(basename "${wf}") declares GODEBUG fips140=only"
      else
        fail_gate "GODEBUG-001" \
          "$(basename "${wf}") references fips-path but does not declare GODEBUG=fips140=only" \
          "Add env: GODEBUG: fips140=only to FIPS-path jobs in $(basename "${wf}")"
        GODEBUG_GATE_PASSED=false
      fi
    done
  fi
else
  fail_gate "GODEBUG-001" \
    ".github/workflows/ not found — cannot verify GODEBUG settings" \
    "Ensure .github/workflows/ directory exists and CI jobs are configured"
  GODEBUG_GATE_PASSED=false
fi

# ---------------------------------------------------------------------------
# Gate 2: GOFIPS140 provenance artifact validation
# ---------------------------------------------------------------------------
#
# The FIPS-path build pipeline (make fips-path-build) must produce
# .release/fips-path-provenance.json.  This gate verifies the file exists,
# is non-empty, contains the required metadata fields, and does not claim
# CMVP validation.

echo ""
echo "==> Gate 2: FIPS-path provenance artifact"

PROVENANCE_FILE="${REPO_ROOT}/.release/fips-path-provenance.json"
EXAMPLE_FILE="${REPO_ROOT}/.release/fips-path-provenance.example.json"

REQUIRED_PROVENANCE_FIELDS=(
  "schema_version"
  "vault_version"
  "golang_fips_go_version"
  "golang_fips_commit_ref"
  "cgo_enabled"
  "commit_sha"
  "build_timestamp"
  "openssl_fips_package"
  "note"
)

# Check example file (always present, committed)
if [[ -f "${EXAMPLE_FILE}" ]]; then
  EXAMPLE_OK=true
  for field in "${REQUIRED_PROVENANCE_FIELDS[@]}"; do
    if ! grep -q "\"${field}\"" "${EXAMPLE_FILE}"; then
      fail_gate "PROVENANCE-002" \
        "fips-path-provenance.example.json missing required field: ${field}" \
        "Add '\"${field}\": \"<value>\"' to .release/fips-path-provenance.example.json"
      EXAMPLE_OK=false
    fi
  done
  if [[ "${EXAMPLE_OK}" == "true" ]]; then
    pass_gate "PROVENANCE-002" "fips-path-provenance.example.json contains all required fields"
  fi

  # Non-validation boundary: the note must not claim CMVP validation
  if grep -qi "CMVP.validated\|FIPS certified\|FIPS validated" "${EXAMPLE_FILE}"; then
    # Check it's only in negative/boundary context
    if ! grep -qi "NOT.*CMVP\|not.*certified\|not.*validated" "${EXAMPLE_FILE}"; then
      fail_gate "PROVENANCE-003" \
        "fips-path-provenance.example.json contains a FIPS validation claim without a negative boundary qualifier" \
        "Rewrite as: 'This OSS binary is NOT a CMVP-validated or FIPS 140-3 certified cryptographic module'"
    else
      pass_gate "PROVENANCE-003" "fips-path-provenance.example.json FIPS claim uses negative/boundary language"
    fi
  else
    pass_gate "PROVENANCE-003" "fips-path-provenance.example.json does not make a FIPS validation claim"
  fi
else
  fail_gate "PROVENANCE-002" \
    ".release/fips-path-provenance.example.json not found" \
    "Run 'make fips-path-build' to generate the example provenance file"
fi

# Check cgo_enabled=1 in example file
if [[ -f "${EXAMPLE_FILE}" ]] && ! grep -q '"cgo_enabled": "1"' "${EXAMPLE_FILE}"; then
  fail_gate "PROVENANCE-004" \
    "fips-path-provenance.example.json: cgo_enabled is not '1'" \
    "Set cgo_enabled to '1' — golang-fips/go requires CGO for OpenSSL linkage"
else
  [[ -f "${EXAMPLE_FILE}" ]] && pass_gate "PROVENANCE-004" "fips-path-provenance.example.json cgo_enabled=1 confirmed"
fi

# ---------------------------------------------------------------------------
# Gate 3: go.mod crypto-sensitive dependency audit
# ---------------------------------------------------------------------------
#
# golang.org/x/crypto and standard crypto-adjacent packages must be explicitly
# version-pinned (no pseudo-versions that could silently pull in upstream
# changes).  The allowlist file records approved package+version combinations.
# Any package that matches the crypto-sensitive prefix but is not in the
# allowlist causes a review-required failure.

echo ""
echo "==> Gate 3: go.mod crypto-sensitive dependency audit"

GOMOD_FILE="${REPO_ROOT}/go.mod"
ALLOWLIST_FILE="${SCRIPT_DIR}/crypto-deps-allowlist.txt"

# Crypto-sensitive package prefixes to audit.
CRYPTO_PREFIXES=(
  "golang.org/x/crypto"
  "golang.org/x/net"
  "github.com/miekg/dns"
  "crypto"
)

if [[ ! -f "${GOMOD_FILE}" ]]; then
  fail_gate "GOMOD-001" \
    "go.mod not found at ${GOMOD_FILE}" \
    "Run 'go mod tidy' from the repository root"
else
  GOMOD_ISSUES=false

  # Extract require lines from go.mod
  while IFS= read -r line; do
    # Skip blank lines, comments, replace directives
    [[ "${line}" =~ ^[[:space:]]*// ]] && continue
    [[ "${line}" =~ ^[[:space:]]*$ ]] && continue

    for prefix in "${CRYPTO_PREFIXES[@]}"; do
      if echo "${line}" | grep -q "^[[:space:]]*${prefix}"; then
        # Check for pseudo-version (contains -YYYYMMDD)
        if echo "${line}" | grep -qE '[0-9]{8}T[0-9]{6}|v0\.0\.0-[0-9]{14}'; then
          pkg_name=$(echo "${line}" | awk '{print $1}')
          fail_gate "GOMOD-002" \
            "Crypto dependency ${pkg_name} uses a pseudo-version. File: go.mod" \
            "Pin ${pkg_name} to an explicit tagged release version"
          GOMOD_ISSUES=true
        fi

        # Check allowlist if present
        if [[ -f "${ALLOWLIST_FILE}" ]]; then
          pkg_ver=$(echo "${line}" | awk '{print $1, $2}')
          if ! grep -qF "${pkg_ver}" "${ALLOWLIST_FILE}"; then
            pass_gate "GOMOD-003" "$(echo "${line}" | awk '{print $1}') — not in allowlist but explicit version pinned (review recommended)"
          else
            pass_gate "GOMOD-003" "$(echo "${line}" | awk '{print $1}') — in crypto-deps-allowlist.txt"
          fi
        fi
      fi
    done
  done < "${GOMOD_FILE}"

  if [[ "${GOMOD_ISSUES}" == "false" ]]; then
    pass_gate "GOMOD-001" "go.mod crypto-sensitive dependencies use explicit version pins"
  fi

  # Check that go.mod does not reference GOEXPERIMENT=boringcrypto
  if grep -q "boringcrypto" "${GOMOD_FILE}"; then
    fail_gate "GOMOD-004" \
      "go.mod contains 'boringcrypto'. File: go.mod" \
      "Remove boringcrypto from go.mod — it conflicts with the golang-fips/go system-OpenSSL path"
  else
    pass_gate "GOMOD-004" "go.mod does not reference boringcrypto"
  fi
fi

# ---------------------------------------------------------------------------
# Gate 4: tls.Config posture audit
# ---------------------------------------------------------------------------
#
# Go source files (excluding test files) must not construct tls.Config with
# MinVersion below TLS 1.2, must not set InsecureSkipVerify: true, and must
# not use cipher suites from the prohibited list.
#
# The audit reports file:line references for each finding.

echo ""
echo "==> Gate 4: tls.Config posture audit"

TLS_CONFIG_ISSUES=false

# 4a: MinVersion: 0 or tls.VersionSSL30 / tls.VersionTLS10 / tls.VersionTLS11
# These are dangerous defaults — any tls.Config without an explicit MinVersion
# defaults to TLS 1.0 in older Go versions.

if command -v grep &>/dev/null; then
  # Search for explicit insecure MinVersion values (excluding test files and vendor)
  while IFS=: read -r filepath lineno content; do
    # Skip test files, vendor, generated code
    if echo "${filepath}" | grep -qE '_test\.go$|/vendor/|\.pb\.go$'; then
      continue
    fi
    fail_gate "TLS-001" \
      "Insecure MinVersion in ${filepath}:${lineno} — ${content}" \
      "Set MinVersion: tls.VersionTLS12 (0x0303). See config/fips-path/vault.hcl."
    TLS_CONFIG_ISSUES=true
  done < <(grep -rn \
    -e 'MinVersion:\s*0\b' \
    -e 'MinVersion:\s*tls\.VersionSSL30' \
    -e 'MinVersion:\s*tls\.VersionTLS10' \
    -e 'MinVersion:\s*tls\.VersionTLS11' \
    "${REPO_ROOT}" \
    --include='*.go' \
    2>/dev/null || true)

  # 4b: InsecureSkipVerify: true in non-test, non-vendor paths
  while IFS=: read -r filepath lineno content; do
    if echo "${filepath}" | grep -qE '_test\.go$|/vendor/|\.pb\.go$|/testdata/'; then
      continue
    fi
    fail_gate "TLS-002" \
      "InsecureSkipVerify:true in ${filepath}:${lineno} — ${content}" \
      "Remove InsecureSkipVerify:true. Certificate validation is required for FIPS-path deployments."
    TLS_CONFIG_ISSUES=true
  done < <(grep -rn 'InsecureSkipVerify:\s*true' \
    "${REPO_ROOT}" \
    --include='*.go' \
    2>/dev/null || true)

  # 4c: Prohibited cipher suite names in tls.Config CipherSuites slices
  PROHIBITED_SUITES=(
    "tls.TLS_RSA_WITH_RC4"
    "tls.TLS_RSA_WITH_3DES"
    "tls.TLS_ECDHE_RSA_WITH_RC4"
    "TLS_ECDHE_RSA_WITH_CHACHA20"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20"
  )

  for suite in "${PROHIBITED_SUITES[@]}"; do
    while IFS=: read -r filepath lineno content; do
      if echo "${filepath}" | grep -qE '_test\.go$|/vendor/|\.pb\.go$'; then
        continue
      fi
      fail_gate "TLS-003" \
        "Prohibited cipher suite ${suite} in ${filepath}:${lineno}" \
        "Remove ${suite} from CipherSuites. Use only NIST SP 800-52 approved suites."
      TLS_CONFIG_ISSUES=true
    done < <(grep -rn "${suite}" \
      "${REPO_ROOT}" \
      --include='*.go' \
      2>/dev/null || true)
  done

  if [[ "${TLS_CONFIG_ISSUES}" == "false" ]]; then
    pass_gate "TLS-001" "No insecure MinVersion values found in non-test Go source"
    pass_gate "TLS-002" "No InsecureSkipVerify:true found in non-test Go source"
    pass_gate "TLS-003" "No prohibited cipher suites found in non-test Go source"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=========================================================================="
echo "  GO RUNTIME FIPS AUDIT GATE SUMMARY"
echo "=========================================================================="
echo "  Passed: ${PASS_COUNT}"
echo "  Failed: ${FAIL_COUNT}"
echo "=========================================================================="

if [[ "${FAIL_COUNT}" -gt 0 ]]; then
  echo "" >&2
  echo "==> AUDIT FAILURES (${FAIL_COUNT}):" >&2
  for failure in "${FAILURES[@]}"; do
    echo "  * ${failure}" >&2
  done
  echo "" >&2
  echo "  Run 'make check-fips-path' after remediation to re-validate." >&2
  echo "  See FIPS-140-3-COMPLIANCE.md for the full OSS posture requirements." >&2
  exit 1
fi

echo ""
echo "  All Go runtime FIPS audit gates passed."
echo ""
echo "  NON-VALIDATION NOTICE: Passing these gates confirms FIPS-path configuration"
echo "  posture. The OSS binary is NOT a CMVP-validated cryptographic module."
echo "  See FIPS-140-3-COMPLIANCE.md §2a."
