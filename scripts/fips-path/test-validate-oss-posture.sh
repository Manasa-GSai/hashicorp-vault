#!/usr/bin/env bash
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1
#
# test-validate-oss-posture.sh — Shell test harness for the OSS FIPS-path validator
#
# Runs scripts/fips-path/validate-oss-posture.sh against the committed fixture
# trees in scripts/fips-path/testdata/ using FIPS_PATH_ROOT and FIPS_HOST_FIPS_FILE
# overrides so the test requires no network access, container registry, AWS
# credentials, or a FIPS-enabled developer workstation.
#
# The harness exercises:
#   - pass   : all eight gates PASS (exit 0)
#   - fail-alpine       : image-glibc gate fails on Alpine reference
#   - fail-host-fips    : host-fips gate fails when fips_enabled=0
#   - fail-tls          : tls-settings gate fails on tls10 / missing cipher suites
#   - fail-algorithm    : prohibited-algorithms gate fails on chacha20
#   - fail-awskms       : awskms-fips-endpoint gate fails on non-kms-fips endpoint
#   - fail-digest       : image-digest-pinned gate fails on missing sha256
#   - fail-evidence     : evidence-freshness gate fails on stale date 2010-01-01
#   - fail-overclaim    : overclaim-and-boring-guard gate fails on prohibited wording
#
# Usage:
#   bash scripts/fips-path/test-validate-oss-posture.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR="${SCRIPT_DIR}/validate-oss-posture.sh"
TESTDATA="${SCRIPT_DIR}/testdata"
PASS_FIXTURE="${TESTDATA}/pass"
PASS_FIPS_FILE="${PASS_FIXTURE}/fips-enabled"

FAIL_COUNT=0
PASS_COUNT=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

tresult_pass() {
    printf 'PASS  [%s]\n' "$1"
    PASS_COUNT=$(( PASS_COUNT + 1 ))
}

tresult_fail() {
    printf 'FAIL  [%s] %s\n' "$1" "$2" >&2
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
}

# run_validator FIPS_ROOT FIPS_FILE — run validator and return its exit code
# without aborting the test harness.
run_validator() {
    local root="$1" fips_file="$2" exit_code=0
    FIPS_PATH_ROOT="${root}" FIPS_HOST_FIPS_FILE="${fips_file}" \
        bash "${VALIDATOR}" > /dev/null 2>&1 || exit_code=$?
    echo "${exit_code}"
}

# run_validator_output FIPS_ROOT FIPS_FILE — run validator and capture combined output
run_validator_output() {
    local root="$1" fips_file="$2"
    FIPS_PATH_ROOT="${root}" FIPS_HOST_FIPS_FILE="${fips_file}" \
        bash "${VALIDATOR}" 2>&1 || true
}

# make_overlay FAIL_DIR INJECT_DATE — create a temp dir by copying the pass
# fixture and then overlaying FAIL_DIR files.  If INJECT_DATE is "true",
# append today's date to the overlay's COMPLIANCE-EVIDENCE.md (so the evidence
# freshness gate does not also fail for non-evidence tests).
make_overlay() {
    local fail_dir="${1:-}" inject_date="${2:-true}" tmp
    tmp="$(mktemp -d)"
    cp -r "${PASS_FIXTURE}/." "${tmp}/"
    if [[ -d "${fail_dir}" ]]; then
        cp -r "${fail_dir}/." "${tmp}/"
    fi
    if [[ "${inject_date}" == "true" ]]; then
        echo "| Verification Date | $(date -u +%Y-%m-%d) | Test harness |" \
            >> "${tmp}/COMPLIANCE-EVIDENCE.md"
    fi
    echo "${tmp}"
}

# ---------------------------------------------------------------------------
# Test: pass fixture — all eight gates must PASS (exit 0)
# ---------------------------------------------------------------------------
_tmp_pass="$(make_overlay "" true)"
_exit="$(run_validator "${_tmp_pass}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp_pass}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp_pass}"

if [[ "${_exit}" -eq 0 ]] && echo "${_output}" | grep -q "All eight OSS FIPS-path gates PASSED"; then
    tresult_pass "pass-all-gates"
else
    tresult_fail "pass-all-gates" "expected exit 0 and 'All eight...PASSED' message; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-alpine — image-glibc gate
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "${TESTDATA}/fail-alpine" true)"
_exit="$(run_validator "${_tmp}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*image-glibc\|image-glibc.*FAIL"; then
    tresult_pass "fail-alpine"
else
    tresult_fail "fail-alpine" "expected exit 1 with FAIL [image-glibc]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-host-fips — host-fips gate
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "" true)"
_exit="$(run_validator "${_tmp}" "${TESTDATA}/fail-host-fips/fips-enabled")"
_output="$(run_validator_output "${_tmp}" "${TESTDATA}/fail-host-fips/fips-enabled")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*host-fips\|host-fips.*FAIL"; then
    tresult_pass "fail-host-fips"
else
    tresult_fail "fail-host-fips" "expected exit 1 with FAIL [host-fips]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-tls — tls-settings gate
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "${TESTDATA}/fail-tls" true)"
_exit="$(run_validator "${_tmp}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*tls-settings\|tls-settings.*FAIL"; then
    tresult_pass "fail-tls"
else
    tresult_fail "fail-tls" "expected exit 1 with FAIL [tls-settings]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-algorithm — prohibited-algorithms gate
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "${TESTDATA}/fail-algorithm" true)"
_exit="$(run_validator "${_tmp}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*prohibited-algorithms\|prohibited-algorithms.*FAIL"; then
    tresult_pass "fail-algorithm"
else
    tresult_fail "fail-algorithm" "expected exit 1 with FAIL [prohibited-algorithms]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-awskms — awskms-fips-endpoint gate
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "${TESTDATA}/fail-awskms" true)"
_exit="$(run_validator "${_tmp}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*awskms-fips-endpoint\|awskms-fips-endpoint.*FAIL"; then
    tresult_pass "fail-awskms"
else
    tresult_fail "fail-awskms" "expected exit 1 with FAIL [awskms-fips-endpoint]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-digest — image-digest-pinned gate
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "${TESTDATA}/fail-digest" true)"
_exit="$(run_validator "${_tmp}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*image-digest-pinned\|image-digest-pinned.*FAIL\|digest"; then
    tresult_pass "fail-digest"
else
    tresult_fail "fail-digest" "expected exit 1 with FAIL [image-digest-pinned]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-evidence — evidence-freshness gate
# INJECT_DATE=false so the stale 2010-01-01 date is preserved.
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "${TESTDATA}/fail-evidence" false)"
_exit="$(run_validator "${_tmp}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*evidence-freshness\|evidence-freshness.*FAIL"; then
    tresult_pass "fail-evidence"
else
    tresult_fail "fail-evidence" "expected exit 1 with FAIL [evidence-freshness]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Test: fail-overclaim — overclaim-and-boring-guard gate
# INJECT_DATE=true so evidence-freshness does not also fail.
# ---------------------------------------------------------------------------
_tmp="$(make_overlay "${TESTDATA}/fail-overclaim" true)"
_exit="$(run_validator "${_tmp}" "${PASS_FIPS_FILE}")"
_output="$(run_validator_output "${_tmp}" "${PASS_FIPS_FILE}")"
rm -rf "${_tmp}"

if [[ "${_exit}" -ne 0 ]] && echo "${_output}" | grep -qi "FAIL.*overclaim\|overclaim.*FAIL"; then
    tresult_pass "fail-overclaim"
else
    tresult_fail "fail-overclaim" "expected exit 1 with FAIL [overclaim-and-boring-guard]; got exit ${_exit}"
    printf '  Validator output:\n%s\n' "${_output}" >&2
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n'
if [[ ${FAIL_COUNT} -gt 0 ]]; then
    printf 'RESULT  %d/%d test(s) FAILED.\n' "${FAIL_COUNT}" "$(( PASS_COUNT + FAIL_COUNT ))" >&2
    exit 1
fi
printf 'RESULT  All %d test(s) PASSED.\n' "${PASS_COUNT}"
exit 0
