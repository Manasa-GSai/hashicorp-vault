#!/usr/bin/env bash
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1
#
# validate-oss-posture.sh — OSS FIPS-path eight-gate compliance validator
#
# Runs deterministic, offline checks against the FIPS-path artifact set to
# enforce the bounded OSS FIPS-aligned posture claim.  Exits 0 only when
# every gate passes.  Each failed gate emits a FAIL line naming the rule and
# the relevant artifact path so operators can remediate multiple violations in
# one cycle without re-running after every fix.
#
# Environment overrides:
#   FIPS_PATH_ROOT       Repository root (default: two levels above this
#                        script, i.e. the vault checkout root)
#   FIPS_HOST_FIPS_FILE  Path to host FIPS state file
#                        (default: /proc/sys/crypto/fips_enabled)
#
# Usage:
#   scripts/fips-path/validate-oss-posture.sh
#   FIPS_HOST_FIPS_FILE=/tmp/fips_1 scripts/fips-path/validate-oss-posture.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$(cd "${SCRIPT_DIR}" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="${FIPS_PATH_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
HOST_FIPS_FILE="${FIPS_HOST_FIPS_FILE:-/proc/sys/crypto/fips_enabled}"

# Accumulated failure count — gates record FAIL lines but do not abort early
# so operators can see every violation in a single run.
FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pass() {
    local gate="$1"; shift
    printf 'PASS  [%s] %s\n' "${gate}" "$*"
}

fail() {
    local gate="$1"; shift
    printf 'FAIL  [%s] %s\n' "${gate}" "$*" >&2
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
}

# strip_comments <file>  — emit file content with comment lines removed.
# Handles: # (YAML/HCL/shell), // (HCL/JSON), /* */ (block, single line).
strip_comments() {
    grep -v -E '^\s*(#|//|\*)' "$1" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# FIPS-path artifact paths (scoped — do NOT scan the entire source tree)
# ---------------------------------------------------------------------------

FIPS_HCL="${ROOT}/config/fips-path/vault.hcl"
FIPS_HELM="${ROOT}/helm/fips-path/values.yaml"
COMPLIANCE_EVIDENCE="${ROOT}/COMPLIANCE-EVIDENCE.md"
FIPS_BOUNDARY_DOC="${ROOT}/FIPS-140-3-COMPLIANCE.md"
FIPS_MANIFEST="${ROOT}/fips-path/fips-path-manifest.json"
FIPS_WORDING="${ROOT}/scripts/fips-path/overclaim-patterns.txt"
DOCKERFILE="${ROOT}/Dockerfile"

# Scoped files used for multi-file algorithm scans.
# JSON manifest is excluded — its "description" fields are prose, not config.
# The wording guardrail file is excluded — it documents prohibited patterns.
# The boundary definition document (FIPS-140-3-COMPLIANCE.md) is excluded from
# algorithm and overclaim scans — it intentionally lists prohibited phrases as
# negative examples for operator education.
FIPS_SCAN_FILES=()
for _f in "${FIPS_HCL}" "${FIPS_HELM}" "${COMPLIANCE_EVIDENCE}"; do
    [[ -f "${_f}" ]] && FIPS_SCAN_FILES+=("${_f}")
done

# ---------------------------------------------------------------------------
# Gate 1: glibc / non-Alpine image
#
# FIPS-path image artifacts must not select Alpine or musl libc as a runtime
# base.  Only the FIPS-path Helm values and the Dockerfile fips-path-builder
# stage are checked — the general OSS Alpine default target is out of scope.
# Comment lines are stripped before scanning so documentation that mentions
# Alpine or musl in a rejection or comparison context does not false-trigger.
# ---------------------------------------------------------------------------
GATE_ALPINE="image-glibc"

_alpine_fail=0

if [[ -f "${FIPS_HELM}" ]]; then
    if strip_comments "${FIPS_HELM}" | grep -qiE '\b(alpine|musl)\b'; then
        fail "${GATE_ALPINE}" "Alpine/musl reference found outside comments in ${FIPS_HELM}"
        _alpine_fail=1
    fi
fi

if [[ -f "${DOCKERFILE}" ]]; then
    # Extract only the fips-path-builder stage (between its FROM line and the
    # next FROM line).
    _fips_stage_block=""
    _in_stage=0
    while IFS= read -r _line; do
        if echo "${_line}" | grep -qi 'fips-path-builder'; then
            _in_stage=1
        fi
        if [[ ${_in_stage} -eq 1 ]]; then
            # A new FROM that is not our stage header ends the stage — do NOT
            # include the terminating FROM line in the scanned block.
            if echo "${_line}" | grep -qiE '^FROM ' && ! echo "${_line}" | grep -qi 'fips-path-builder'; then
                _in_stage=0
            else
                _fips_stage_block+="${_line}"$'\n'
            fi
        fi
    done < "${DOCKERFILE}"

    if [[ -n "${_fips_stage_block}" ]]; then
        # Strip comment lines from the stage before searching.
        _stage_no_comments="$(printf '%s' "${_fips_stage_block}" | grep -v -E '^\s*#' || true)"
        if printf '%s' "${_stage_no_comments}" | grep -qiE '\b(alpine|musl)\b'; then
            fail "${GATE_ALPINE}" "Alpine/musl reference found outside comments in Dockerfile fips-path-builder stage"
            _alpine_fail=1
        fi
    fi
fi

if [[ ${_alpine_fail} -eq 0 ]]; then
    pass "${GATE_ALPINE}" "No Alpine or musl references in FIPS-path image artifacts (non-comment lines)"
fi

# ---------------------------------------------------------------------------
# Gate 2: Host OS FIPS state
#
# The host kernel FIPS mode file must contain exactly "1".  The file path is
# overridable via FIPS_HOST_FIPS_FILE for test environments that cannot modify
# /proc/sys/crypto/fips_enabled.
# ---------------------------------------------------------------------------
GATE_HOST="host-fips"

if [[ ! -f "${HOST_FIPS_FILE}" ]]; then
    fail "${GATE_HOST}" "FIPS state file not found or unreadable: ${HOST_FIPS_FILE} — /proc/sys/crypto/fips_enabled must be accessible on the runner"
else
    _host_val="$(tr -d '[:space:]' < "${HOST_FIPS_FILE}")"
    case "${_host_val}" in
        1)  pass "${GATE_HOST}" "Host OS FIPS mode is enabled (${HOST_FIPS_FILE}=1)" ;;
        0)  fail "${GATE_HOST}" "/proc/sys/crypto/fips_enabled is 0 — host OS FIPS mode is not enabled; check ${HOST_FIPS_FILE}" ;;
        *)  fail "${GATE_HOST}" "/proc/sys/crypto/fips_enabled contains unexpected value; check ${HOST_FIPS_FILE}" ;;
    esac
fi

# ---------------------------------------------------------------------------
# Gate 3: TLS listener settings
#
# The FIPS-path HCL example must set tls_min_version to "tls12" or "tls13"
# and must declare an explicit tls_cipher_suites value.
# ---------------------------------------------------------------------------
GATE_TLS="tls-settings"

_tls_fail=0
if [[ ! -f "${FIPS_HCL}" ]]; then
    fail "${GATE_TLS}" "FIPS-path HCL config not found: ${FIPS_HCL}"
    _tls_fail=1
else
    if grep -qE 'tls_min_version\s*=\s*"tls1[23]"' "${FIPS_HCL}"; then
        _min_ver="$(grep -oE 'tls_min_version\s*=\s*"[^"]+"' "${FIPS_HCL}" | head -1)"
        pass "${GATE_TLS}" "tls_min_version is acceptable: ${_min_ver}"
    else
        fail "${GATE_TLS}" "tls_min_version is missing or not tls12/tls13 in ${FIPS_HCL}"
        _tls_fail=1
    fi

    if grep -qE 'tls_cipher_suites\s*=\s*"[^"]+"' "${FIPS_HCL}"; then
        pass "${GATE_TLS}" "tls_cipher_suites is explicitly set in ${FIPS_HCL}"
    else
        fail "${GATE_TLS}" "tls_cipher_suites is missing or empty in ${FIPS_HCL}"
        _tls_fail=1
    fi
fi

# ---------------------------------------------------------------------------
# Gate 4: Prohibited algorithm references
#
# FIPS-path HCL and YAML config files must not reference weak or disallowed
# algorithms in their non-comment content.  Comment lines (starting with #
# or //) are stripped before scanning so educational inline notes do not
# trigger this gate.  JSON manifest files are excluded because their
# "description" fields are prose documentation, not algorithm identifiers.
#
# Patterns (case-insensitive): chacha20, poly1305, ff3-1, x25519, ed25519,
# tls1.0, tls1.1, md5, sha1 (not sha1[23456]), 3des/triple-des, rc4.
# ---------------------------------------------------------------------------
GATE_ALGO="prohibited-algorithms"

# Word-boundary-based pattern (BRE-safe: uses [^a-zA-Z0-9_] boundaries
# instead of \b which is not portable across all grep ERE implementations).
_PROHIBITED_ALGO_PATTERN='(chacha20|poly1305|ff3[-_]?1|x25519|ed25519|tls1[._]0|tls1[._]1|(^|[^a-zA-Z0-9_])md5([^a-zA-Z0-9_]|$)|(^|[^a-zA-Z0-9_])sha-?1([^23456a-zA-Z0-9_]|$)|(^|[^a-zA-Z0-9_])(3des|triple.?des|rc4)([^a-zA-Z0-9_]|$))'

_algo_fail=0
for _f in "${FIPS_SCAN_FILES[@]+"${FIPS_SCAN_FILES[@]}"}"; do
    _stripped="$(strip_comments "${_f}")"
    if echo "${_stripped}" | grep -qiE "${_PROHIBITED_ALGO_PATTERN}"; then
        _matches="$(echo "${_stripped}" | grep -inE "${_PROHIBITED_ALGO_PATTERN}" | cut -c1-200)"
        fail "${GATE_ALGO}" "Prohibited algorithm reference in ${_f}:"$'\n'"${_matches}"
        _algo_fail=1
    fi
done

if [[ ${_algo_fail} -eq 0 ]]; then
    pass "${GATE_ALGO}" "No prohibited algorithm references in non-comment content of FIPS-path config artifacts"
fi

# ---------------------------------------------------------------------------
# Gate 5: AWS KMS FIPS endpoint
#
# Any awskms seal "endpoint" value that is not a placeholder must use the
# kms-fips.<region>.amazonaws.com form.
# ---------------------------------------------------------------------------
GATE_KMS="awskms-fips-endpoint"

_kms_fail=0
if [[ -f "${FIPS_HCL}" ]]; then
    _endpoint_lines="$(grep -iE '^\s*endpoint\s*=' "${FIPS_HCL}" 2>/dev/null || true)"
    if [[ -n "${_endpoint_lines}" ]]; then
        while IFS= read -r _eline; do
            # Skip placeholder lines (angle-bracket markers like <aws-region>)
            echo "${_eline}" | grep -q '<' && continue
            if ! echo "${_eline}" | grep -qi 'kms-fips\.'; then
                fail "${GATE_KMS}" "Non-FIPS awskms endpoint in ${FIPS_HCL} — use kms-fips.<region>.amazonaws.com; found: ${_eline}"
                _kms_fail=1
            fi
        done <<< "${_endpoint_lines}"
    fi
fi

if [[ ${_kms_fail} -eq 0 ]]; then
    pass "${GATE_KMS}" "AWS KMS endpoint in FIPS-path HCL uses kms-fips format (or is a placeholder)"
fi

# ---------------------------------------------------------------------------
# Gate 6: Image digest pinning
#
# FIPS-path image references must use @sha256: digest pins.  Helm values and
# the manifest are checked for the presence of sha256 digest annotations.
# ---------------------------------------------------------------------------
GATE_DIGEST="image-digest-pinned"

_digest_fail=0
_IMAGE_FILES=()
[[ -f "${FIPS_HELM}" ]]     && _IMAGE_FILES+=("${FIPS_HELM}")
[[ -f "${FIPS_MANIFEST}" ]] && _IMAGE_FILES+=("${FIPS_MANIFEST}")

for _f in "${_IMAGE_FILES[@]+"${_IMAGE_FILES[@]}"}"; do
    if grep -qiE '(image|repository|tag)\s*[=:]' "${_f}" 2>/dev/null; then
        if ! grep -qiE 'sha256' "${_f}" 2>/dev/null; then
            fail "${GATE_DIGEST}" "No sha256 digest pinning found in ${_f} — FIPS-path images must be digest-pinned"
            _digest_fail=1
        fi
    fi
done

if [[ ${_digest_fail} -eq 0 ]]; then
    pass "${GATE_DIGEST}" "SHA-256 image digest pinning guidance present in FIPS-path image artifact files"
fi

# ---------------------------------------------------------------------------
# Gate 7: COMPLIANCE-EVIDENCE.md freshness
#
# The file must exist and must contain a real (non-placeholder) verification
# date no older than 90 days.  The date must be in ISO-8601 (YYYY-MM-DD)
# format on a line that mentions "verification" or "date".
# ---------------------------------------------------------------------------
GATE_EVIDENCE="evidence-freshness"

if [[ ! -f "${COMPLIANCE_EVIDENCE}" ]]; then
    fail "${GATE_EVIDENCE}" "COMPLIANCE-EVIDENCE.md not found at ${COMPLIANCE_EVIDENCE}"
else
    # Search for a real date (not a placeholder like <YYYY-MM-DD> or YYYY-MM-DD
    # with literal letters).
    _evidence_date=""

    # Try lines mentioning "verification" or "date" first.
    _evidence_date="$(grep -iE '(verification|date)' "${COMPLIANCE_EVIDENCE}" \
        | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | grep -v '0000-00-00' | tail -1 || true)"

    # Fallback: any ISO date in the file.
    if [[ -z "${_evidence_date}" ]]; then
        _evidence_date="$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "${COMPLIANCE_EVIDENCE}" \
            | grep -v '0000-00-00' | head -1 || true)"
    fi

    if [[ -z "${_evidence_date}" ]]; then
        fail "${GATE_EVIDENCE}" "No parseable YYYY-MM-DD verification date found in ${COMPLIANCE_EVIDENCE} — fill in the verification date before release"
    else
        _now_epoch="$(date -u +%s)"
        # GNU date (Linux runners): date -d. BSD date (macOS dev): date -j -f.
        _evidence_epoch="$(date -u -d "${_evidence_date}" +%s 2>/dev/null || \
            date -u -j -f "%Y-%m-%d" "${_evidence_date}" +%s 2>/dev/null || echo 0)"
        _max_age_secs=$(( 90 * 86400 ))
        _age_secs=$(( _now_epoch - _evidence_epoch ))

        if [[ ${_evidence_epoch} -eq 0 ]]; then
            fail "${GATE_EVIDENCE}" "Could not parse date '${_evidence_date}' from ${COMPLIANCE_EVIDENCE}"
        elif [[ ${_age_secs} -gt ${_max_age_secs} ]]; then
            _age_days=$(( _age_secs / 86400 ))
            fail "${GATE_EVIDENCE}" "Verification date ${_evidence_date} is ${_age_days} days old (max 90) in ${COMPLIANCE_EVIDENCE} — refresh evidence before release"
        else
            _age_days=$(( _age_secs / 86400 ))
            pass "${GATE_EVIDENCE}" "COMPLIANCE-EVIDENCE.md verification date ${_evidence_date} is ${_age_days} days old (within 90-day window)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Gate 8: Markdown overclaim detection and goboringcrypto/BoringCrypto guard
#
# Operator-facing Markdown must not use language that overstates the bounded
# OSS FIPS posture.  Prohibited phrases are loaded from
# scripts/fips-path/overclaim-patterns.txt (PROHIBITED: lines).
#
# IMPORTANT: FIPS-140-3-COMPLIANCE.md is the BOUNDARY DEFINITION document; it
# intentionally lists prohibited phrases as negative examples for operator
# education.  It is excluded from this scan.  Only COMPLIANCE-EVIDENCE.md
# (the per-release operator evidence package) is scanned for overclaims.
#
# The goboringcrypto/BoringCrypto guard also runs against FIPS-path HCL and
# YAML config files.  Markdown templates (which may reference BoringCrypto in
# the Enterprise upgrade path context) and the validator script itself are
# excluded.
# ---------------------------------------------------------------------------
GATE_OVERCLAIM="overclaim-and-boring-guard"

_overclaim_fail=0

# Load prohibited phrases from the wording guardrail file.
_prohibited_patterns=()
if [[ -f "${FIPS_WORDING}" ]]; then
    while IFS= read -r _pline; do
        if [[ "${_pline}" == PROHIBITED:* ]]; then
            _phrase="${_pline#PROHIBITED: }"
            _phrase="${_phrase%$'\r'}"
            [[ -n "${_phrase}" ]] && _prohibited_patterns+=("${_phrase}")
        fi
    done < "${FIPS_WORDING}"
fi

# Only scan COMPLIANCE-EVIDENCE.md for overclaim phrases.
# FIPS-140-3-COMPLIANCE.md is a boundary definition document that intentionally
# shows prohibited wording as negative examples — it must not be scanned.
_OVERCLAIM_SCAN_FILES=()
[[ -f "${COMPLIANCE_EVIDENCE}" ]] && _OVERCLAIM_SCAN_FILES+=("${COMPLIANCE_EVIDENCE}")

for _mdfile in "${_OVERCLAIM_SCAN_FILES[@]+"${_OVERCLAIM_SCAN_FILES[@]}"}"; do
    for _phrase in "${_prohibited_patterns[@]+"${_prohibited_patterns[@]}"}"; do
        if grep -qiF "${_phrase}" "${_mdfile}" 2>/dev/null; then
            fail "${GATE_OVERCLAIM}" "Prohibited wording '${_phrase}' found in ${_mdfile}"
            _overclaim_fail=1
        fi
    done

    # Hard-coded additional overclaim patterns not in the guardrail file.
    _EXTRA_OVERCLAIM='(FIPS 140-3 (validated|certified|compliant)|is FIPS compliant|FIPS mode enabled|FIPS 140-4 compliant)'
    if grep -qiE "${_EXTRA_OVERCLAIM}" "${_mdfile}" 2>/dev/null; then
        fail "${GATE_OVERCLAIM}" "Overclaim pattern detected in ${_mdfile} — use the approved OSS posture phrase"
        _overclaim_fail=1
    fi
done

# BoringCrypto/goboringcrypto guard: reject from FIPS-path HCL and YAML config
# files only.  Markdown templates (which document the Enterprise upgrade path)
# and the validator script itself are excluded from this check.
_BORING_PATTERN='(goboringcrypto|GOEXPERIMENT=boringcrypto|BoringCrypto|go tool nm)'
_BORING_SCAN_FILES=()
for _f in "${FIPS_HCL}" "${FIPS_HELM}"; do
    [[ -f "${_f}" ]] && _BORING_SCAN_FILES+=("${_f}")
done

for _f in "${_BORING_SCAN_FILES[@]+"${_BORING_SCAN_FILES[@]}"}"; do
    if grep -qiE "${_BORING_PATTERN}" "${_f}" 2>/dev/null; then
        fail "${GATE_OVERCLAIM}" "BoringCrypto/GOEXPERIMENT reference in ${_f} — these patterns create false assurance for Vault Community"
        _overclaim_fail=1
    fi
done

# Check other scripts in scripts/fips-path/*.sh (excluding this validator script).
while IFS= read -r -d '' _sf; do
    # Skip the validator script itself — it defines the pattern to scan FOR.
    [[ "${_sf}" == "${SCRIPT_PATH}" ]] && continue
    if grep -qiE "${_BORING_PATTERN}" "${_sf}" 2>/dev/null; then
        fail "${GATE_OVERCLAIM}" "BoringCrypto/goboringcrypto reference in ${_sf} — prohibited in OSS FIPS-path scripts"
        _overclaim_fail=1
    fi
done < <(find "${ROOT}/scripts/fips-path" -maxdepth 1 -name '*.sh' -print0 2>/dev/null || true)

if [[ ${_overclaim_fail} -eq 0 ]]; then
    pass "${GATE_OVERCLAIM}" "No overclaim or BoringCrypto/GOEXPERIMENT references in scanned FIPS-path artifacts"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf '\n'
if [[ ${FAIL_COUNT} -eq 0 ]]; then
    printf 'RESULT  All eight OSS FIPS-path gates PASSED.\n'
    exit 0
else
    printf 'RESULT  %d gate(s) FAILED — resolve FAIL lines above before releasing a FIPS-path artifact.\n' \
        "${FAIL_COUNT}" >&2
    exit 1
fi
