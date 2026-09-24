# FIPS 140-3 Compliance Evidence

> **Release Owner:** TO-BE-FILLED-BY-RELEASE-OWNER
> **Vault Version:** TO-BE-FILLED-BY-RELEASE-OWNER
> **Evidence Date:** TO-BE-FILLED-BY-RELEASE-OWNER
> **Next Review Due:** TO-BE-FILLED-BY-RELEASE-OWNER (must be within 90 days of evidence date)

This document is the audit anchor for each Vault Community OSS FIPS-path release. It must be
completed, reviewed, and signed off before a FIPS-path release artifact is promoted. Evidence
older than 90 days cannot be used for FIPS-path release sign-off.

---

## 1. OSS Posture Claim

The following bounded claim applies to this release. It is reproduced verbatim from
[FIPS-140-3-COMPLIANCE.md §2a](./FIPS-140-3-COMPLIANCE.md) and must not be modified here:

> Vault Community is deployed in a FIPS-aligned configuration; Vault's internal cryptographic
> operations are not performed in a CMVP-validated module.

This claim is valid only when all deployment prerequisites in FIPS-140-3-COMPLIANCE.md §6 are
satisfied and all fields in this document are populated with release-specific evidence.

---

## 2. Residual Gap — Operations Outside a Validated Boundary

The following Vault Community internal cryptographic operations remain outside any CMVP-validated
module for this release. They must be disclosed to auditors and must not be described as
operating within a validated boundary:

| Operation | Component | Residual Gap Status |
|---|---|---|
| Vault Community binary — all internal Go crypto | Vault OSS binary | **Outside validated boundary** |
| barrier encryption / decryption | `vault/barrier_aes_gcm.go` | **Outside validated boundary** |
| Transit engine encrypt / decrypt / sign / HMAC | `builtin/logical/transit` | **Outside validated boundary** |
| PKI engine certificate and key generation | `builtin/logical/pki` | **Outside validated boundary** |
| token HMAC derivation | `vault/token_store.go` | **Outside validated boundary** |
| audit HMAC derivation | `audit/` | **Outside validated boundary** |
| Listener TLS termination via Go `crypto/tls` | `http/handler.go` | **Outside validated boundary** |

> **Note:** Vault Community's internal cryptographic operations are not performed in a CMVP-validated module. Cloud KMS auto-unseal narrows the key-wrapping boundary only and does not validate the operations listed above.

---

## 3. CMVP Certificate Evidence

Complete one row per validated module used at an available boundary in this release. Mark
unused providers as **Not in boundary** rather than leaving the row blank or inventing
certificate numbers.

| Module Name | Provider | CMVP Certificate # | Certificate Status | Security Policy PDF | Exact Package / Service Version | Boundary Role |
|---|---|---|---|---|---|---|
| AWS KMS (FIPS endpoint) | Amazon Web Services | TO-BE-FILLED-BY-RELEASE-OWNER | TO-BE-FILLED (Active / Historical) | TO-BE-FILLED-BY-RELEASE-OWNER | kms-fips.\<region\>.amazonaws.com | Unseal key wrap/unwrap only |
| Azure Key Vault (HSM) | Microsoft | Not in boundary | — | — | — | — |
| GCP Cloud HSM | Google | Not in boundary | — | — | — | — |
| On-prem PKCS#11 HSM | N/A (Enterprise Plus only) | Not in boundary | — | — | — | — |
| System OpenSSL FIPS Provider | OS vendor (UBI/Debian) | TO-BE-FILLED-BY-RELEASE-OWNER | TO-BE-FILLED | TO-BE-FILLED-BY-RELEASE-OWNER | TO-BE-FILLED (e.g. openssl 3.x.x) | glibc crypto boundary for fips-path-builder |

### 3a. Security Policy PDF Links

For each validated module listed above, provide a direct link to the NIST CMVP Security Policy PDF:

- **AWS KMS:** TO-BE-FILLED-BY-RELEASE-OWNER (https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/...)
- **System OpenSSL FIPS Provider:** TO-BE-FILLED-BY-RELEASE-OWNER

---

## 4. SBOM and Provenance

Release sign-off is **blocked** until all fields below are populated. Placeholder values are
not acceptable for production FIPS-path releases.

| Field | Value |
|---|---|
| **SBOM format** | CycloneDX or SPDX (TO-BE-FILLED-BY-RELEASE-OWNER) |
| **SBOM artifact path / URL** | TO-BE-FILLED-BY-RELEASE-OWNER |
| **SBOM crypto library versions** | TO-BE-FILLED (list Go crypto, OpenSSL, and seal provider versions) |
| **Provenance artifact path / URL** | TO-BE-FILLED-BY-RELEASE-OWNER |
| **Vault version** | TO-BE-FILLED-BY-RELEASE-OWNER |
| **Vault git commit SHA** | TO-BE-FILLED-BY-RELEASE-OWNER |
| **base image digest** | TO-BE-FILLED-BY-RELEASE-OWNER (sha256:...) |
| **golang-fips/go toolchain version** | TO-BE-FILLED-BY-RELEASE-OWNER |
| **Build pipeline run URL** | TO-BE-FILLED-BY-RELEASE-OWNER |

---

## 5. Runtime Configuration

Provide the FIPS-path runtime configuration diff for this release. **Redact all tokens, private
keys, credentials, connection strings, and sensitive cryptographic material before committing.**

```hcl
# REDACTED FIPS-PATH RUNTIME CONFIG DIFF
# TO-BE-FILLED-BY-RELEASE-OWNER
# Required fields: listener TLS min version, cipher suites, seal stanza type and endpoint,
# storage backend, disabled algorithms list.
# DO NOT commit actual secrets, tokens, private keys, or credentials here.
```

---

## 6. Verification Log

Complete one entry per verification run. Evidence age is measured from the most recent entry.
**Verification must be rerun every release and evidence older than 90 days cannot be used for
FIPS-path release sign-off.**

| Check | Command / Method | Result | Date | Verifier |
|---|---|---|---|---|
| OS FIPS mode enabled | `cat /proc/sys/crypto/fips_enabled` → must be `1` | TO-BE-FILLED | TO-BE-FILLED | TO-BE-FILLED |
| glibc container base | `ldd --version` or `getconf GNU_LIBC_VERSION` | TO-BE-FILLED | TO-BE-FILLED | TO-BE-FILLED |
| TLS suite check | `openssl s_client` or listener config inspection | TO-BE-FILLED | TO-BE-FILLED | TO-BE-FILLED |
| AWS KMS FIPS endpoint check | Seal config `address = kms-fips.<region>.amazonaws.com` | TO-BE-FILLED | TO-BE-FILLED | TO-BE-FILLED |
| No prohibited wording | `grep -f scripts/fips-path/overclaim-patterns.txt **/*.md` | TO-BE-FILLED | TO-BE-FILLED | TO-BE-FILLED |
| Evidence age within 90 days | Date delta from evidence date to today | TO-BE-FILLED | TO-BE-FILLED | TO-BE-FILLED |

**Verifier Identity:** TO-BE-FILLED-BY-RELEASE-OWNER (name, role, team)
**Verification Date:** TO-BE-FILLED-BY-RELEASE-OWNER
**Release Version:** TO-BE-FILLED-BY-RELEASE-OWNER

---

## 7. Enterprise Plus Upgrade Path

> **This section applies if you are evaluating a transition to the official HashiCorp FIPS path.**

Vault Enterprise Plus is the official HashiCorp-supported FIPS path. It links a CMVP-validated
BoringCrypto module and removes the residual gap described in §2. If your compliance posture
requires formal FIPS 140-3 product validation (rather than the bounded OSS deployment claim in
§1), you must use Vault Enterprise Plus.

When transitioning to Enterprise Plus:

1. Replace this OSS evidence document with the Enterprise Plus FIPS evidence package.
2. Update CMVP certificate references to the BoringCrypto certificate applicable to the
   Enterprise Plus build.
3. Remove the OSS residual-gap disclosure in §2 and replace it with the Enterprise Plus
   boundary statement.
4. Do not carry over OSS posture language into Enterprise Plus documentation.

---

## 8. Sign-Off Checklist

Release sign-off requires ALL of the following to be ✅:

- [ ] §3 CMVP certificate table fully populated — no TO-BE-FILLED rows for in-boundary modules
- [ ] §3a Security Policy PDF links present for all validated modules
- [ ] §4 SBOM format, artifact path, crypto library versions, provenance, base image digest, and Vault version all populated
- [ ] §5 Runtime config diff present and redacted of secrets
- [ ] §6 All verification log rows completed with result, date, and verifier identity
- [ ] §6 Verification date within 90 days of this release
- [ ] §6 Verifier identity named (not anonymous)
- [ ] No prohibited wording from `scripts/fips-path/overclaim-patterns.txt` present in any FIPS-path artifact
