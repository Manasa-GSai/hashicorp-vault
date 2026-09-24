# FIPS 140-3 Compliance Posture

This document defines the FIPS 140-3 posture for Vault Community (OSS). It is the authoritative
source of truth for maintainers, operators, and auditors who need to understand what
compliance-oriented claims this project makes, what claims it explicitly does not make, and
which deployment conditions are required before any FIPS-aligned statement may be used.

---

## 1. Terminology

| Term | Definition |
|---|---|
| **FIPS-capable** | The deployment environment supports OS-level FIPS mode and the operator has configured Vault to use only FIPS-Approved algorithms. Vault itself is not validated. |
| **FIPS-compatible** | Vault's configuration and algorithm choices are consistent with FIPS 140-3 Approved methods, but no CMVP validation applies to the Vault binary or its internal Go cryptographic operations. |
| **FIPS-validated** | A cryptographic module holds an active NIST CMVP certificate. Vault Community does **not** hold such a certificate. Only external modules used at available seal and non-Vault boundaries (e.g., an AWS KMS FIPS endpoint) may be described as validated. |
| **CMVP** | Cryptographic Module Validation Program — the NIST program that issues FIPS 140-3 certificates. |
| **Residual gap** | Cryptographic operations performed inside Vault Community that are not covered by any CMVP-validated module boundary. |
| **FIPS-Approved algorithm** | An algorithm permitted by FIPS 140-3 for use in security functions, such as AES-GCM, SHA-2, HMAC-SHA-2, RSA, ECDSA P-256/P-384, and TLS 1.2/1.3. |

---

## 2. OSS Constraint — What Vault Community Cannot Claim

FIPS 140-3 validates cryptographic modules. It does not validate repositories, applications,
complete systems, or codebases. A CMVP certificate is issued to a specific cryptographic module
implementation, not to the product or codebase that uses it.

Vault Community builds and ships with standard Go cryptographic libraries. **The stock Go
`crypto` package and its sub-packages are not CMVP-validated cryptographic modules.**
Therefore:

> **Vault Community / OSS cannot make a FIPS 140-3 compliance claim for its own cryptographic operations because the community build does not link a CMVP-validated cryptographic module.**

No configuration setting, build flag, or environment variable changes this fact. Operators and
downstream documentation **must not** describe Vault Community itself as FIPS 140-3 validated,
certified, or compliant.

### 2a. Defensible Deployment Claim (Section 2a)

A Vault Community deployment **may** make the following bounded posture statement when all
conditions in this section are satisfied:

> Vault Community is deployed in a FIPS-aligned configuration; Vault's internal cryptographic operations are not performed in a CMVP-validated module.

The conditions that must all be present before this statement may be used are:

1. OS-level FIPS mode, FIPS-Approved algorithm restriction in configuration, validated cryptographic modules at available seal and non-Vault boundaries (e.g., AWS KMS via a FIPS endpoint), and documented residual-gap evidence are all present and verifiable.
2. The host operating system has FIPS mode enabled at the kernel level (e.g., the `fips=1`
   kernel parameter on RHEL/UBI; verified via `/proc/sys/crypto/fips_enabled`).
3. Vault's listener is configured with `tls_min_version = "tls12"` (or `"tls13"`) and an
   explicit set of FIPS-Approved cipher suites.
4. The container image used is a glibc-based image (UBI, Debian slim, or equivalent).
   Alpine and musl-based images must not be used for FIPS-path deployments.
5. The `COMPLIANCE-EVIDENCE.md` artifact exists, names a verifier, and has been updated
   within the past 90 days.

If any of these conditions is absent, the statement in this section must not be made.

---

## 3. Residual Gap — Operations Outside a Validated Boundary

The following Vault Community cryptographic operations are performed using standard Go
cryptographic libraries and are **not** covered by any CMVP-validated module:

| Operation | Location / Component |
|---|---|
| barrier encryption and decryption of all data written to the storage backend | `vault/barrier_aes_gcm.go` — AES-256-GCM via Go `crypto/aes` |
| Transit encrypt / Transit decrypt / Transit sign / Transit HMAC via key operations | `builtin/logical/transit` — Go `crypto` via `sdk/helper/keysutil/policy.go` |
| PKI certificate generation, private key generation, and signing operations | `builtin/logical/pki` — Go `crypto/x509`, `crypto/elliptic`, `crypto/rsa` |
| token HMAC derivation used for token accessor and HMAC index lookups | `vault/token_store.go` — Go `crypto/hmac` and `crypto/sha256` |
| audit HMAC derivation applied to sensitive field values in audit log entries | `audit/` — Go `crypto/hmac`; HMAC applied before values reach the audit sink |
| Vault listener TLS termination through Go crypto/tls | `http/handler.go` — Go `crypto/tls`; TLS is not delegated to a validated library |

These operations collectively represent the residual gap for any Vault Community FIPS-aligned
deployment. They must be disclosed in `COMPLIANCE-EVIDENCE.md` and must not be described as
operating within a validated boundary.

> **Cloud KMS auto-unseal narrows the key-wrapping boundary only.** Using AWS KMS via a
> FIPS-validated endpoint means that root and unseal key _wrap_ and _unwrap_ operations cross
> a validated module boundary. It does **not** validate barrier encryption,
> data-at-rest cryptography, Transit operations, PKI key generation, token derivation,
> audit HMAC derivation, or listener TLS termination. Those operations remain in the residual
> gap regardless of seal provider choice.

---

## 4. Approved and Prohibited Wording

### 4a. Approved Wording Examples

The following phrasings are consistent with this posture document and may be used in operator
guides, release notes, and deployment documentation:

- _"Vault Community is deployed in a FIPS-aligned configuration; Vault's internal cryptographic operations are not performed in a CMVP-validated module."_
- _"This deployment uses OS-level FIPS mode and restricts Vault configuration to FIPS-Approved
  algorithms. Vault's internal Go cryptographic operations are outside a validated boundary and
  are documented as residual gaps in COMPLIANCE-EVIDENCE.md."_
- _"The AWS KMS seal uses a FIPS 140-3 validated module for unseal key wrapping. Vault's
  barrier encryption and internal cryptographic operations are not covered by that certificate."_

### 4b. Prohibited Wording Examples

The following phrasings make claims beyond the defensible section 2a posture and **must not**
be used in any project documentation, release announcement, blog post, or operator guide:

| Prohibited phrasing | Why it is prohibited |
|---|---|
| _"Vault is FIPS 140-3 compliant."_ | Implies product validation. Vault Community holds no CMVP certificate. |
| _"Vault is FIPS 140-3 validated."_ | Only a validated module may use the word "validated." |
| _"Vault is FIPS 140-3 certified."_ | Same as above. |
| _"Vault's cryptography is FIPS-approved."_ | Internal Go crypto is not performed in a validated module. |
| _"Enabling FIPS mode makes Vault FIPS compliant."_ | No single configuration switch achieves product validation. |
| _"AWS KMS auto-unseal makes Vault FIPS 140-3 compliant."_ | KMS validates only the key-wrapping boundary, not Vault internals. |

---

## 5. OSS Posture Guardrails — No Runtime Toggle or Local BoringCrypto Assertion

This section documents explicit exclusions that prevent documentation and implementation
from drifting toward misleading OSS compliance claims.

### 5a. No fips-Style Runtime Toggle

Vault Community does not and must not expose a configuration key, API parameter, or
environment variable that claims to enable FIPS compliance at runtime. No configuration flag
alone can make OSS Vault FIPS validated — such a toggle would imply that the Vault binary
switches into a validated cryptographic mode, which is false for the community build. A
fips-style boolean stanza in the listener or server block is not supported and must not be
added to any FIPS-path configuration example.

### 5b. No boringcrypto Build Experiment Assertion for OSS

The boringcrypto Go experiment links BoringSSL-derived cryptography into the Go runtime.
Vault Community release artifacts are **not** built with this experiment. Documentation,
CI scripts, and posture language for OSS must not assert that the boringcrypto experiment
is active, that the boring-crypto Go module is linked, or that OSS builds perform
cryptographic operations inside a CMVP-validated BoringCrypto module.

Using the boringcrypto experiment in Enterprise builds is a separate, Enterprise-scoped
matter and does not affect the OSS posture described in this document.

### 5c. Summary Exclusion Table

| Mechanism | Status for Vault Community OSS | Reason |
|---|---|---|
| fips-style boolean configuration stanza | **Excluded** | No validated module; toggle would be misleading |
| boringcrypto build experiment | **Excluded** from OSS posture | Not present in community release artifacts |
| BoringCrypto symbol gate or assertion | **Excluded** from OSS posture | Not applicable to community build |
| FIPS 140-4 claims | **Out of scope** | FIPS 140-4 is not a valid target for this work; this work targets FIPS 140-3 only. FIPS 140-4 is a separate standard not yet applicable to this project. |
| Enterprise FIPS artifacts (Seal Wrap, PKCS#11 seal, Entropy Augmentation, replication FIPS) | **Out of scope** | Enterprise-only features; not part of OSS posture |

---

## 6. Intended Operating Environments and Deployment Assumptions

The section 2a posture claim is intended for deployments that meet all of the following:

| Requirement | Minimum Prerequisite |
|---|---|
| Host OS | FIPS mode enabled at kernel level; glibc-based (RHEL, UBI, Debian) |
| Container image | glibc-based image (UBI 8/9, Debian slim); no Alpine or musl |
| Vault listener TLS | `tls_min_version = "tls12"` or `"tls13"` with explicit FIPS-Approved cipher suites |
| Seal provider | Cloud KMS via a FIPS-validated endpoint where possible; Shamir otherwise (with residual gap disclosed) |
| Storage backend | Integrated Storage (Raft) — no external Consul dependency in normative FIPS-path reference |
| Evidence artifact | `COMPLIANCE-EVIDENCE.md` present, complete, and updated within 90 days |
| Algorithm restriction | Only FIPS-Approved algorithms configured (AES-GCM, SHA-2, HMAC-SHA-2, RSA ≥ 2048, ECDSA P-256/P-384, TLS 1.2/1.3) |

Deployments that do not meet these prerequisites may not use the section 2a posture statement.

---

## 7. Non-Goals

The following are explicitly out of scope for this document and the OSS FIPS posture:

- Claiming that Vault Community, its repository, or its release binary is FIPS 140-3 validated or certified.
- Describing Enterprise-only features (Seal Wrap, PKCS#11 HSM seal, Entropy Augmentation, FIPS Enterprise binary, replication) as part of the OSS posture.
- Making claims about FIPS 140-4 or any future standard not yet applicable to the community build.
- Providing runtime enforcement of algorithm restrictions inside the Vault binary for OSS builds.
- Replacing or modifying Vault Community's existing cryptographic behavior.

---

## 8. Vault Community OSS vs. Vault Enterprise Plus

Vault Community (OSS) and Vault Enterprise Plus follow distinct FIPS-related paths:

| Aspect | Vault Community (OSS) | Vault Enterprise Plus |
|---|---|---|
| **FIPS path** | FIPS-aligned deployment posture only (section 2a claim) | Official HashiCorp-supported FIPS path with validated module linking |
| **Cryptographic module** | Standard Go `crypto`; not CMVP-validated | Links a CMVP-validated BoringCrypto module (FIPS 140-3 Certificate #4735) |
| **CMVP certificate** | None — OSS binary holds no certificate | BoringCrypto certificate applies to the validated module used in the build |
| **Build experiment** | Not built with the boringcrypto experiment | Built with validated module support enabled |
| **Seal Wrap / Entropy Augmentation** | Not available | Available as Enterprise-only features |
| **Supported FIPS path** | Not the official HashiCorp-supported path | **Enterprise Plus is the official HashiCorp-supported FIPS path** |

> **Vault Enterprise Plus is the official HashiCorp-supported FIPS path.** Operators with
> formal FIPS 140-3 compliance requirements that cannot be satisfied by the section 2a OSS
> deployment posture should use Vault Enterprise Plus.

This document applies only to Vault Community (OSS). Enterprise Plus FIPS behavior, its
CMVP certificate details, and its deployment requirements are governed separately and must
not be described or implied within this OSS posture document.

---

## 8. Maintainer Guidance

This document is the source of truth for subsequent implementation and documentation work
across all work orders in the OSS FIPS 140-3 posture epic. When writing operator guides,
release notes, Helm chart READMEs, or CI pipeline documentation:

1. Verify that any compliance language matches the **approved wording** in §4a.
2. Check that no **prohibited wording** from §4b is present.
3. Confirm the **residual gap** operations from §3 are disclosed where relevant.
4. Do not assert that any mechanism listed in §5c is active in OSS builds.
5. Update `COMPLIANCE-EVIDENCE.md` with a new dated verification entry for each release.
