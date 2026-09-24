# FIPS-path Vault Server Configuration Example
#
# This file is a FIPS-path-specific operator example for Vault Community deployments
# that use VAULT_FIPS_PATH=1 to enforce a FIPS-aligned runtime posture.
#
# COMPLIANCE POSTURE (see FIPS-140-3-COMPLIANCE.md §2):
#   Vault Community is deployed in a FIPS-aligned configuration; Vault's internal
#   cryptographic operations are not performed in a CMVP-validated module.
#   The AWS KMS seal provides FIPS 140-3 validated unseal key wrapping at the cloud
#   boundary only. Vault barrier encryption and internal Go operations are residual
#   gaps documented in COMPLIANCE-EVIDENCE.md.
#
# IMPORTANT: Replace all <placeholder> values before use.
#   - Do NOT commit real KMS key IDs, TLS private keys, certificates, tokens,
#     credentials, or connection strings.
#   - Seal configuration notes are advisory; actual FIPS 140-3 module validation
#     is the responsibility of the KMS provider, not Vault Community.
#
# Runtime gate: set VAULT_FIPS_PATH=1 in the environment before starting Vault.

# ---------------------------------------------------------------------------
# Storage Backend
# ---------------------------------------------------------------------------

storage "raft" {
  path    = "/vault/data"
  node_id = "<node-id-placeholder>"

  # For multi-node clusters, add one retry_join stanza per peer.
  # retry_join {
  #   leader_api_addr = "https://<peer-node-address>:8200"
  # }
}

# ---------------------------------------------------------------------------
# Listener: TLS 1.2+ with FIPS-Approved AES-GCM Cipher Suites
#
# tls_min_version is set to "tls12" so that TLS 1.0 and TLS 1.1 are excluded.
# tls_cipher_suites is set to the approved AES-GCM suite list.  TLS 1.3 cipher
# selection in Go's crypto/tls is automatic and not governed by tls_cipher_suites,
# but the explicit list is required here for TLS 1.2 audit evidence and for
# CI validation by scripts/fips-path/validate-oss-posture.sh.
#
# Approved cipher suites reference (NIST SP 800-52 Rev 2):
#   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    — ECDHE key exchange, AES-128-GCM AEAD
#   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    — ECDHE key exchange, AES-256-GCM AEAD
#   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  — ECDSA key exchange, AES-128-GCM AEAD
#   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  — ECDSA key exchange, AES-256-GCM AEAD
#   TLS_RSA_WITH_AES_128_GCM_SHA256          — RSA key exchange, AES-128-GCM AEAD
#   TLS_RSA_WITH_AES_256_GCM_SHA384          — RSA key exchange, AES-256-GCM AEAD
# ---------------------------------------------------------------------------

listener "tcp" {
  address       = "0.0.0.0:8200"
  cluster_addr  = "https://<node-address-placeholder>:8201"

  tls_cert_file = "/vault/config/tls.crt"
  tls_key_file  = "/vault/config/tls.key"
  tls_ca_cert   = "/vault/config/ca.crt"

  # FIPS-path TLS requirements:
  tls_min_version = "tls12"

  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384"

  # Disable plaintext access; the FIPS-path posture requires all traffic to use
  # the TLS listener above.
  tls_disable = false
}

# ---------------------------------------------------------------------------
# AWS KMS Auto-Unseal (FIPS-endpoint)
#
# The kms-fips.<region>.amazonaws.com endpoint uses AWS KMS FIPS 140-3 validated
# endpoints (CMVP certificate number varies by module and version; see
# https://csrc.nist.gov/projects/cryptographic-module-validation-program).
#
# BOUNDARY NOTE: the KMS FIPS endpoint validates unseal key wrapping and
# unwrapping only.  Vault barrier encryption (AES-256-GCM) and all internal
# Go cryptographic operations are OUTSIDE the KMS FIPS 140-3 module boundary
# and are documented as residual gaps in COMPLIANCE-EVIDENCE.md.
#
# Replace <aws-region> and <aws-kms-key-id> with real values at deployment time.
# Do NOT commit real key IDs or credentials to this file.
# ---------------------------------------------------------------------------

seal "awskms" {
  region     = "<aws-region>"
  kms_key_id = "<aws-kms-key-id>"
  endpoint   = "https://kms-fips.<aws-region>.amazonaws.com"
}

# ---------------------------------------------------------------------------
# API and UI
# ---------------------------------------------------------------------------

api_addr     = "https://<node-address-placeholder>:8200"
cluster_addr = "https://<node-address-placeholder>:8201"

ui = false

# ---------------------------------------------------------------------------
# Telemetry (optional, uncomment to enable)
# ---------------------------------------------------------------------------

# telemetry {
#   prometheus_retention_time = "30s"
#   disable_hostname          = true
# }

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log_level  = "info"
log_format = "json"

# ---------------------------------------------------------------------------
# Disable mlock (not recommended for production; use kernel capability instead)
# ---------------------------------------------------------------------------

# disable_mlock = true
