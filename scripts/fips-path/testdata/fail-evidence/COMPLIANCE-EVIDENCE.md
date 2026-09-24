# FIPS-Path Compliance Evidence — fail-evidence fixture
# INTENTIONALLY contains a stale verification date (2010-01-01) to trigger
# the evidence-freshness gate (max 90 days).
# This date must remain clearly older than 90 days across all future runs.

## §1 OSS Posture Claim

Vault Community is deployed in a FIPS-aligned configuration; Vault's internal
cryptographic operations are not performed in a CMVP-validated module.

## §6 Verification Log

| Check                      | Command                                 | Result       | Verifier   | Date       |
|----------------------------|-----------------------------------------|--------------|------------|------------|
| Verification Date          | 2010-01-01                              | STALE        | Test       | 2010-01-01 |
