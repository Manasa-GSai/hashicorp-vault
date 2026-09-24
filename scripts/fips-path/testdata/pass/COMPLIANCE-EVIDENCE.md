# FIPS-Path Compliance Evidence — Test Fixture (pass)

## §1 OSS Posture Claim

Vault Community is deployed in a FIPS-aligned configuration; Vault's internal
cryptographic operations are not performed in a CMVP-validated module.

## §5 Redacted Runtime Configuration

| Setting              | Value                 | Status       |
|----------------------|-----------------------|--------------|
| VAULT_FIPS_PATH      | 1                     | TO-BE-FILLED |
| TLS min version      | tls12                 | TO-BE-FILLED |
| OS FIPS kernel status | fips_enabled=1       | TO-BE-FILLED |

## §6 Verification Log

| Check                         | Command                                      | Result       | Verifier     | Date         |
|-------------------------------|----------------------------------------------|--------------|--------------|--------------|
| Host OS FIPS kernel status    | cat /proc/sys/crypto/fips_enabled            | TO-BE-FILLED | TO-BE-FILLED | TO-BE-FILLED |
