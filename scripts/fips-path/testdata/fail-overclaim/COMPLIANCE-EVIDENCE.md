# FIPS-Path Compliance Evidence — fail-overclaim fixture
# INTENTIONALLY contains prohibited Vault FIPS overclaim wording to trigger
# the overclaim-and-boring-guard gate.
# Note: test runner injects today's date so evidence-freshness does not also fail.

## §1 OSS Posture Claim (INTENTIONAL OVERCLAIM — FOR TESTING ONLY)

Vault is FIPS 140-3 compliant.

This fixture is used to verify the overclaim wording gate fires on prohibited
phrases.  The approved phrase is:
"Vault Community is deployed in a FIPS-aligned configuration; Vault's internal
cryptographic operations are not performed in a CMVP-validated module."
