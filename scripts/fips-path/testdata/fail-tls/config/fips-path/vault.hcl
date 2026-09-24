# FIPS-path Vault HCL — fail-tls fixture
# INTENTIONALLY sets tls_min_version below tls12 and omits tls_cipher_suites
# to trigger the tls-settings gate.

listener "tcp" {
  address          = "0.0.0.0:8200"
  tls_cert_file    = "<PLACEHOLDER-CERT-PATH>"
  tls_key_file     = "<PLACEHOLDER-KEY-PATH>"
  tls_min_version  = "tls10"
  # tls_cipher_suites intentionally omitted to trigger the cipher suites gate
}

seal "awskms" {
  region     = "<aws-region>"
  kms_key_id = "<PLACEHOLDER-KMS-KEY-ID>"
  endpoint   = "https://kms-fips.<aws-region>.amazonaws.com"
}
