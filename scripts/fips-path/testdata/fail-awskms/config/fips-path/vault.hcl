# FIPS-path Vault HCL — fail-awskms fixture
# INTENTIONALLY uses a standard (non-FIPS) AWS KMS endpoint to trigger the
# awskms-fips-endpoint gate.  The endpoint must contain "kms-fips." in
# production FIPS-path deployments.

listener "tcp" {
  address           = "0.0.0.0:8200"
  tls_cert_file     = "<PLACEHOLDER-CERT-PATH>"
  tls_key_file      = "<PLACEHOLDER-KEY-PATH>"
  tls_min_version   = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "<PLACEHOLDER-KMS-KEY-ID>"
  endpoint   = "https://kms.us-east-1.amazonaws.com"
}
