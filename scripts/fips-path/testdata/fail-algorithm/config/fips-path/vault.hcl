# FIPS-path Vault HCL — fail-algorithm fixture
# INTENTIONALLY includes a chacha20-poly1305 cipher reference in a non-comment
# configuration value to trigger the prohibited-algorithms gate.

listener "tcp" {
  address           = "0.0.0.0:8200"
  tls_cert_file     = "<PLACEHOLDER-CERT-PATH>"
  tls_key_file      = "<PLACEHOLDER-KEY-PATH>"
  tls_min_version   = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,chacha20-poly1305"
}

seal "awskms" {
  region     = "<aws-region>"
  kms_key_id = "<PLACEHOLDER-KMS-KEY-ID>"
  endpoint   = "https://kms-fips.<aws-region>.amazonaws.com"
}
