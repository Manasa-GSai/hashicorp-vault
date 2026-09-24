# FIPS-path Vault HCL example — pass fixture
# All values use FIPS-approved TLS settings and a kms-fips. endpoint.
# Operator-specific values are placeholders only; no real credentials.

listener "tcp" {
  address             = "0.0.0.0:8200"
  tls_cert_file       = "<PLACEHOLDER-CERT-PATH>"
  tls_key_file        = "<PLACEHOLDER-KEY-PATH>"
  tls_min_version     = "tls12"
  tls_cipher_suites   = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384"
}

seal "awskms" {
  region     = "<aws-region>"
  kms_key_id = "<PLACEHOLDER-KMS-KEY-ID>"
  endpoint   = "https://kms-fips.<aws-region>.amazonaws.com"
}

storage "raft" {
  path    = "<PLACEHOLDER-DATA-PATH>"
  node_id = "<PLACEHOLDER-NODE-ID>"
}
