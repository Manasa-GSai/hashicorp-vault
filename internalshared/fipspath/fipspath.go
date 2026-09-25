// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package fipspath provides the central VAULT_FIPS_PATH enforcement predicate
// and shared policy objects for OSS Vault FIPS-aligned deployment posture.
//
// # OSS FIPS-aligned enforcement mode — not a product validation switch
//
// VAULT_FIPS_PATH is an opt-in runtime enforcement gate. When active it
// enforces approved-algorithm and deployment posture constraints across four
// Vault configuration surfaces: listener TLS settings, AWS KMS seal endpoints,
// Transit/PKI key types, and host OS FIPS status. Enabling this variable does
// NOT make Vault Community a CMVP-validated or FIPS 140-3 certified product.
//
// # Activation values
//
// VAULT_FIPS_PATH is considered active when set to "1", "true", or "enabled"
// (case-insensitive). Any other value — including unset or empty — leaves all
// existing non-FIPS behavior completely unchanged.
//
// # Usage across modules
//
// Packages in the main vault module import this package directly:
//
//	import "github.com/hashicorp/vault/internalshared/fipspath"
//	if fipspath.Enabled() { ... }
//
// Packages in the sdk module (github.com/hashicorp/vault/sdk) are a separate
// Go module and cannot import this package. Those packages inline an equivalent
// predicate using [IsEnabled] semantics.
package fipspath

import (
	"os"
	"strings"
)

// Enabled reports whether VAULT_FIPS_PATH runtime enforcement is currently
// active. It reads the environment variable on every call; results are not
// cached so tests can use t.Setenv without isolation issues.
func Enabled() bool {
	return IsEnabled(os.Getenv("VAULT_FIPS_PATH"))
}

// IsEnabled parses a raw VAULT_FIPS_PATH value and returns true when the value
// indicates enforcement should be active. Exported so callers can test
// predicate logic without manipulating environment variables.
//
// Enabling values (case-insensitive, leading/trailing space ignored):
//   - "1"
//   - "true"
//   - "enabled"
//
// All other values — including "", "0", "false", "disabled" — return false.
func IsEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "enabled":
		return true
	}
	return false
}

// ApprovedTLSCipherSuites is the allow-list of TLS 1.2 cipher suite names
// that are acceptable in a VAULT_FIPS_PATH deployment. TLS 1.3 cipher
// selection is handled automatically by Go's crypto/tls package and is not
// configurable through tls_cipher_suites; this list applies only to the
// explicit tls_cipher_suites HCL configuration field.
//
// Source: NIST SP 800-52 Rev 2, Table 3-1 recommended cipher suites.
var ApprovedTLSCipherSuites = map[string]struct{}{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   {},
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   {},
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": {},
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": {},
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         {},
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         {},
}

// DisallowedTLSVersions lists tls_min_version identifiers that are not
// acceptable in FIPS-path listener configuration. Values are lower-cased;
// callers should normalise input before comparison.
var DisallowedTLSVersions = []string{
	"tls10", "tls1.0",
	"tls11", "tls1.1",
}

// DisallowedAlgorithmNames lists algorithm identifiers that are prohibited in
// FIPS-path security-relevant configuration. These are cross-referenced
// against key type selections, HCL option names, and CI artifact scans when
// VAULT_FIPS_PATH enforcement is active.
//
// ChaCha20-Poly1305, Ed25519, X25519, FF3/FF3-1, MD5, SHA-1, DES, 3DES, and
// RC4 are not FIPS-Approved for security-relevant operations.
var DisallowedAlgorithmNames = []string{
	"chacha20",
	"poly1305",
	"chacha20-poly1305",
	"ed25519",
	"x25519",
	"ff3",
	"ff3-1",
	"md5",
	"sha1",
	"sha-1",
	"des",
	"3des",
	"rc4",
}
