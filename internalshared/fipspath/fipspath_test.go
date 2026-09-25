// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package fipspath

import (
	"strings"
	"testing"
)

// TestIsEnabled covers the full activation matrix for VAULT_FIPS_PATH values.
func TestIsEnabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  bool
	}{
		// Enabling values.
		{name: "digit-one", input: "1", want: true},
		{name: "true-lower", input: "true", want: true},
		{name: "true-upper", input: "TRUE", want: true},
		{name: "true-mixed", input: "True", want: true},
		{name: "enabled-lower", input: "enabled", want: true},
		{name: "enabled-upper", input: "ENABLED", want: true},
		{name: "enabled-mixed", input: "Enabled", want: true},
		// Leading/trailing whitespace must be trimmed.
		{name: "one-with-spaces", input: "  1  ", want: true},
		{name: "true-with-tab", input: "\ttrue\t", want: true},
		{name: "enabled-with-newline", input: "enabled\n", want: true},

		// Non-enabling values — existing OSS behaviour must be unchanged.
		{name: "empty", input: "", want: false},
		{name: "zero", input: "0", want: false},
		{name: "false-lower", input: "false", want: false},
		{name: "false-upper", input: "FALSE", want: false},
		{name: "disabled", input: "disabled", want: false},
		{name: "two", input: "2", want: false},
		{name: "yes", input: "yes", want: false},
		{name: "on", input: "on", want: false},
		{name: "arbitrary", input: "fips", want: false},
		{name: "spaces-only", input: "   ", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := IsEnabled(tc.input)
			if got != tc.want {
				t.Errorf("IsEnabled(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestEnabled_EnvVar verifies that Enabled() reads the live environment
// variable and reflects t.Setenv changes immediately.
func TestEnabled_EnvVar(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "unset", value: "", want: false},
		{name: "one", value: "1", want: true},
		{name: "true", value: "true", want: true},
		{name: "enabled", value: "enabled", want: true},
		{name: "zero", value: "0", want: false},
		{name: "false", value: "false", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv restores the original value after the sub-test.
			t.Setenv("VAULT_FIPS_PATH", tc.value)
			got := Enabled()
			if got != tc.want {
				t.Errorf("Enabled() with VAULT_FIPS_PATH=%q = %v, want %v",
					tc.value, got, tc.want)
			}
		})
	}
}

// TestApprovedTLSCipherSuites verifies the allow-list contains the expected
// NIST SP 800-52 Rev 2 cipher suites and excludes known non-approved ones.
func TestApprovedTLSCipherSuites(t *testing.T) {
	t.Parallel()

	approved := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
	}
	notApproved := []string{
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	}

	for _, suite := range approved {
		if _, ok := ApprovedTLSCipherSuites[suite]; !ok {
			t.Errorf("expected %q to be in ApprovedTLSCipherSuites", suite)
		}
	}
	for _, suite := range notApproved {
		if _, ok := ApprovedTLSCipherSuites[suite]; ok {
			t.Errorf("expected %q to NOT be in ApprovedTLSCipherSuites", suite)
		}
	}
}

// TestDisallowedAlgorithmNames verifies that the prohibited algorithm list
// covers all required FIPS-path exclusions.
func TestDisallowedAlgorithmNames(t *testing.T) {
	t.Parallel()

	required := []string{
		"chacha20", "poly1305", "chacha20-poly1305",
		"ed25519", "x25519",
		"ff3", "ff3-1",
		"md5",
		"sha1", "sha-1",
		"des", "3des",
		"rc4",
	}

	set := make(map[string]struct{}, len(DisallowedAlgorithmNames))
	for _, name := range DisallowedAlgorithmNames {
		set[strings.ToLower(name)] = struct{}{}
	}

	for _, algo := range required {
		if _, ok := set[algo]; !ok {
			t.Errorf("expected %q to be in DisallowedAlgorithmNames", algo)
		}
	}
}

// TestDisallowedTLSVersions verifies that tls10 and tls11 variants are listed.
func TestDisallowedTLSVersions(t *testing.T) {
	t.Parallel()

	required := []string{"tls10", "tls1.0", "tls11", "tls1.1"}
	set := make(map[string]struct{}, len(DisallowedTLSVersions))
	for _, v := range DisallowedTLSVersions {
		set[v] = struct{}{}
	}
	for _, ver := range required {
		if _, ok := set[ver]; !ok {
			t.Errorf("expected %q to be in DisallowedTLSVersions", ver)
		}
	}
}
