// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build go1.24

package fipspath

import "crypto/fips140"

// GoRuntimeFIPS140Enabled reports whether the Go runtime has FIPS 140-only
// mode active according to the crypto/fips140 package (Go 1.24+).
//
// This is distinct from VAULT_FIPS_PATH enforcement: the runtime flag reflects
// whether the Go standard-library crypto packages are restricted to FIPS-approved
// algorithms at the language level, not whether Vault's configuration surfaces
// have been validated.
//
// Returns (enabled bool, status string) where status is one of:
//   - "enabled"  — crypto/fips140 reports FIPS-only mode active
//   - "disabled" — crypto/fips140 reports FIPS-only mode not active
func GoRuntimeFIPS140Enabled() (bool, string) {
	if fips140.Enabled() {
		return true, "enabled"
	}
	return false, "disabled"
}
