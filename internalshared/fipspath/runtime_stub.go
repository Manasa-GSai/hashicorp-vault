// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build !go1.24

package fipspath

// GoRuntimeFIPS140Enabled is the stub implementation for Go versions before
// 1.24, which do not expose crypto/fips140.Enabled().  It always returns
// (false, "unavailable") — the caller must treat this as an unknown state
// rather than as a confirmation that FIPS mode is disabled.
//
// To obtain a definitive runtime status, rebuild with Go 1.24 or later.
func GoRuntimeFIPS140Enabled() (bool, string) {
	return false, "unavailable: requires Go 1.24+"
}
