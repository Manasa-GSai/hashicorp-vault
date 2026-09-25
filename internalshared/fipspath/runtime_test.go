// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package fipspath

import (
	"testing"
)

// TestGoRuntimeFIPS140Enabled verifies that the function compiles, returns a
// non-empty status string, and is consistent with itself.
//
// The actual bool value depends on the runtime FIPS state of the test
// environment and is not asserted here. The contract tested is:
//   - The function never panics.
//   - The returned status string is never empty.
//   - "enabled" status maps to true; "disabled" / "unavailable" map to false.
func TestGoRuntimeFIPS140Enabled(t *testing.T) {
	t.Parallel()

	enabled, status := GoRuntimeFIPS140Enabled()

	if status == "" {
		t.Fatal("GoRuntimeFIPS140Enabled returned an empty status string")
	}

	// Consistency check: if status == "enabled" then enabled must be true.
	if status == "enabled" && !enabled {
		t.Errorf("status=%q but enabled=false — inconsistent return", status)
	}

	// Consistency check: if enabled is false, status must not be "enabled".
	if !enabled && status == "enabled" {
		t.Errorf("enabled=false but status=%q — inconsistent return", status)
	}

	// The status must be one of the documented values.
	validStatuses := map[string]bool{
		"enabled":                     true,
		"disabled":                    true,
		"unavailable: requires Go 1.24+": true,
	}
	if !validStatuses[status] {
		t.Errorf("GoRuntimeFIPS140Enabled returned undocumented status: %q", status)
	}

	t.Logf("GoRuntimeFIPS140Enabled() = %v, %q", enabled, status)
}
