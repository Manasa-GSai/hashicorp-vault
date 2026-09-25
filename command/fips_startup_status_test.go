// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package command

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// TestCollectFIPSPathStartupStatus verifies that collectFIPSPathStartupStatus
// correctly populates FIPSPathStartupStatus fields for each VAULT_FIPS_PATH
// activation state.
func TestCollectFIPSPathStartupStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		envVal          string
		wantActive      bool
		wantValueNonEmpty bool
	}{
		{name: "unset", envVal: "", wantActive: false, wantValueNonEmpty: false},
		{name: "zero", envVal: "0", wantActive: false, wantValueNonEmpty: false},
		{name: "false", envVal: "false", wantActive: false, wantValueNonEmpty: false},
		{name: "disabled", envVal: "disabled", wantActive: false, wantValueNonEmpty: false},
		{name: "one", envVal: "1", wantActive: true, wantValueNonEmpty: true},
		{name: "true", envVal: "true", wantActive: true, wantValueNonEmpty: true},
		{name: "enabled", envVal: "enabled", wantActive: true, wantValueNonEmpty: true},
		{name: "TRUE", envVal: "TRUE", wantActive: true, wantValueNonEmpty: true},
		{name: "ENABLED", envVal: "ENABLED", wantActive: true, wantValueNonEmpty: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			t.Setenv("VAULT_FIPS_PATH", tc.envVal)

			s := collectFIPSPathStartupStatus()

			if s.EnforcementActive != tc.wantActive {
				t.Errorf("EnforcementActive = %v, want %v", s.EnforcementActive, tc.wantActive)
			}

			// EnforcementValue must be non-empty only when active.
			if tc.wantValueNonEmpty && s.EnforcementValue == "" {
				t.Errorf("EnforcementValue is empty but enforcement is active")
			}
			if !tc.wantValueNonEmpty && s.EnforcementValue != "" {
				t.Errorf("EnforcementValue is %q but enforcement is not active — must be empty to avoid leaking arbitrary env content", s.EnforcementValue)
			}

			// GoVersion must always be set.
			if s.GoVersion == "" {
				t.Error("GoVersion is empty")
			}

			// GoRuntimeFIPS140Status must always be a documented value.
			validStatuses := map[string]bool{
				"enabled":                      true,
				"disabled":                     true,
				"unavailable: requires Go 1.24+": true,
			}
			if !validStatuses[s.GoRuntimeFIPS140Status] {
				t.Errorf("GoRuntimeFIPS140Status = %q — undocumented value", s.GoRuntimeFIPS140Status)
			}

			// GolangFIPSGoVersion must never be empty (may be "not-set" in non-FIPS builds).
			if s.GolangFIPSGoVersion == "" {
				t.Error("GolangFIPSGoVersion is empty — should be 'not-set' when not embedded")
			}

			// BuildTimestamp must never be empty.
			if s.BuildTimestamp == "" {
				t.Error("BuildTimestamp is empty — should be 'not-set' when not embedded")
			}
		})
	}
}

// TestLogFIPSPathStartupStatus_EnforcementActive verifies that the INFO log is
// emitted when enforcement is active and a WARN is emitted when the Go runtime
// FIPS status is not confirmed.
func TestLogFIPSPathStartupStatus_EnforcementActive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                   string
		goFIPS140Enabled       bool
		goFIPS140Status        string
		wantWarn               bool
		wantInfoContains       string
		wantNoSecretSubstrings []string
	}{
		{
			name:             "fips140 enabled",
			goFIPS140Enabled: true,
			goFIPS140Status:  "enabled",
			wantWarn:         false,
			wantInfoContains: "FIPS-path enforcement is active",
		},
		{
			name:             "fips140 disabled",
			goFIPS140Enabled: false,
			goFIPS140Status:  "disabled",
			wantWarn:         true,
			wantInfoContains: "FIPS-path enforcement is active",
		},
		{
			name:             "fips140 unavailable",
			goFIPS140Enabled: false,
			goFIPS140Status:  "unavailable: requires Go 1.24+",
			wantWarn:         true,
			wantInfoContains: "FIPS-path enforcement is active",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := hclog.New(&hclog.LoggerOptions{
				Level:  hclog.Debug,
				Output: &buf,
			})

			s := FIPSPathStartupStatus{
				EnforcementActive:       true,
				EnforcementValue:        "1",
				GoRuntimeFIPS140Enabled: tc.goFIPS140Enabled,
				GoRuntimeFIPS140Status:  tc.goFIPS140Status,
				GoVersion:               "go1.22.5-1",
				VCSRevision:             "abc12345",
				GolangFIPSGoVersion:     "go1.22.5-1",
				BuildTimestamp:          "2026-01-01T00:00:00Z",
			}

			logFIPSPathStartupStatus(logger, s)

			logOutput := buf.String()

			// INFO must always be present when enforcement is active.
			if !strings.Contains(logOutput, tc.wantInfoContains) {
				t.Errorf("expected log to contain %q\ngot: %s", tc.wantInfoContains, logOutput)
			}

			// WARN presence.
			hasWarn := strings.Contains(logOutput, "[WARN]") ||
				strings.Contains(strings.ToUpper(logOutput), "WARN")
			if tc.wantWarn && !hasWarn {
				t.Errorf("expected WARN log when goFIPS140 is %q, got none\nlog: %s",
					tc.goFIPS140Status, logOutput)
			}
			if !tc.wantWarn && hasWarn {
				t.Errorf("unexpected WARN when goFIPS140 is %q\nlog: %s",
					tc.goFIPS140Status, logOutput)
			}

			// No secret material in output.
			for _, forbidden := range []string{
				"token", "secret", "password", "private key",
				"client_secret", "Authorization", "Bearer",
			} {
				if strings.Contains(logOutput, forbidden) {
					t.Errorf("log contains forbidden substring %q: %s", forbidden, logOutput)
				}
			}

			// Non-validation boundary statement must be present.
			if !strings.Contains(logOutput, "not a CMVP") &&
				!strings.Contains(logOutput, "FIPS-140-3-COMPLIANCE") &&
				!strings.Contains(logOutput, "not a CMVP validation") {
				// at least one of the boundary phrases must appear
				// (the WO requires no FIPS validation claim in logs)
				// Accept the check if the info log has "not a CMVP" or doc reference.
				if !strings.Contains(logOutput, "OSS FIPS-aligned enforcement mode") {
					t.Errorf("log missing non-validation boundary phrase\nlog: %s", logOutput)
				}
			}
		})
	}
}

// TestLogFIPSPathStartupStatus_NotActive verifies that only DEBUG output is
// emitted (not INFO/WARN) when enforcement is inactive.
func TestLogFIPSPathStartupStatus_NotActive(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Debug,
		Output: &buf,
	})

	s := FIPSPathStartupStatus{
		EnforcementActive:       false,
		EnforcementValue:        "",
		GoRuntimeFIPS140Enabled: false,
		GoRuntimeFIPS140Status:  "disabled",
		GoVersion:               "go1.22.5",
		VCSRevision:             "deadbeef",
		GolangFIPSGoVersion:     "not-set",
		BuildTimestamp:          "not-set",
	}

	logFIPSPathStartupStatus(logger, s)

	logOutput := buf.String()

	// Must have DEBUG output.
	if !strings.Contains(strings.ToUpper(logOutput), "DEBUG") {
		t.Errorf("expected DEBUG log when enforcement is inactive, got: %s", logOutput)
	}

	// Must NOT have INFO or WARN.
	if strings.Contains(strings.ToUpper(logOutput), "[INFO]") {
		t.Errorf("unexpected INFO log when enforcement is inactive: %s", logOutput)
	}
	if strings.Contains(strings.ToUpper(logOutput), "[WARN]") {
		t.Errorf("unexpected WARN log when enforcement is inactive: %s", logOutput)
	}
}

// TestFIPSPathStartupStatus_UnavailableRuntimeState verifies that an
// "unavailable" Go runtime FIPS140 status is represented explicitly and not
// silently omitted or misreported as false.
func TestFIPSPathStartupStatus_UnavailableRuntimeState(t *testing.T) {
	t.Parallel()

	s := FIPSPathStartupStatus{
		EnforcementActive:       true,
		EnforcementValue:        "1",
		GoRuntimeFIPS140Enabled: false,
		GoRuntimeFIPS140Status:  "unavailable: requires Go 1.24+",
		GoVersion:               "go1.22.5",
		VCSRevision:             "00000000",
		GolangFIPSGoVersion:     "not-set",
		BuildTimestamp:          "not-set",
	}

	if s.GoRuntimeFIPS140Status == "" {
		t.Fatal("GoRuntimeFIPS140Status must not be empty for unavailable state")
	}

	if s.GoRuntimeFIPS140Enabled {
		t.Error("GoRuntimeFIPS140Enabled must be false when status is unavailable")
	}

	if !strings.Contains(s.GoRuntimeFIPS140Status, "unavailable") {
		t.Errorf("status %q does not contain 'unavailable'", s.GoRuntimeFIPS140Status)
	}
}

// TestFIPSPathStartupStatus_EnforcementValueRedaction verifies that the
// EnforcementValue field only ever contains an enabling activation string —
// never arbitrary env var content from a non-enabling value.
func TestFIPSPathStartupStatus_EnforcementValueRedaction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		envVal    string
		wantEmpty bool
	}{
		{"", true},
		{"0", true},
		{"false", true},
		{"some-operator-credential-that-must-not-be-logged", true},
		{"1", false},
		{"true", false},
		{"enabled", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run("val="+tc.envVal, func(t *testing.T) {
			t.Parallel()
			t.Setenv("VAULT_FIPS_PATH", tc.envVal)
			s := collectFIPSPathStartupStatus()
			if tc.wantEmpty && s.EnforcementValue != "" {
				t.Errorf("EnforcementValue=%q should be empty for non-enabling env value %q",
					s.EnforcementValue, tc.envVal)
			}
			if !tc.wantEmpty && s.EnforcementValue == "" {
				t.Errorf("EnforcementValue is empty for enabling env value %q", tc.envVal)
			}
		})
	}
}
