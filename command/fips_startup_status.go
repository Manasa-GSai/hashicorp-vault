// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package command — fips_startup_status.go
//
// This file provides structured FIPS-path startup reporting for Vault.  At
// process boot, collectFIPSPathStartupStatus gathers:
//
//   - Whether VAULT_FIPS_PATH enforcement is active and the raw activation
//     value (empty string when unset, never the full environment).
//   - The Go runtime crypto/fips140 module status (enabled/disabled/unavailable)
//     when the binary was built with Go 1.24+.
//   - Go version and build provenance identifiers available from runtime metadata.
//
// logFIPSPathStartupStatus emits the collected status as structured log fields
// at INFO level when enforcement is active or at DEBUG level otherwise.
//
// NON-VALIDATION BOUNDARY STATEMENT
//   Startup status "enabled" means VAULT_FIPS_PATH enforcement gates are
//   active.  It does NOT assert that Vault Community is a CMVP-validated or
//   FIPS 140-3 certified cryptographic module.  See FIPS-140-3-COMPLIANCE.md.
//
// REDACTION REQUIREMENTS
//   The log fields emitted by this file must NEVER include:
//     - Tokens, bearer credentials, API keys, or IAM secrets
//     - Seal unseal keys, private keys, or key material
//     - Listener TLS certificate contents
//     - Full HCL configuration dumps or sensitive environment values
//   The status field only records the VAULT_FIPS_PATH _activation_ value
//   ("1", "true", or "enabled") — never the full environment.

package command

import (
	"os"
	"runtime"
	runtimedebug "runtime/debug"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/internalshared/fipspath"
)

// FIPSPathStartupStatus holds the FIPS-path runtime posture observed at
// process startup.  All fields are safe to log — they contain no secret
// material, key data, tokens, credentials, or sensitive configuration.
type FIPSPathStartupStatus struct {
	// EnforcementActive is true when VAULT_FIPS_PATH resolves to an enabling
	// value ("1", "true", or "enabled").
	EnforcementActive bool

	// EnforcementValue is the raw VAULT_FIPS_PATH value.  It is recorded only
	// when it is one of the documented enabling strings so that the log entry
	// does not capture arbitrary operator-controlled env var content.
	// Set to empty string when VAULT_FIPS_PATH is unset or non-enabling.
	EnforcementValue string

	// GoRuntimeFIPS140Enabled reports whether crypto/fips140.Enabled() returned
	// true.  Only meaningful when GoRuntimeFIPS140Status == "enabled".
	GoRuntimeFIPS140Enabled bool

	// GoRuntimeFIPS140Status is "enabled", "disabled", or
	// "unavailable: requires Go 1.24+" depending on build/runtime support.
	GoRuntimeFIPS140Status string

	// GoVersion is the Go version string from runtime.Version().
	GoVersion string

	// VCSRevision is the short VCS commit from build info when available.
	VCSRevision string

	// GolangFIPSGoVersion is the golang-fips/go version embedded via the
	// GOLANG_FIPS_GO_VERSION linker flag during the FIPS-path build, or
	// "not-set" when the binary was built without that flag.
	GolangFIPSGoVersion string

	// BuildTimestamp is the build timestamp embedded via BUILD_TIMESTAMP linker
	// flag during the FIPS-path build, or "not-set" when absent.
	BuildTimestamp string
}

// fipsGolangFIPSGoVersion and fipsBuildTimestamp are linker-injectable build
// variables for the golang-fips/go toolchain and build timestamp.  They are
// set during the FIPS-path build via:
//
//	-X github.com/hashicorp/vault/command.fipsGolangFIPSGoVersion=<version>
//	-X github.com/hashicorp/vault/command.fipsBuildTimestamp=<timestamp>
//
// In standard CE builds these remain empty strings, which is reflected as
// "not-set" in the startup status log.
var (
	fipsGolangFIPSGoVersion = ""
	fipsBuildTimestamp      = ""
)

// collectFIPSPathStartupStatus collects the FIPS-path runtime posture.
// It is deterministic: the same environment always produces the same struct.
// It never makes network calls, reads files, or blocks.
func collectFIPSPathStartupStatus() FIPSPathStartupStatus {
	rawEnvVal := os.Getenv("VAULT_FIPS_PATH")
	active := fipspath.IsEnabled(rawEnvVal)

	// Only record the activation value when it is one of the explicit enabling
	// strings — never record arbitrary env var content.
	var recordedValue string
	if active {
		recordedValue = rawEnvVal
	}

	fips140Enabled, fips140Status := fipspath.GoRuntimeFIPS140Enabled()

	goVer := runtime.Version()

	// Extract VCS revision from build info — this is the binary's commit SHA
	// and contains no secret material.
	vcsRevision := "unknown"
	if info, ok := runtimedebug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 8 {
				vcsRevision = s.Value[:8] // short SHA only
				break
			}
		}
	}

	golangFIPSVer := fipsGolangFIPSGoVersion
	if golangFIPSVer == "" {
		golangFIPSVer = "not-set"
	}

	buildTS := fipsBuildTimestamp
	if buildTS == "" {
		buildTS = "not-set"
	}

	return FIPSPathStartupStatus{
		EnforcementActive:       active,
		EnforcementValue:        recordedValue,
		GoRuntimeFIPS140Enabled: fips140Enabled,
		GoRuntimeFIPS140Status:  fips140Status,
		GoVersion:               goVer,
		VCSRevision:             vcsRevision,
		GolangFIPSGoVersion:     golangFIPSVer,
		BuildTimestamp:          buildTS,
	}
}

// logFIPSPathStartupStatus logs the FIPS-path posture to the provided logger.
//
// Log levels:
//   - INFO  when VAULT_FIPS_PATH enforcement is active.
//   - DEBUG when VAULT_FIPS_PATH is unset or not active.
//
// An additional WARN is emitted when enforcement is active but the Go runtime
// FIPS 140 module status is "disabled" or "unavailable" — this indicates that
// the crypto/fips140 layer is not confirming FIPS-only mode.
//
// The log message never asserts FIPS validation or CMVP certification status.
func logFIPSPathStartupStatus(logger hclog.Logger, s FIPSPathStartupStatus) {
	fields := []interface{}{
		"enforcement_active", s.EnforcementActive,
		"go_version", s.GoVersion,
		"go_runtime_fips140_status", s.GoRuntimeFIPS140Status,
		"golang_fips_go_version", s.GolangFIPSGoVersion,
		"build_timestamp", s.BuildTimestamp,
		"vcs_revision", s.VCSRevision,
	}

	if s.EnforcementActive {
		fields = append(fields, "enforcement_value", s.EnforcementValue)
		logger.Info(
			"FIPS-path enforcement is active: VAULT_FIPS_PATH enforcement gates enabled. "+
				"This is an OSS FIPS-aligned enforcement mode, not a CMVP validation.",
			fields...,
		)

		// Warn when enforcement is active but runtime FIPS 140 is not confirmed.
		if !s.GoRuntimeFIPS140Enabled {
			logger.Warn(
				"FIPS-path enforcement is active but Go runtime crypto/fips140 module status is "+
					s.GoRuntimeFIPS140Status+
					". VAULT_FIPS_PATH enforces approved-algorithm configuration gates; it does not "+
					"enable the Go standard-library FIPS-only mode. See FIPS-140-3-COMPLIANCE.md §2a.",
				"go_runtime_fips140_status", s.GoRuntimeFIPS140Status,
				"golang_fips_go_version", s.GolangFIPSGoVersion,
			)
		}
	} else {
		logger.Debug("FIPS-path enforcement is not active: VAULT_FIPS_PATH unset or non-enabling",
			fields...)
	}
}
