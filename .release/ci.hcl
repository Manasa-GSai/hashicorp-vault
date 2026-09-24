# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1

schema = "2"

project "vault" {
  team = "vault"
  slack {
    notification_channel = "C09LD1XT5MX" // #feed-vault-releases
  }
  github {
    organization = "hashicorp"
    repository = "vault"
    release_branches = [
      "main",
      "release/**",
    ]
  }
}

event "merge" {
  // "entrypoint" to use if build is not run automatically
  // i.e. send "merge" complete signal to orchestrator to trigger build
}

event "build" {
  depends = ["merge"]
  action "build" {
    organization = "hashicorp"
    repository = "vault"
    workflow = "build"
  }
}

event "prepare" {
  depends = ["build"]
  action "prepare" {
    organization = "hashicorp"
    repository   = "crt-workflows-common"
    workflow     = "prepare"
    depends      = ["build"]
  }

  notification {
    on = "fail"
  }
}

event "enos-release-testing-oss" {
  depends = ["prepare"]
  action "enos-release-testing-oss" {
    organization = "hashicorp"
    repository = "vault"
    workflow = "enos-release-testing-oss"
  }

  notification {
    on = "fail"
  }
}

## These events are publish and post-publish events and should be added to the end of the file
## after the verify event stanza.

event "trigger-staging" {
  // This event is dispatched by the bob trigger-promotion command
  // and is required - do not delete.
}

event "promote-staging" {
  depends = ["trigger-staging"]
  action "promote-staging" {
    organization = "hashicorp"
    repository = "crt-workflows-common"
    workflow = "promote-staging"
    config = "release-metadata.hcl"
  }

  notification {
    on = "always"
  }
}

event "trigger-production" {
  // This event is dispatched by the bob trigger-promotion command
  // and is required - do not delete.
}

event "promote-production" {
  depends = ["trigger-production"]
  action "promote-production" {
    organization = "hashicorp"
    repository = "crt-workflows-common"
    workflow = "promote-production"
  }

  promotion-events {
    update-ironbank = true
    bump-version-patch = true
    post-publish-website = true
  }

  notification {
    on = "always"
  }
}

event "crt-generate-sbom" {
  depends = ["promote-production"]
  action "crt-generate-sbom" {
	organization = "hashicorp"
	repository = "security-generate-release-sbom"
	workflow = "crt-generate-sbom"
  }

  notification {
	on = "fail"
  }
}

# ---------------------------------------------------------------------------
# FIPS-path artifact job
#
# This release pipeline entry records that a FIPS-path OSS artifact lane
# exists for the Community edition.  It is deliberately separate from the
# standard CE artifact path so non-FIPS artifacts continue through the
# existing standard Go build path with cgo-enabled: 0.
#
# Fields captured for COMPLIANCE-EVIDENCE.md §2 / §4:
#   vault_version, golang_fips_go_version, openssl_fips_provider_package_version,
#   base_image_digest, sbom_path, provenance_path.
#
# COMPLIANCE NOTE: This lane produces an OSS FIPS-aligned artifact.
# Vault Community internal cryptographic operations are not performed in a
# CMVP-validated module.  See FIPS-140-3-COMPLIANCE.md for the authoritative
# OSS posture boundary.
# ---------------------------------------------------------------------------

event "build-fips-path" {
  depends = ["build"]
  action "build-fips-path" {
    organization = "hashicorp"
    repository   = "vault"
    workflow     = "build-artifacts-ce.yml"
    # The workflow must be invoked with fips-path: "true" to activate the
    # separate build lane in .github/actions/build-vault/action.yml.
    # Standard Community artifacts are not affected.
    inputs = {
      "fips-path" = "true"
    }
  }

  notification {
    on = "fail"
  }
}
