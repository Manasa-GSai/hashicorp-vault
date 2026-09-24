# Copyright IBM Corp. 2016, 2026
# SPDX-License-Identifier: BUSL-1.1

## Builder
#
#  A build container used to build the Vault binary. We use focal because the
#  version of glibc is old enough for all of our supported distros for editions
#  that require CGO. This container is used in CI to build all binaries that
#  require CGO.
#
#  To run it locally, first build the builder container:
#    docker build -t builder --build-arg GO_VERSION=$(cat .go-version) .
#
#  Then build Vault using the builder container:
#    docker run -it -v $(pwd):/build -v GITHUB_TOKEN=$GITHUB_TOKEN --env GO_TAGS='ui enterprise cgo hsm venthsm' --env GOARCH=s390x --env GOOS=linux --env VERSION=1.20.0-beta1 --env VERSION_METADATA=ent.hsm --env CGO_ENABLED=1 builder make ci-build
#
#  You can also share your local Go modules with the container to avoid downloading
#  them every time:
#    docker run -it -v $(pwd):/build -v $(go env GOMODCACHE):/go-mod-cache --env GITHUB_TOKEN=$GITHUB_TOKEN --env GO_TAGS='ui enterprise cgo hsm venthsm' --env GOARCH=s390x --env GOOS=linux --env VERSION=1.20.0-beta1 --env VERSION_METADATA=ent.hsm --env GOMODCACHE=/go-mod-cache --env CGO_ENABLED=1 builder make ci-build
#
#  If you have a linux machine you can also share the tools
#    GOBIN="$(go env GOPATH)/bin" make tools
#    docker run -it -v $(pwd):/build -v $(go env GOMODCACHE):/go-mod-cache -v "$(go env GOPATH)/bin":/opt/tools/bin --env GITHUB_TOKEN=$GITHUB_TOKEN --env GO_TAGS='ui enterprise cgo hsm venthsm' --env GOARCH=s390x --env GOOS=linux --env VERSION=1.20.0-beta1 --env VERSION_METADATA=ent.hsm --env GOMODCACHE=/go-mod-cache --env CGO_ENABLED=1 builder make ci-build
FROM ubuntu:focal AS builder

# Pass in the GO_VERSION as a build-arg
ARG GO_VERSION

# Set our environment
ENV PATH="/root/go/bin:/opt/go/bin:/opt/tools/bin:$PATH"
ENV GOPRIVATE='github.com/hashicorp/*'

# Install the necessary system tooling to cross compile vault for our various
# CGO targets. Do this separately from branch specific Go and build toolchains
# so our various builder image layers can share cache.
COPY .build/system.sh .
RUN chmod +x system.sh && ./system.sh && rm -rf system.sh

# Install the correct Go toolchain
COPY .build/go.sh .
RUN chmod +x go.sh && ./go.sh && rm -rf go.sh

# Install the vault tools installer. It might be required during build if the
# pre-build tools are not mounted into the container.
COPY tools/tools.sh .
RUN chmod +x tools.sh

# Run the build
COPY .build/entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

## FIPS-Path Builder
#
#  A dedicated build stage for the OSS FIPS-path binary. Uses a glibc-compatible
#  base image (Ubuntu), installs golang-fips/go (a fork of Go that routes crypto
#  through OpenSSL), enables CGO, and installs the OpenSSL FIPS provider
#  prerequisites needed for a defensible OSS FIPS-aligned posture.
#
#  This stage does NOT replace the default builder or the standard CE build path.
#  Non-FIPS Community builds continue to use the ubuntu:focal builder stage above.
#  No Enterprise-only goboringcrypto, GOEXPERIMENT, BoringCrypto symbol checks,
#  Seal Wrap, or PKCS#11 features are added here.
#
#  To build only this stage:
#    docker build -f Dockerfile --target fips-path-builder \
#      --build-arg GO_VERSION=$(cat .go-version) \
#      --build-arg GOLANG_FIPS_VERSION=1.22.5-1 \
#      --build-arg OPENSSL_FIPS_PACKAGE=openssl \
#      -t vault-fips-path-builder:test .
#
#  To verify the resulting image:
#    docker run --rm vault-fips-path-builder:test \
#      sh -c 'go version && go env CGO_ENABLED && (ldd --version || getconf GNU_LIBC_VERSION)'

# Version pins for golang-fips/go toolchain and OpenSSL FIPS provider package.
# Expose as ARGs so downstream release automation can capture exact values for
# provenance evidence.
ARG GOLANG_FIPS_VERSION=1.22.5-1
ARG OPENSSL_FIPS_PACKAGE=openssl
ARG OPENSSL_FIPS_PACKAGE_VERSION=""

FROM ubuntu:focal AS fips-path-builder

# Inherit version ARGs declared above — must be re-declared inside the stage.
ARG GO_VERSION
ARG GOLANG_FIPS_VERSION
ARG OPENSSL_FIPS_PACKAGE
ARG OPENSSL_FIPS_PACKAGE_VERSION

# Set build environment — glibc toolchain, golang-fips/go first on PATH, CGO enabled.
ENV PATH="/usr/local/golang-fips/bin:/root/go/bin:/opt/go/bin:/opt/tools/bin:$PATH"
ENV GOPRIVATE='github.com/hashicorp/*'
ENV CGO_ENABLED=1

# Install glibc build toolchain, OpenSSL, and FIPS provider prerequisites.
# Fail closed: any missing package stops the image build with the failing command visible.
RUN set -euo pipefail && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        libssl-dev \
        ${OPENSSL_FIPS_PACKAGE} \
        pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Verify glibc is present — this will fail the build on Alpine or musl images.
RUN ldd --version 2>&1 | head -1 || getconf GNU_LIBC_VERSION

# Install golang-fips/go toolchain.
# golang-fips/go routes Go crypto operations through the system OpenSSL provider,
# enabling the glibc OpenSSL boundary for FIPS-aligned builds.
# The toolchain is placed at /usr/local/golang-fips so it does not shadow the
# standard Go binary used by the default builder stage.
RUN set -euo pipefail && \
    GOARCH=$(dpkg --print-architecture) && \
    GOLANG_FIPS_URL="https://github.com/golang-fips/go/releases/download/go${GOLANG_FIPS_VERSION}/go${GOLANG_FIPS_VERSION}.linux-${GOARCH}.tar.gz" && \
    echo "Downloading golang-fips/go ${GOLANG_FIPS_VERSION} for ${GOARCH}" && \
    curl -fsSL "${GOLANG_FIPS_URL}" -o /tmp/golang-fips.tar.gz && \
    mkdir -p /usr/local/golang-fips && \
    tar -C /usr/local/golang-fips --strip-components=1 -xzf /tmp/golang-fips.tar.gz && \
    rm -f /tmp/golang-fips.tar.gz

# Confirm golang-fips/go is selected and CGO is enabled.
RUN go version && go env CGO_ENABLED

# Install the vault tools installer (same as the default builder).
COPY tools/tools.sh .
RUN chmod +x tools.sh

# Run the build (same entrypoint as the default builder).
COPY .build/entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

#  Default
#
#  Our default conatiner image.
#
FROM alpine:3 AS default

ARG BIN_NAME
# NAME and PRODUCT_VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=vault PRODUCT_VERSION=1.2.3.
ARG NAME=vault
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH
# LICENSE_SOURCE is the path to IBM license documents, which may be architecture-specific.
ARG LICENSE_SOURCE
# LICENSE_DEST is the path where license files are installed in the container
ARG LICENSE_DEST

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Vault" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=${PRODUCT_VERSION} \
      release=${PRODUCT_REVISION} \
      revision=${PRODUCT_REVISION} \
      summary="Vault is a tool for securely accessing secrets." \
      description="Vault is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, and more. Vault provides a unified interface to any secret, while providing tight access control and recording a detailed audit log."

# Copy the license file as per Legal requirement
COPY ${LICENSE_SOURCE} ${LICENSE_DEST}

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME

# Create a non-root user to run the software.
RUN addgroup ${NAME} && adduser -S -G ${NAME} ${NAME}

# Install su-exec for exec-ing Vault when the container is run with a privileged
# user. Install dumb-init to use as the entrypoint PID 1 to handle reaping
# zombie processes. Update our timezone database.
RUN apk update && apk add --upgrade --no-cache su-exec dumb-init tzdata

COPY dist/$TARGETOS/$TARGETARCH/${BIN_NAME} /bin/${BIN_NAME}

# /vault/logs is made available to use as a location to store audit logs, if
# desired; /vault/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /vault/config as
# the configuration directory so you can add additional config files in that
# location.
RUN mkdir -p /vault/logs && \
    mkdir -p /vault/file && \
    mkdir -p /vault/config && \
    chown -R ${NAME}:${NAME} /vault

# Expose the logs directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/logs

# Expose the file directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/file

# 8200/tcp is the primary interface that applications use to interact with
# Vault.
EXPOSE 8200

# The entry point script uses dumb-init as the top-level process to reap any
# zombie processes created by Vault sub-processes.
#
# For production derivatives of this container, you should add the IPC_LOCK
# capability so that Vault can mlock memory.
COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

# Use the Vault user as the default user for starting this container.
USER ${NAME}

# # By default you'll get a single-node development server that stores everything
# # in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev"]


#  UBI
#
#  Our UBI container image
#
FROM registry.access.redhat.com/ubi10/ubi-minimal AS ubi

ARG BIN_NAME
# NAME and PRODUCT_VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=vault PRODUCT_VERSION=1.2.3.
ARG NAME=vault
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH
# LICENSE_SOURCE is the path to IBM license documents, which may be architecture-specific.
ARG LICENSE_SOURCE
# LICENSE_DEST is the path where license files are installed in the container
ARG LICENSE_DEST

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Vault" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=${PRODUCT_VERSION} \
      release=${PRODUCT_REVISION} \
      revision=${PRODUCT_REVISION} \
      summary="Vault is a tool for securely accessing secrets." \
      description="Vault is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, and more. Vault provides a unified interface to any secret, while providing tight access control and recording a detailed audit log."

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME

# Copy the license file as per Legal requirement
COPY ${LICENSE_SOURCE} ${LICENSE_DEST}/

# We must have a copy of the license in this directory to comply with the HasLicense Redhat requirement
# Note the trailing slash on the first argument -- plain files meet the requirement but directories do not.
COPY ${LICENSE_SOURCE}/ /licenses/

# Update our timezone database. Install shadow-utils for creating our vault user
# and group. Install util-linux for su for exec when the container is run as root.
# Add tar as tar as it is necessary for some of our testing.
RUN microdnf update -y --nobest && \
  microdnf install -y tzdata shadow-utils util-linux tar && \
  rm -rf /var/cache/yum && \
  microdnf clean all

# Create a non-root user to run the software.
RUN groupadd --gid 1000 vault && \
    adduser --uid 100 --system -g vault vault && \
    usermod -a -G root vault

COPY dist/$TARGETOS/$TARGETARCH/${BIN_NAME} /bin/${BIN_NAME}

# /vault/logs is made available to use as a location to store audit logs, if
# desired; /vault/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /vault/config as
# the configuration directory so you can add additional config files in that
# location.
ENV HOME=/home/vault
RUN mkdir -p /vault/logs && \
    mkdir -p /vault/file && \
    mkdir -p /vault/config && \
    mkdir -p $HOME && \
    chown -R vault /vault && chown -R vault $HOME && \
    chgrp -R 0 $HOME && chmod -R g+rwX $HOME && \
    chgrp -R 0 /vault && chmod -R g+rwX /vault

# Expose the logs directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/logs

# Expose the file directory as a volume since there's potentially long-running
# state in there
VOLUME /vault/file

# 8200/tcp is the primary interface that applications use to interact with
# Vault.
EXPOSE 8200

# The entry point script uses dumb-init as the top-level process to reap any
# zombie processes created by Vault sub-processes.
#
# For production derivatives of this container, you should add the IPC_LOCK
# capability so that Vault can mlock memory.
COPY .release/docker/ubi-docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

# Use the Vault user as the default user for starting this container.
USER ${NAME}

# # By default you'll get a single-node development server that stores everything
# # in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev"]
