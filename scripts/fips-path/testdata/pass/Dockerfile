# FIPS-path builder stage — ubuntu/focal glibc base, no Alpine or musl
# This is a minimal fixture for validator regression tests.

FROM ubuntu:focal AS fips-path-builder
RUN apt-get update -y && apt-get install -y --no-install-recommends build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/entrypoint.sh"]

FROM ubuntu:focal AS default
ENTRYPOINT ["/entrypoint.sh"]
