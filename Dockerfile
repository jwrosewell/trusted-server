# syntax=docker/dockerfile:1.7
#
# Trusted Server appliance, one container running one process, the native
# Axum adapter. This is the first container image of Trusted Server itself.
# Every other Dockerfile in this tree belongs to an integration test fixture.
#
#   docker build -t trusted-server-appliance:dev .
#   docker compose up          # publishes the appliance on the host as 3010
#
# Three things here are not obvious, and each is explained where it happens.
# Node is needed at Rust compile time, the binary is called
# trusted-server-axum rather than trusted-server-adapter-axum, and the
# runtime stage is Debian slim rather than distroless.
#
# Configuration is supplied the way the Axum adapter documents it, as
# environment variables carrying the config store and the secret store values
# (docs/guide/getting-started.md, the Axum dev server option). compose passes
# them with env_file. Nothing in this image translates a configuration file
# into environment variables.

# Pinned to the repository's own pins so the image cannot drift from a host
# build. Rust from rust-toolchain.toml, Node from .tool-versions. Both bases
# are the same Debian release, so the glibc the binary is linked against is
# the glibc it runs on.
ARG RUST_VERSION=1.95.0
ARG NODE_VERSION=24.12.0
ARG DEBIAN_RELEASE=trixie

# ---------------------------------------------------------------------------
# Stage: node, the exact Node the repository pins.
#
# From the official image rather than a distribution package or an installer
# script, so the version is the pinned one and not whatever the apt
# repository holds this week.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS node

# ---------------------------------------------------------------------------
# Stage: builder, Rust and Node in the same stage, because the Rust build
# needs Node.
#
# crates/trusted-server-js/build.rs runs `npm ci` and `npm run build` during
# `cargo build`, then asserts it found at least one `tsjs-*.js` bundle. Those
# bundles live in crates/trusted-server-js/dist, which is gitignored, so a
# clean checkout has nothing to fall back on. No Node means the Rust build
# fails on that assert rather than warning.
#
# A consequence worth knowing is that this Rust build is not hermetic. It
# reaches the npm registry during compilation, and github.com for the EdgeZero
# git dependencies named in Cargo.toml and locked in Cargo.lock.
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS builder

# The official Node layout is one binary plus /usr/local/lib/node_modules.
# npm's launcher is recreated as a symlink rather than copied across, because
# a symlink copied between stages is not reliably still a symlink.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN set -eux; \
    ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm; \
    ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx; \
    node --version; \
    npm --version

# rust-toolchain.toml pins the channel and also asks for wasm32-wasip1 and
# wasm32-unknown-unknown. This image builds the native adapter, so those two
# targets are tens of megabytes of download for nothing. RUSTUP_TOOLCHAIN
# outranks the toolchain file in rustup's precedence and names the same
# version, so the pin is honored and the wasm downloads are skipped.
ARG RUST_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

WORKDIR /src
COPY . .

# One RUN, because target/ is a cache mount and therefore does not survive
# into a layer, so the binary has to be copied out before the mount
# disappears.
#
# `--package trusted-server-adapter-axum` is the `build-axum` alias from
# .cargo/config.toml, plus --release for an appliance and --locked so the
# committed Cargo.lock is used exactly. A bare `cargo build` at the workspace
# root fails, because default-members is the Fastly adapter and its target is
# wasm32-wasip1.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/root/.npm,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    cargo build --locked --release --package trusted-server-adapter-axum; \
    mkdir -p /out; \
    cp target/release/trusted-server-axum /out/trusted-server-axum; \
    strip /out/trusted-server-axum

# ---------------------------------------------------------------------------
# Stage: runtime.
#
# Debian slim rather than distroless, because the health check below runs
# curl and an operator's first debugging move is a shell. The binary is
# ordinary glibc-dynamic, so a deployment that wants distroless can switch
# this stage to gcr.io/distroless/cc and drop the health check without
# touching the builder.
#
# Runtime packages, each with a reason:
#   ca-certificates, because the providers that call cloud endpoints do so
#     over HTTPS, and rustls reads the OS trust store.
#   curl, for the HEALTHCHECK and for an operator debugging a container.
#
# No detection data files. Every provider in this tree calls a service, so
# there is no data file to license, download or update in this image.
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS runtime

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl; \
    rm -rf /var/lib/apt/lists/*

# The binary is `trusted-server-axum`. The crate is
# trusted-server-adapter-axum and its [[bin]] name is not, and reaching for
# the crate name here is the mistake this comment exists to prevent.
COPY --from=builder /out/trusted-server-axum /usr/local/bin/trusted-server-axum
RUN chmod +x /usr/local/bin/trusted-server-axum

# The port the process binds. The adapter reads PORT and exits non-zero on a
# value it cannot parse, so this is the adapter's own mechanism, unchanged.
ENV PORT=8787

# The bind host. The adapter resolves it through EdgeZero from
# EDGEZERO__ADAPTER__HOST and falls back to loopback, which inside a container
# is reachable from nowhere, because a published port forwards to the
# container's external address rather than to its loopback.
ENV EDGEZERO__ADAPTER__HOST=0.0.0.0

# The durable key-value store, which holds the Edge Cookie identity graph and
# withdrawal state. The adapter opens it before serving and answers every
# route with the startup error when it cannot, so the directory is a volume,
# writable by the process and kept across container replacements.
ENV EDGEZERO__STORES__KV__TRUSTED_SERVER_KV__PATH=/var/lib/trusted-server/trusted_server_kv.redb

# Non-root. The port is above 1024, so nothing here needs privilege.
RUN set -eux; \
    useradd --create-home --shell /usr/sbin/nologin --uid 10001 appliance; \
    mkdir -p /var/lib/trusted-server; \
    chown appliance:appliance /var/lib/trusted-server
VOLUME ["/var/lib/trusted-server"]
USER appliance
WORKDIR /home/appliance

EXPOSE 8787

# `/health` rather than `/`. The route returns a static 200 without touching
# application state, so it reports on this process only. `/` would go through
# the publisher fallback to the origin, which would mark the appliance
# unhealthy whenever the origin was down, the wrong container blamed for the
# wrong fault. Credentials are only demanded for a path the configuration
# declares a handler for, so the probe needs none.
#
# The probe uses container loopback, which a process bound to 0.0.0.0 also
# answers on.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/trusted-server-axum"]
