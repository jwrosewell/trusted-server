# syntax=docker/dockerfile:1.7
#
# Trusted Server appliance — one container, one process, running the native
# Axum adapter. This is the first container of Trusted Server itself; every
# other Dockerfile in this tree belongs to an integration-test fixture.
#
#   docker build -t trusted-server-appliance:dev .
#   docker compose up          # publishes the appliance on the host as 3010
#
# Three things here are not obvious, and each is explained where it happens:
# Node is needed at Rust compile time, the binary is called
# trusted-server-axum and not trusted-server-adapter-axum, and the runtime
# stage is Debian slim rather than distroless.
#
# Configuration is supplied the way the Axum adapter already documents it, as
# environment variables (docs/guide/getting-started.md, "Option B — Axum dev
# server"). compose passes them with env_file. Nothing in this image
# translates a configuration file into environment variables: a publisher does
# expect to mount a file, but that belongs in the adapter, not in a wrapper
# script here. See "Configuration, the production shape" in
# .claude/findings-C.md.

# Pinned to the repository's own pins so the image cannot drift from a host
# build. Rust from rust-toolchain.toml, Node from .tool-versions. Both bases
# are the same Debian release, so the glibc the binary is linked against is
# the glibc it runs on.
ARG RUST_VERSION=1.95.0
ARG NODE_VERSION=24.12.0
ARG DEBIAN_RELEASE=trixie

# ---------------------------------------------------------------------------
# Stage: node — the exact Node the repository pins.
#
# From the official image rather than a distribution package or an installer
# script, so the version is 24.12.0 and not whatever the apt repository holds
# this week.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS node

# ---------------------------------------------------------------------------
# Stage: builder — Rust and Node in the same stage, because the Rust build
# genuinely needs Node.
#
# crates/trusted-server-js/build.rs runs `npm ci` and `npm run build` during
# `cargo build` (lines 48-85), then asserts it found at least one `tsjs-*.js`
# bundle (lines 112-116). Those bundles live in crates/trusted-server-js/dist,
# which is gitignored, so a clean checkout has nothing to fall back on. No
# Node means the Rust build fails on that assert, not a warning.
#
# A consequence worth knowing: this Rust build is not hermetic. It reaches the
# npm registry during compilation, and github.com for the six EdgeZero git
# dependencies (Cargo.toml lines 57-62, locked to rev 5c9886e in Cargo.lock).
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

# rust-toolchain.toml pins channel 1.95.0 and also asks for wasm32-wasip1 and
# wasm32-unknown-unknown. This image builds the native adapter, so those two
# targets are tens of megabytes of download for nothing. RUSTUP_TOOLCHAIN
# outranks the toolchain file in rustup's precedence and names the same
# version, so the pin is honoured and the wasm downloads are skipped.
ARG RUST_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

WORKDIR /src
COPY . .

# One RUN, because target/ is a cache mount and therefore does not survive
# into a layer: the binary has to be copied out before the mount disappears.
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
# Debian slim, not distroless, for one reason: the entry point is a shell
# script. It carries the single-instance refusal, which is the packaging
# decision that this appliance keeps identity in memory and so must not be
# scaled silently. Nothing else in this stage needs a shell, and the binary is
# ordinary glibc-dynamic, so if that refusal ever moves into the adapter where
# it arguably belongs, this stage becomes gcr.io/distroless/cc unchanged.
#
# Runtime packages, each earning its place:
#   ca-certificates — device detection and IP intelligence call cloud
#     endpoints over HTTPS. reqwest is built with rustls-tls, but
#     rustls-native-certs is in Cargo.lock, so the OS trust store is read.
#   curl — the HEALTHCHECK, and an operator's first debugging move.
# No detection data files: both capabilities call the cloud, so there is no
# multi-gigabyte data file, no licence-keyed download and no update service in
# this image. Nothing in the build asked for a local data file.
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
COPY .claude/docker/entrypoint.sh /usr/local/bin/appliance-entrypoint
RUN chmod +x /usr/local/bin/appliance-entrypoint /usr/local/bin/trusted-server-axum

# The port the process binds. main.rs:36-45 reads PORT and exits non-zero on a
# value it cannot parse, so this is the adapter's own mechanism, unchanged.
# Note what it does NOT control: the bind host. main.rs:14-19 hardcodes
# 127.0.0.1 on both paths, so today this port is reachable only from inside
# the container. compose still maps it to the host, so publishing starts
# working the moment the adapter can bind 0.0.0.0. The one-line change that
# needs is written up in .claude/findings-C.md, Discovery 1.
ENV PORT=8787

# Loud by default about being a single instance. See the entry point.
ENV TS_APPLIANCE_REPLICAS=1

# Non-root. The port is above 1024, so nothing here needs privilege.
RUN set -eux; \
    useradd --create-home --shell /usr/sbin/nologin --uid 10001 appliance
USER appliance
WORKDIR /home/appliance

EXPOSE 8787

# `/health` rather than `/`. The route is registered at
# crates/trusted-server-adapter-axum/src/app.rs:611 and returns a static 200
# "ok" without touching application state, so it reports on this process only.
# `/` would go through the publisher fallback to the origin, which would mark
# the appliance unhealthy whenever the origin was down: the wrong container
# blamed for the wrong fault. It is also ungated by default:
# crates/trusted-server-core/src/auth.rs:89-96 only demands credentials for a
# path the config declares a handler for.
#
# The probe uses container loopback, which is where the process listens today
# anyway. It stays correct after the bind fix, because a process bound to
# 0.0.0.0 also answers on 127.0.0.1.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/appliance-entrypoint"]
