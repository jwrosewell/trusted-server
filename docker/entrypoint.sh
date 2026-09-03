#!/bin/sh
# Entry point for the Trusted Server appliance container.
#
# This script does exactly one thing before handing over: it refuses to start
# more than one instance. It deliberately does not translate, rewrite or
# generate configuration. The Axum adapter takes its settings from environment
# variables, which is what compose passes it, and if a publisher should be able
# to mount a configuration file then the adapter should read a file. A wrapper
# script converting one into the other would be a workaround living in
# packaging for a gap that belongs in the adapter.
#
# Everything after the guard is `exec`, so the appliance is PID 1 and receives
# SIGTERM from `docker stop` directly.

set -eu

log() {
    # Matched to the shape the Rust side emits (simple_logger), so an operator
    # reading `docker logs` sees one consistent stream rather than two formats.
    printf '%s %-5s [appliance-entrypoint] %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" >&2
}

replicas="${TS_APPLIANCE_REPLICAS:-1}"

# A replica count that is not a number is a mistake worth stopping for. Left
# alone, `[ "abc" -gt 1 ]` is a shell error under `set -e` on some shells and a
# silent false on others, and either way nobody finds out.
#
# There is deliberately no empty-string branch here: `${TS_APPLIANCE_REPLICAS:-1}`
# above substitutes the default when the variable is unset *or* empty, so an
# empty value has already become 1 by this point and a branch for it would be
# unreachable. Verified by running this script with TS_APPLIANCE_REPLICAS= set.
case "${replicas}" in
    *[!0-9]*)
        log ERROR "TS_APPLIANCE_REPLICAS='${replicas}' is not a whole number."
        log ERROR "Refusing to start. Set it to the number of instances you intend to run."
        exit 1
        ;;
esac

if [ "${replicas}" -gt 1 ]; then
    log ERROR "TS_APPLIANCE_REPLICAS=${replicas}. Refusing to start."
    log ERROR "This appliance cannot be replicated. It is not a configuration"
    log ERROR "choice you can override here, it is what the Axum adapter is:"
    log ERROR "  crates/trusted-server-adapter-axum/src/platform.rs:570-572 wires"
    log ERROR "  UnavailableKvStore as the KV store, so there is no shared store to"
    log ERROR "  put identity or consent state in. Edge Cookie identity therefore"
    log ERROR "  lives in this process's memory and nowhere else."
    log ERROR "Two instances means a visitor's identity depends on which one"
    log ERROR "answered, and a consent withdrawal reaches one instance and not the"
    log ERROR "other. Both fail quietly, which is why this is a refusal and not a"
    log ERROR "warning: a warning in a scaled deployment is a warning nobody reads"
    log ERROR "until a regulator asks why a withdrawal did not take effect."
    log ERROR "To run more than one instance the adapter needs a real shared KV"
    log ERROR "store. That is a Trusted Server change, not a packaging one."
    exit 1
fi

# Said on every start, not only on the failure path, because the quiet
# assumption this is guarding against is "containers are interchangeable".
# Somebody reading `docker logs` for the first time should meet this once.
log WARN "Single instance only. Identity and consent state are in memory, so"
log WARN "this container is stateful: do not scale it, and expect a restart to"
log WARN "drop every Edge Cookie identity it was holding."

exec /usr/local/bin/trusted-server-axum "$@"
