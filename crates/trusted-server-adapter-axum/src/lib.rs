//! Native Axum adapter for local Trusted Server development.
//!
//! Runs a full Axum HTTP server on `localhost` as a drop-in dev alternative to
//! the Fastly Compute adapter (via Viceroy). All routes and middleware mirror
//! the Fastly adapter; store and geo primitives fall back to env vars and no-ops.

/// Application routing and handler registration for the Axum dev server.
pub mod app;
/// Edge Cookie identity-graph storage over the persistent KV store.
pub mod ec_kv;
/// Request middleware (auth, response finalisation).
pub mod middleware;
/// Platform-trait implementations backed by env vars and `reqwest`.
pub mod platform;
/// In-process request rate limiting for the Edge Cookie sync endpoints.
pub mod rate_limiter;
