//! Optional TLS termination for the Axum adapter.
//!
//! The adapter speaks plain HTTP by default, which is what a developer running
//! `cargo run` wants. An appliance serving readers directly needs HTTPS, and a
//! separate terminator in front of it is another process to install, supervise
//! and configure, plus a second host and port for the publisher rewrite to get
//! wrong. So TLS is terminated here instead, and it stays off unless an
//! operator points the two environment variables below at a certificate and
//! its key.
//!
//! The listener is otherwise the one `EdgeZero`'s own dev server builds, being
//! the same [`EdgeZeroAxumService`], wrapped the same way, and served with
//! `into_make_service_with_connect_info::<SocketAddr>()` so the client address
//! still reaches `AxumRequestContext` and, through it, the client IP that geo
//! and the permission model read.

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use edgezero_adapter_axum::service::EdgeZeroAxumService;
use edgezero_core::router::RouterService;
use error_stack::Report;
use tower::{Service as _, service_fn};
use trusted_server_core::error::TrustedServerError;

/// Environment variable naming the PEM certificate chain to serve.
pub const TLS_CERTIFICATE_PATH_VAR: &str = "TRUSTED_SERVER_TLS_CERTIFICATE_PATH";

/// Environment variable naming the PEM private key for that certificate.
pub const TLS_PRIVATE_KEY_PATH_VAR: &str = "TRUSTED_SERVER_TLS_PRIVATE_KEY_PATH";

/// Paths to the certificate chain and private key used to serve HTTPS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPaths {
    /// PEM certificate chain, leaf first.
    pub certificate: PathBuf,
    /// PEM private key matching the leaf certificate.
    pub private_key: PathBuf,
}

/// Reads the TLS paths from a named-value source.
///
/// Returns `Ok(None)` when neither variable is set, which is the default and
/// leaves the server on plain HTTP.
///
/// # Errors
///
/// Returns [`TrustedServerError::Configuration`] when exactly one of the two
/// is set. An operator who set one and mistyped the other has to be told,
/// rather than served plain HTTP on a port they believe is encrypted.
pub fn tls_paths_from<F>(read: F) -> Result<Option<TlsPaths>, Report<TrustedServerError>>
where
    F: Fn(&str) -> Option<String>,
{
    let certificate = read(TLS_CERTIFICATE_PATH_VAR).filter(|value| !value.trim().is_empty());
    let private_key = read(TLS_PRIVATE_KEY_PATH_VAR).filter(|value| !value.trim().is_empty());

    match (certificate, private_key) {
        (None, None) => Ok(None),
        (Some(certificate), Some(private_key)) => Ok(Some(TlsPaths {
            certificate: PathBuf::from(certificate),
            private_key: PathBuf::from(private_key),
        })),
        (Some(_), None) => Err(Report::new(TrustedServerError::Configuration {
            message: format!(
                "{TLS_CERTIFICATE_PATH_VAR} is set but {TLS_PRIVATE_KEY_PATH_VAR} is not, so TLS cannot be enabled"
            ),
        })),
        (None, Some(_)) => Err(Report::new(TrustedServerError::Configuration {
            message: format!(
                "{TLS_PRIVATE_KEY_PATH_VAR} is set but {TLS_CERTIFICATE_PATH_VAR} is not, so TLS cannot be enabled"
            ),
        })),
    }
}

/// Reads the TLS paths from the process environment.
///
/// # Errors
///
/// See [`tls_paths_from`].
pub fn tls_paths_from_env() -> Result<Option<TlsPaths>, Report<TrustedServerError>> {
    tls_paths_from(|name| std::env::var(name).ok())
}

/// Serves `router` over HTTPS on `addr` until the process is stopped.
///
/// Builds its own multi-threaded Tokio runtime, matching `EdgeZero`'s plain
/// HTTP dev server. The multi-threaded flavor is required rather than
/// preferred, because [`EdgeZeroAxumService`] dispatches through
/// `task::block_in_place`, which panics on a current-thread runtime.
///
/// # Errors
///
/// Returns [`TrustedServerError::Configuration`] when the runtime cannot be
/// built, when the certificate or key cannot be read or parsed, or when the
/// listener fails.
/// Records whether this process is terminating TLS.
///
/// The core scheme detector decides `https` from the TLS fields on
/// [`ClientInfo`](trusted_server_core::platform::ClientInfo), which the adapter
/// populates. Without this the adapter reported no TLS even while serving it,
/// so every rewritten URL was emitted as `http://` on an `https://` page and
/// the browser blocked the lot as mixed content, the injected script included.
static TLS_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Marks this process as terminating TLS.
pub fn mark_tls_active() {
    TLS_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Whether this process is terminating TLS.
///
/// Reports only that TLS is in use, not the negotiated version, because the
/// per-connection version is not plumbed through to the request handler at this
/// layer. That is enough for scheme detection, which is all core asks of it.
#[must_use]
pub fn tls_active() -> bool {
    TLS_ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn serve_https(
    router: RouterService,
    addr: SocketAddr,
    paths: &TlsPaths,
) -> Result<(), Report<TrustedServerError>> {
    // Declared before the listener starts, so the first request already sees it.
    mark_tls_active();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            Report::new(err).change_context(TrustedServerError::Configuration {
                message: "failed to build the Tokio runtime for the HTTPS listener".to_owned(),
            })
        })?;

    runtime.block_on(serve_https_async(router, addr, paths))
}

async fn serve_https_async(
    router: RouterService,
    addr: SocketAddr,
    paths: &TlsPaths,
) -> Result<(), Report<TrustedServerError>> {
    // rustls refuses to pick a cryptography backend on its own when more than
    // one is compiled in, and this binary already links one through reqwest.
    // Installing it explicitly turns a possible runtime panic into a decision
    // made here. An error means another call already installed a default,
    // which is fine.
    let _already_installed = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let tls = RustlsConfig::from_pem_file(&paths.certificate, &paths.private_key)
        .await
        .map_err(|err| {
            Report::new(err).change_context(TrustedServerError::Configuration {
                message: format!(
                    "failed to load the TLS certificate {} and key {}",
                    paths.certificate.display(),
                    paths.private_key.display()
                ),
            })
        })?;

    // The same wrapping the EdgeZero dev server uses, so routing, store
    // handles and the client address behave identically over TLS and over
    // plain HTTP.
    let service = EdgeZeroAxumService::new(router);
    let app = Router::new().fallback_service(service_fn(move |request| {
        let mut service = service.clone();
        async move { service.call(request).await }
    }));

    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|err| {
            Report::new(err).change_context(TrustedServerError::Configuration {
                message: format!("HTTPS listener on {addr} failed"),
            })
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn tls_is_off_when_neither_variable_is_set() {
        let paths = tls_paths_from(reader(&[])).expect("should read an empty environment");

        assert!(
            paths.is_none(),
            "TLS must default to off so existing plain HTTP users are unaffected"
        );
    }

    #[test]
    fn tls_is_on_when_both_variables_are_set() {
        let paths = tls_paths_from(reader(&[
            (TLS_CERTIFICATE_PATH_VAR, "/etc/trusted-server/site.pem"),
            (TLS_PRIVATE_KEY_PATH_VAR, "/etc/trusted-server/site-key.pem"),
        ]))
        .expect("should read both variables")
        .expect("should enable TLS");

        assert_eq!(
            paths.certificate,
            PathBuf::from("/etc/trusted-server/site.pem"),
            "should use the configured certificate"
        );
        assert_eq!(
            paths.private_key,
            PathBuf::from("/etc/trusted-server/site-key.pem"),
            "should use the configured private key"
        );
    }

    #[test]
    fn a_certificate_without_a_key_is_refused() {
        let result = tls_paths_from(reader(&[(
            TLS_CERTIFICATE_PATH_VAR,
            "/etc/trusted-server/site.pem",
        )]));

        assert!(
            result.is_err(),
            "half-configured TLS must fail loudly rather than serve plain HTTP on an address the operator believes is encrypted"
        );
    }

    #[test]
    fn a_key_without_a_certificate_is_refused() {
        let result = tls_paths_from(reader(&[(
            TLS_PRIVATE_KEY_PATH_VAR,
            "/etc/trusted-server/site-key.pem",
        )]));

        assert!(result.is_err(), "half-configured TLS must fail loudly");
    }

    #[test]
    fn a_blank_value_counts_as_unset() {
        let paths = tls_paths_from(reader(&[
            (TLS_CERTIFICATE_PATH_VAR, "   "),
            (TLS_PRIVATE_KEY_PATH_VAR, ""),
        ]))
        .expect("blank values should read as unset");

        assert!(
            paths.is_none(),
            "an exported but empty variable must not half-enable TLS"
        );
    }
}
