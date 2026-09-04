use edgezero_adapter_axum::dev_server::{AxumDevServer, AxumDevServerConfig};
use edgezero_core::app::Hooks as _;
use trusted_server_adapter_axum::app::TrustedServerApp;
use trusted_server_adapter_axum::tls::{self, TlsPaths};

#[allow(clippy::print_stderr)]
fn main() {
    if let Err(e) = simple_logger::SimpleLogger::new().init() {
        eprintln!("warning: logger init failed: {e}");
    }

    let config = match port_from_env() {
        // When PORT is set, bind to a specific address so integration tests
        // can allocate a fresh OS port each run and avoid TIME_WAIT flakiness.
        Some(port) => AxumDevServerConfig {
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            enable_ctrl_c: true,
        },
        // Normal development path: read bind address from axum.toml.
        None => AxumDevServerConfig::default(),
    };

    // TLS is off unless the operator configures a certificate and key. Reading
    // it before the router is built means a half-configured pair stops startup
    // instead of quietly serving plain HTTP on an address the operator
    // believes is encrypted.
    let tls_paths = match tls::tls_paths_from_env() {
        Ok(paths) => paths,
        Err(err) => {
            log::error!("TLS configuration is not usable: {err:?}");
            std::process::exit(1);
        }
    };

    let router = TrustedServerApp::routes();

    let result = match &tls_paths {
        Some(paths) => serve_https(router, &config, paths),
        None => {
            log::info!("Listening on http://{}", config.addr);
            AxumDevServer::with_config(router, config)
                .run()
                .map_err(|err| format!("{err}"))
        }
    };

    if let Err(err) = result {
        log::error!("trusted-server-adapter-axum failed: {err}");
        std::process::exit(1);
    }
}

/// Serves the router over HTTPS on the configured address.
fn serve_https(
    router: edgezero_core::router::RouterService,
    config: &AxumDevServerConfig,
    paths: &TlsPaths,
) -> Result<(), String> {
    log::info!(
        "Listening on https://{} with certificate {}",
        config.addr,
        paths.certificate.display()
    );
    tls::serve_https(router, config.addr, paths).map_err(|err| format!("{err:?}"))
}

/// Read a port number from the `PORT` environment variable.
///
/// Returns `None` when the variable is unset. Exits non-zero if the value
/// is set but cannot be parsed — silently falling back to a different port
/// would surprise tooling that expects the server at the requested address.
#[allow(clippy::print_stderr)]
fn port_from_env() -> Option<u16> {
    let raw = std::env::var("PORT").ok()?;
    match raw.parse() {
        Ok(port) => Some(port),
        Err(e) => {
            eprintln!("error: PORT env var '{raw}' is not a valid u16: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
