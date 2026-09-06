use edgezero_adapter_axum::dev_server::{AxumDevServer, AxumDevServerConfig};
use edgezero_core::addr::resolve_bind_addr;
use edgezero_core::app::Hooks as _;
use trusted_server_adapter_axum::app::TrustedServerApp;
use trusted_server_adapter_axum::tls::{self, TlsPaths};

#[allow(clippy::print_stderr)]
fn main() {
    if let Err(e) = simple_logger::SimpleLogger::new().init() {
        eprintln!("warning: logger init failed: {e}");
    }

    // The bind host comes from `EDGEZERO__ADAPTER__HOST` through EdgeZero's
    // shared resolver, the same one the CLI dev server uses, and falls back to
    // loopback so an existing deployment sees no change. Binding loopback
    // unconditionally left the adapter unreachable through a published
    // container port, because a port publisher forwards to the container's
    // external address rather than to its loopback.
    //
    // `PORT` keeps its own reader rather than being handed to the resolver as
    // the environment port, because an unparseable `PORT` must exit rather
    // than warn and fall back. See `port_from_env`.
    let env_host = std::env::var("EDGEZERO__ADAPTER__HOST").ok();
    let resolution = resolve_bind_addr(env_host.as_deref(), None, None, port_from_env());
    for warning in &resolution.warnings {
        log::warn!("{warning}");
    }
    let config = AxumDevServerConfig {
        addr: resolution.addr,
        enable_ctrl_c: true,
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
