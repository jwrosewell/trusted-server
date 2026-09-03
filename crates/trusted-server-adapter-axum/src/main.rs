use edgezero_adapter_axum::dev_server::{AxumDevServer, AxumDevServerConfig};
use edgezero_core::addr::resolve_bind_addr;
use edgezero_core::app::Hooks as _;
use trusted_server_adapter_axum::app::TrustedServerApp;

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

    log::info!("Listening on http://{}", config.addr);
    let router = TrustedServerApp::routes();
    if let Err(err) = AxumDevServer::with_config(router, config).run() {
        log::error!("trusted-server-adapter-axum failed: {err}");
        std::process::exit(1);
    }
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
