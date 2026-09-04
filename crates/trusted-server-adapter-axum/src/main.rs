use edgezero_adapter_axum::dev_server::{AxumDevServer, AxumDevServerConfig};
use edgezero_core::app::Hooks as _;
use edgezero_core::env_config::EnvConfig;
use trusted_server_adapter_axum::app::TrustedServerApp;
use trusted_server_adapter_axum::platform::init_kv_store;

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

    // Open the persistent KV store before the first request can arrive, and
    // refuse to start if it cannot be opened. Serving traffic without it would
    // silently drop the identity and consent state the store holds, and a
    // dropped consent withdrawal is indistinguishable from a reader who never
    // withdrew.
    match init_kv_store(&EnvConfig::from_env()) {
        Ok(path) => log::info!("KV store opened at {}", path.display()),
        Err(err) => {
            log::error!("failed to open the KV store: {err:?}");
            std::process::exit(1);
        }
    }

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
