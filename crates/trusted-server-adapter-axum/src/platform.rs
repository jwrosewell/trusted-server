use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use edgezero_adapter_axum::key_value_store::PersistentKvStore;
use edgezero_core::env_config::EnvConfig;
use edgezero_core::http::{HeaderMap, HeaderName, HeaderValue, header};
use error_stack::{Report, ResultExt as _};
use trusted_server_core::error::TrustedServerError;
use trusted_server_core::platform::{
    ClientInfo, GeoInfo, PlatformBackend, PlatformBackendSpec, PlatformConfigStore, PlatformError,
    PlatformGeo, PlatformHttpClient, PlatformHttpRequest, PlatformKvStore, PlatformPendingRequest,
    PlatformResponse, PlatformSecretStore, PlatformSelectResult, RuntimeServices, StoreId,
    StoreName,
};

// ---------------------------------------------------------------------------
// Env-var naming helpers
// ---------------------------------------------------------------------------

/// Normalize a store name or key for use as an environment-variable segment.
///
/// Uppercases and replaces hyphens, dots, and spaces with underscores.
fn normalize_env_segment(s: &str) -> String {
    s.to_uppercase().replace(['-', '.', ' '], "_")
}

fn config_env_var(store_name: &str, key: &str) -> String {
    format!(
        "TRUSTED_SERVER_CONFIG_{}_{}",
        normalize_env_segment(store_name),
        normalize_env_segment(key),
    )
}

fn secret_env_var(store_name: &str, key: &str) -> String {
    format!(
        "TRUSTED_SERVER_SECRET_{}_{}",
        normalize_env_segment(store_name),
        normalize_env_segment(key),
    )
}

// ---------------------------------------------------------------------------
// PlatformConfigStore
// ---------------------------------------------------------------------------

/// Environment-variable–backed config store for the Axum dev server.
///
/// Reads from `TRUSTED_SERVER_CONFIG_{STORE}_{KEY}` (uppercased, hyphens→underscores).
/// Write operations are unsupported in local development.
pub struct AxumPlatformConfigStore;

impl PlatformConfigStore for AxumPlatformConfigStore {
    fn get(&self, store_name: &StoreName, key: &str) -> Result<String, Report<PlatformError>> {
        let var_name = config_env_var(store_name.as_ref(), key);
        std::env::var(&var_name).map_err(|_| {
            Report::new(PlatformError::ConfigStore).attach(format!(
                "env var '{var_name}' not set — export it to supply this config value"
            ))
        })
    }

    fn put(
        &self,
        store_id: &StoreId,
        key: &str,
        _value: &str,
    ) -> Result<(), Report<PlatformError>> {
        log::warn!(
            "AxumPlatformConfigStore: write to store '{}' key '{}' ignored \
             (config store writes are not supported on the Axum dev server)",
            store_id.as_ref(),
            key
        );
        Err(Report::new(PlatformError::ConfigStore)
            .attach("config store writes are not supported on the Axum dev server"))
    }

    fn delete(&self, store_id: &StoreId, key: &str) -> Result<(), Report<PlatformError>> {
        log::warn!(
            "AxumPlatformConfigStore: delete from store '{}' key '{}' ignored \
             (config store deletes are not supported on the Axum dev server)",
            store_id.as_ref(),
            key
        );
        Err(Report::new(PlatformError::ConfigStore)
            .attach("config store deletes are not supported on the Axum dev server"))
    }
}

// ---------------------------------------------------------------------------
// PlatformSecretStore
// ---------------------------------------------------------------------------

/// Environment-variable–backed secret store for the Axum dev server.
///
/// Reads from `TRUSTED_SERVER_SECRET_{STORE}_{KEY}` as raw UTF-8 bytes.
/// Write operations are unsupported in local development.
pub struct AxumPlatformSecretStore;

impl PlatformSecretStore for AxumPlatformSecretStore {
    fn get_bytes(
        &self,
        store_name: &StoreName,
        key: &str,
    ) -> Result<Vec<u8>, Report<PlatformError>> {
        let var_name = secret_env_var(store_name.as_ref(), key);
        std::env::var(&var_name)
            .map(String::into_bytes)
            .map_err(|_| {
                Report::new(PlatformError::SecretStore).attach(format!(
                    "env var '{var_name}' not set — export it to supply this secret value"
                ))
            })
    }

    fn create(
        &self,
        store_id: &StoreId,
        name: &str,
        _value: &str,
    ) -> Result<(), Report<PlatformError>> {
        log::warn!(
            "AxumPlatformSecretStore: create '{}' in store '{}' ignored \
             (secret store writes are not supported on the Axum dev server)",
            name,
            store_id.as_ref()
        );
        Err(Report::new(PlatformError::SecretStore)
            .attach("secret store writes are not supported on the Axum dev server"))
    }

    fn delete(&self, store_id: &StoreId, name: &str) -> Result<(), Report<PlatformError>> {
        log::warn!(
            "AxumPlatformSecretStore: delete '{}' from store '{}' ignored \
             (secret store deletes are not supported on the Axum dev server)",
            name,
            store_id.as_ref()
        );
        Err(Report::new(PlatformError::SecretStore)
            .attach("secret store deletes are not supported on the Axum dev server"))
    }
}

// ---------------------------------------------------------------------------
// PlatformBackend
// ---------------------------------------------------------------------------

/// No-op backend for the Axum dev server.
///
/// Returns a deterministic name; `ensure` is a no-op returning the same name.
/// The Axum HTTP client sends directly to URIs and ignores backend names.
pub struct AxumPlatformBackend;

impl PlatformBackend for AxumPlatformBackend {
    fn predict_name(&self, spec: &PlatformBackendSpec) -> Result<String, Report<PlatformError>> {
        let port = spec
            .port
            .unwrap_or(if spec.scheme == "https" { 443 } else { 80 });
        // Keep two providers that share an origin on distinct names so auction
        // response correlation cannot cross providers.
        let discriminator = spec
            .discriminator
            .as_deref()
            .map(|d| format!("_p_{}", normalize_env_segment(d)))
            .unwrap_or_default();
        Ok(format!(
            "{}_{}_{}{}",
            normalize_env_segment(&spec.scheme),
            normalize_env_segment(&spec.host),
            port,
            discriminator,
        ))
    }

    fn ensure(&self, spec: &PlatformBackendSpec) -> Result<String, Report<PlatformError>> {
        self.predict_name(spec)
    }
}

// ---------------------------------------------------------------------------
// PlatformGeo
// ---------------------------------------------------------------------------

/// No-op geo implementation — geographic lookup is unavailable in local development.
pub struct AxumPlatformGeo;

#[async_trait::async_trait(?Send)]
impl PlatformGeo for AxumPlatformGeo {
    async fn lookup(
        &self,
        _client_ip: Option<IpAddr>,
        _services: &trusted_server_core::platform::RuntimeServices,
    ) -> Result<Option<GeoInfo>, Report<PlatformError>> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// PlatformHttpClient
// ---------------------------------------------------------------------------

/// Maximum buffered upstream response body.
///
/// The Fastly adapter caps origin responses at this size
/// (`MAX_PLATFORM_RESPONSE_BODY_BYTES` in
/// `crates/trusted-server-adapter-fastly/src/platform.rs`) and the Cloudflare
/// adapter mirrors it
/// (`crates/trusted-server-adapter-cloudflare/src/platform.rs`). This adapter
/// buffers the whole upstream response with `resp.bytes()`, so without the same
/// cap a large or hostile upstream grows the process heap without bound. The
/// value is copied from those two rather than chosen here, so all three
/// adapters accept and reject the same responses.
const MAX_PLATFORM_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

/// Rejects an upstream response whose declared `Content-Length` is over the cap.
///
/// `Content-Length` is advisory and absent on chunked responses, so this only
/// rejects honestly-declared large bodies, before any bytes are copied.
/// [`reject_oversized_body`] is the real guard. Mirrors the two-stage cap in
/// the Fastly and Cloudflare adapters.
fn reject_oversized_content_length(
    headers: &reqwest::header::HeaderMap,
    uri: &str,
) -> Result<(), Report<PlatformError>> {
    let Some(claimed_len) = headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<usize>().ok())
    else {
        return Ok(());
    };

    if claimed_len > MAX_PLATFORM_RESPONSE_BODY_BYTES {
        return Err(Report::new(PlatformError::HttpClient).attach(format!(
            "origin Content-Length {claimed_len} from {uri} exceeds \
             {MAX_PLATFORM_RESPONSE_BODY_BYTES}-byte response body limit"
        )));
    }
    Ok(())
}

/// Rejects an upstream response body that is over the cap once buffered.
///
/// Belt and braces for a chunked response that declares no `Content-Length`.
fn reject_oversized_body(len: usize, uri: &str) -> Result<(), Report<PlatformError>> {
    if len > MAX_PLATFORM_RESPONSE_BODY_BYTES {
        return Err(Report::new(PlatformError::HttpClient).attach(format!(
            "origin response body {len} bytes from {uri} exceeds \
             {MAX_PLATFORM_RESPONSE_BODY_BYTES}-byte limit"
        )));
    }
    Ok(())
}

type SpawnedRequestResult = Result<(u16, Vec<(String, Vec<u8>)>, Vec<u8>), Report<PlatformError>>;

fn sanitized_response_headers(headers: &HeaderMap) -> Vec<(String, Vec<u8>)> {
    let connection_tokens = connection_header_tokens(headers);

    headers
        .iter()
        .filter(|(name, _)| !is_hop_by_hop_response_header(name, &connection_tokens))
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect()
}

fn connection_header_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(header_value_to_str)
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
        .collect()
}

fn header_value_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

fn is_hop_by_hop_response_header(name: &HeaderName, connection_tokens: &[HeaderName]) -> bool {
    name == header::CONNECTION
        || name == header::PROXY_AUTHENTICATE
        || name == header::PROXY_AUTHORIZATION
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || connection_tokens.iter().any(|token| token == name)
}

/// Buffered response parts from a spawned outbound request.
///
/// Stored inside [`PlatformPendingRequest`] so that [`AxumPlatformHttpClient::select`]
/// can poll multiple in-flight handles concurrently via
/// [`futures::future::select_all`].
struct AxumPendingHandle {
    backend_name: String,
    handle: tokio::task::JoinHandle<SpawnedRequestResult>,
}

impl Drop for AxumPendingHandle {
    fn drop(&mut self) {
        // Abort instead of detaching: when the orchestrator hits the auction
        // deadline and drops the remaining pending requests, the abandoned
        // bidder tasks would otherwise keep running for up to the 30s
        // transport timeout.
        self.handle.abort();
    }
}

/// Resolves to the backend name together with the task result so that
/// [`futures::future::select_all`] callers never have to reconstruct which
/// backend a completion belongs to by position. `select_all` removes the
/// ready future with `swap_remove` and makes no ordering guarantee for the
/// remaining futures, so positional bookkeeping would mislabel them.
impl Future for AxumPendingHandle {
    type Output = (String, Result<SpawnedRequestResult, tokio::task::JoinError>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.handle).poll(cx) {
            Poll::Ready(result) => {
                let backend_name = std::mem::take(&mut self.backend_name);
                Poll::Ready((backend_name, result))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// reqwest-backed HTTP client for the Axum dev server.
///
/// `send_async` buffers any `Body::Stream` in the calling context, then spawns
/// a `tokio` task for each outbound request so that multiple `send_async` calls
/// run concurrently. `select` uses [`futures::future::select_all`] to wait for
/// the first completing handle, preserving fan-out semantics.
pub struct AxumPlatformHttpClient {
    client: reqwest::Client,
}

impl AxumPlatformHttpClient {
    /// Create a new client with sensible dev-server timeouts.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` cannot be built (should not
    /// happen with the default TLS configuration on any supported platform).
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(30))
                // Disable automatic redirects: core proxy code enforces redirect
                // limits and allowed_domains checks itself. Without this, reqwest
                // would follow Location headers internally and bypass those checks.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("should build reqwest client"),
        }
    }

    /// Drain `body` to a `Vec<u8>`.
    ///
    /// For `Body::Stream` this awaits every chunk in the current async context
    /// (where `LocalBoxStream` is valid) before the bytes are moved into a
    /// `tokio::spawn` task that requires `Send`.
    async fn buffer_body(
        body: edgezero_core::body::Body,
    ) -> Result<Vec<u8>, Report<PlatformError>> {
        match body {
            edgezero_core::body::Body::Once(bytes) => Ok(bytes.to_vec()),
            edgezero_core::body::Body::Stream(mut stream) => {
                log::debug!("buffering Body::Stream into Vec<u8> for outbound request");
                use futures::StreamExt as _;
                let mut buf = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let bytes = chunk.map_err(|e| {
                        Report::new(PlatformError::HttpClient)
                            .attach(format!("failed to buffer outbound streaming body: {e}"))
                    })?;
                    buf.extend_from_slice(&bytes);
                }
                Ok(buf)
            }
        }
    }

    async fn execute(
        &self,
        request: PlatformHttpRequest,
    ) -> Result<PlatformResponse, Report<PlatformError>> {
        let uri = request.request.uri().to_string();
        let method = reqwest::Method::from_bytes(request.request.method().as_str().as_bytes())
            .change_context(PlatformError::HttpClient)?;

        let mut builder = self.client.request(method, &uri);
        for (name, value) in request.request.headers() {
            builder = builder.header(name.as_str(), value.as_bytes());
        }

        let (_, body) = request.request.into_parts();
        let body_bytes = Self::buffer_body(body).await?;
        if !body_bytes.is_empty() {
            builder = builder.body(body_bytes);
        }

        let resp = builder
            .send()
            .await
            .change_context(PlatformError::HttpClient)
            .attach(format!("outbound request to {uri} failed"))?;

        let status = resp.status().as_u16();
        reject_oversized_content_length(resp.headers(), &uri)?;
        let mut edge_builder = edgezero_core::http::response_builder().status(status);
        for (name, value) in sanitized_response_headers(resp.headers()) {
            edge_builder = edge_builder.header(name.as_str(), value.as_slice());
        }
        let resp_bytes = resp
            .bytes()
            .await
            .change_context(PlatformError::HttpClient)?;
        reject_oversized_body(resp_bytes.len(), &uri)?;
        log::debug!(
            "buffered {} upstream response bytes from {uri}",
            resp_bytes.len()
        );
        let edge_resp = edge_builder
            .body(edgezero_core::body::Body::from(resp_bytes.to_vec()))
            .change_context(PlatformError::HttpClient)?;

        Ok(PlatformResponse::new(edge_resp).with_backend_name(request.backend_name))
    }
}

impl Default for AxumPlatformHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl PlatformHttpClient for AxumPlatformHttpClient {
    async fn send(
        &self,
        request: PlatformHttpRequest,
    ) -> Result<PlatformResponse, Report<PlatformError>> {
        self.execute(request).await
    }

    async fn send_async(
        &self,
        request: PlatformHttpRequest,
    ) -> Result<PlatformPendingRequest, Report<PlatformError>> {
        let backend_name = request.backend_name.clone();

        // Extract all Send-compatible parts before spawning.
        let uri = request.request.uri().to_string();
        let method_bytes = request.request.method().as_str().as_bytes().to_vec();
        let headers: Vec<(String, Vec<u8>)> = request
            .request
            .headers()
            .iter()
            .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
            .collect();

        // Buffer any LocalBoxStream body here in the ?Send context before spawn.
        let (_, body) = request.request.into_parts();
        let body_bytes = Self::buffer_body(body).await?;

        let client = self.client.clone();
        let handle = tokio::spawn(async move {
            let method = reqwest::Method::from_bytes(&method_bytes)
                .map_err(|e| Report::new(PlatformError::HttpClient).attach(e.to_string()))?;
            let mut builder = client.request(method, &uri);
            for (name, value) in &headers {
                builder = builder.header(name.as_str(), value.as_slice());
            }
            if !body_bytes.is_empty() {
                builder = builder.body(body_bytes);
            }
            let resp = builder.send().await.map_err(|e| {
                Report::new(PlatformError::HttpClient)
                    .attach(format!("outbound request to {uri} failed: {e}"))
            })?;
            let status = resp.status().as_u16();
            reject_oversized_content_length(resp.headers(), &uri)?;
            let resp_headers = sanitized_response_headers(resp.headers());
            let body = resp
                .bytes()
                .await
                .map_err(|e| Report::new(PlatformError::HttpClient).attach(e.to_string()))?
                .to_vec();
            reject_oversized_body(body.len(), &uri)?;
            log::debug!("buffered {} upstream response bytes from {uri}", body.len());
            Ok::<_, Report<PlatformError>>((status, resp_headers, body))
        });

        let pending = AxumPendingHandle {
            backend_name: backend_name.clone(),
            handle,
        };
        Ok(PlatformPendingRequest::new(pending).with_backend_name(backend_name))
    }

    async fn select(
        &self,
        pending_requests: Vec<PlatformPendingRequest>,
    ) -> Result<PlatformSelectResult, Report<PlatformError>> {
        if pending_requests.is_empty() {
            return Err(Report::new(PlatformError::HttpClient)
                .attach("select called with an empty pending_requests list"));
        }

        let handles: Vec<AxumPendingHandle> = pending_requests
            .into_iter()
            .map(|pr| {
                pr.downcast::<AxumPendingHandle>().map_err(|_| {
                    Report::new(PlatformError::HttpClient)
                        .attach("unexpected inner type in AxumPlatformHttpClient::select")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Each AxumPendingHandle resolves to (backend_name, result), so the
        // remaining handles keep their own backend names — no positional
        // reconstruction (select_all does not preserve the order of the
        // remaining futures).
        let ((backend_name, result), _ready_idx, remaining_handles) =
            futures::future::select_all(handles).await;

        let remaining: Vec<PlatformPendingRequest> = remaining_handles
            .into_iter()
            .map(|handle| {
                let backend_name = handle.backend_name.clone();
                PlatformPendingRequest::new(handle).with_backend_name(backend_name)
            })
            .collect();

        // Map join panics and per-request errors into ready: Err(...) so that the
        // auction orchestrator can log the failure and continue with remaining providers
        // rather than treating one bad provider as a fatal select() failure.
        let ready = result
            .map_err(|e| {
                Report::new(PlatformError::HttpClient)
                    .attach(format!("auction request task panicked: {e}"))
            })
            .and_then(|inner| inner)
            .and_then(|(status, headers, body)| {
                let mut builder = edgezero_core::http::response_builder().status(status);
                for (name, value) in &headers {
                    builder = builder.header(name.as_str(), value.as_slice());
                }
                builder
                    .body(edgezero_core::body::Body::from(body))
                    .change_context(PlatformError::HttpClient)
            })
            .map(|edge_resp| {
                PlatformResponse::new(edge_resp).with_backend_name(backend_name.clone())
            });

        // Attribute the failure to its backend so the orchestrator can remove
        // the provider and record a BidStatus::Error, matching the Fastly
        // adapter. Without this, a failed provider silently vanishes through
        // the orchestrator's "backend not identified" branch.
        let failed_backend_name = ready.as_ref().err().map(|_| backend_name);

        Ok(PlatformSelectResult {
            ready,
            remaining,
            failed_backend_name,
        })
    }
}

const DEFAULT_KV_STORE_ID: &str = "trusted_server_kv";

/// Directory holding the adapter's local KV database file.
///
/// Matches the `.edgezero/` convention the `EdgeZero` Axum dev server already
/// uses, which is listed in the repository `.gitignore`.
const DEFAULT_KV_DIR: &str = ".edgezero";

/// Process-wide KV store, published by [`init_kv_store`] before the server
/// starts accepting requests.
static KV_STORE: OnceLock<Arc<dyn PlatformKvStore>> = OnceLock::new();

/// Warn-once guard for requests served before [`init_kv_store`] ran.
static KV_UNINITIALIZED_WARNED: OnceLock<()> = OnceLock::new();

/// Resolves the file path backing the adapter's persistent KV store.
///
/// Resolution order, both read from the `EDGEZERO__*` environment layer that
/// already supplies every other adapter store binding:
///
/// 1. `EDGEZERO__STORES__KV__TRUSTED_SERVER_KV__PATH` — a complete path,
///    used verbatim. An appliance sets this so durable state lives outside
///    the working directory.
/// 2. Otherwise `.edgezero/<store name>.redb`, where the store name comes
///    from `EDGEZERO__STORES__KV__TRUSTED_SERVER_KV__NAME` and falls back to
///    the logical id `trusted_server_kv`.
///
/// # Examples
///
/// ```
/// use edgezero_core::env_config::EnvConfig;
/// use trusted_server_adapter_axum::platform::kv_store_path;
///
/// let env = EnvConfig::from_vars(Vec::<(String, String)>::new());
/// assert!(
///     kv_store_path(&env).ends_with("trusted_server_kv.redb"),
///     "should derive the file name from the logical store id"
/// );
/// ```
#[must_use]
pub fn kv_store_path(env: &EnvConfig) -> PathBuf {
    if let Some(path) = env
        .get(&["stores", "kv", DEFAULT_KV_STORE_ID, "path"])
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        return PathBuf::from(path);
    }

    let store_name = env.store_name("kv", DEFAULT_KV_STORE_ID);
    Path::new(DEFAULT_KV_DIR).join(format!("{store_name}.redb"))
}

/// Opens a persistent KV store at `path`, creating the parent directory and
/// the database file when they do not exist.
///
/// This is the seam the contract tests drive, so the store they exercise is
/// built exactly the way a request-serving process builds it.
///
/// # Errors
///
/// Returns [`TrustedServerError::KvStore`] when the parent directory cannot be
/// created or the database file cannot be opened. A file already locked by
/// another process is reported here too, because `redb` takes an exclusive
/// lock and only one process may hold a database file at a time.
pub fn open_kv_store(path: &Path) -> Result<Arc<dyn PlatformKvStore>, Report<TrustedServerError>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            Report::new(err).change_context(TrustedServerError::KvStore {
                store_name: DEFAULT_KV_STORE_ID.to_owned(),
                message: format!("Failed to create KV store directory {}", parent.display()),
            })
        })?;
    }

    let store = PersistentKvStore::new(path).map_err(|err| {
        Report::new(err).change_context(TrustedServerError::KvStore {
            store_name: DEFAULT_KV_STORE_ID.to_owned(),
            message: format!("Failed to open KV database at {}", path.display()),
        })
    })?;

    Ok(Arc::new(store) as Arc<dyn PlatformKvStore>)
}

/// Opens the persistent KV store and publishes it for request handling.
///
/// Returns the path that was opened so the caller can log it. Call this once,
/// before the server starts accepting requests. A second call leaves the
/// already-published store in place and returns the path it would have used.
///
/// # Errors
///
/// Returns [`TrustedServerError::KvStore`] when the store cannot be opened.
/// The caller is expected to fail startup: serving traffic without the store
/// would silently drop the identity and consent state the store exists to
/// keep, and a dropped consent withdrawal is indistinguishable from a reader
/// who never withdrew.
pub fn init_kv_store(env: &EnvConfig) -> Result<PathBuf, Report<TrustedServerError>> {
    let path = kv_store_path(env);
    let store = open_kv_store(&path)?;

    // `set` fails only when the store was already published, which is a
    // repeated call rather than a reason to fail startup.
    let _ = KV_STORE.set(store);
    Ok(path)
}

/// Returns the published KV store, or an unavailable stand-in when
/// [`init_kv_store`] has not run.
///
/// The stand-in is only reachable from in-process test harnesses that build a
/// router directly; the binary always initializes the store first and exits if
/// it cannot.
fn kv_store() -> Arc<dyn PlatformKvStore> {
    if let Some(store) = KV_STORE.get() {
        return Arc::clone(store);
    }

    KV_UNINITIALIZED_WARNED.get_or_init(|| {
        log::warn!(
            "KV store was not initialized before serving, so this process falls \
             back to UnavailableKvStore. Call init_kv_store at startup."
        );
    });
    Arc::new(trusted_server_core::platform::UnavailableKvStore) as Arc<dyn PlatformKvStore>
}

// ---------------------------------------------------------------------------
// build_runtime_services
// ---------------------------------------------------------------------------

/// Construct [`RuntimeServices`] for an incoming Axum request.
///
/// The KV store is the persistent `redb`-backed store opened by
/// [`init_kv_store`] at startup. When that has not run, which is only reachable
/// from an in-process test harness, the request falls back to
/// [`trusted_server_core::platform::UnavailableKvStore`] and a `warn` is logged
/// once per process.
///
/// `settings` selects the geo, Edge Cookie and device providers, so it stays on
/// the signature even though the store no longer needs it.
pub fn build_runtime_services(
    ctx: &edgezero_core::context::RequestContext,
    settings: &trusted_server_core::settings::Settings,
) -> RuntimeServices {
    let socket_ip = edgezero_adapter_axum::context::AxumRequestContext::get(ctx.request())
        .and_then(|c| c.remote_addr)
        .map(|addr| addr.ip());
    let client_ip = forwarded_client_ip(ctx.request().headers()).or(socket_ip);

    use trusted_server_core::platform::{
        PlatformBackend, PlatformConfigStore, PlatformGeo, PlatformSecretStore,
    };

    // Stateless shims are promoted to process-wide statics so callers clone
    // an existing Arc instead of allocating a new one per request.
    static CONFIG_STORE: std::sync::OnceLock<Arc<dyn PlatformConfigStore>> =
        std::sync::OnceLock::new();
    static SECRET_STORE: std::sync::OnceLock<Arc<dyn PlatformSecretStore>> =
        std::sync::OnceLock::new();
    static BACKEND: std::sync::OnceLock<Arc<dyn PlatformBackend>> = std::sync::OnceLock::new();
    static GEO: std::sync::OnceLock<Arc<dyn PlatformGeo>> = std::sync::OnceLock::new();

    RuntimeServices::builder()
        .config_store(Arc::clone(CONFIG_STORE.get_or_init(|| {
            Arc::new(AxumPlatformConfigStore) as Arc<dyn PlatformConfigStore>
        })))
        .secret_store(Arc::clone(SECRET_STORE.get_or_init(|| {
            Arc::new(AxumPlatformSecretStore) as Arc<dyn PlatformSecretStore>
        })))
        .kv_store(kv_store())
        .backend(Arc::clone(BACKEND.get_or_init(|| {
            Arc::new(AxumPlatformBackend) as Arc<dyn PlatformBackend>
        })))
        // Keep the HTTP client request-scoped in the dev adapter. Sharing a pooled
        // client across requests previously regressed the Next.js server-action →
        // API-route integration flow by reusing a poisoned connection after a
        // truncated POST. Revisit pooling if profiling shows allocation cost.
        .http_client(Arc::new(AxumPlatformHttpClient::new()))
        // Route through the [geo] provider selector like the Fastly adapter,
        // so the selector behaves the same on every adapter.
        .geo(trusted_server_core::platform::build_geo_provider(
            settings,
            Arc::clone(GEO.get_or_init(|| Arc::new(AxumPlatformGeo) as Arc<dyn PlatformGeo>)),
        ))
        .client_info(ClientInfo {
            client_ip,
            tls_protocol: None,
            tls_cipher: None,
            ..ClientInfo::default()
        })
        .build()
}

/// Environment variable naming how many proxies sit in front of this
/// appliance.
///
/// Unset, zero, or unparseable all mean the same thing: never read a forwarded
/// header. That default is the safe one and it is the one a deployment gets by
/// doing nothing.
const TRUSTED_PROXY_HOPS: &str = "TRUSTED_SERVER_TRUSTED_PROXY_HOPS";

/// The number of proxies whose `X-Forwarded-For` entries this deployment
/// trusts, read once per process.
fn trusted_proxy_hops() -> usize {
    static HOPS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *HOPS.get_or_init(|| {
        let hops = std::env::var(TRUSTED_PROXY_HOPS)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if hops > 0 {
            // Said once, at the level an operator will see, because trusting a
            // header is a security posture and not a tuning knob.
            log::warn!(
                "{TRUSTED_PROXY_HOPS}={hops}: the client address will be read from \
                 X-Forwarded-For. This is only safe when exactly {hops} proxy or proxies \
                 you control sit in front of this appliance and rewrite that header. \
                 Reachable directly, a visitor can choose their own address, and with it \
                 their own country and their own identity evidence."
            );
        }
        hops
    })
}

/// The client address a trusted proxy forwarded, when this deployment has said
/// it is behind one.
///
/// # Why this is opt-in, and counted rather than merely present
///
/// `X-Forwarded-For` is a header any client can send. Reading it whenever it
/// appears lets a visitor pick their own address, and with it their own
/// country, their own permission jurisdiction and their own identity evidence.
/// So this reads nothing at all unless an operator has said how many proxies
/// are in front, and then it reads exactly that far in.
///
/// The header is a list appended left to right, so the rightmost entry was
/// written by the nearest proxy and is the only one that proxy vouches for.
/// Counting in from the right by the number of hops lands on the address the
/// outermost trusted proxy saw. Taking the leftmost entry instead, which is the
/// common shortcut, takes whatever the client wrote.
fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    forwarded_client_ip_with_hops(headers, trusted_proxy_hops())
}

/// The forwarded address for an explicit hop count.
///
/// Separated from [`forwarded_client_ip`] because the hop count is read from
/// the environment once per process, and a rule about trusting client input
/// deserves tests that do not depend on process-wide state.
fn forwarded_client_ip_with_hops(headers: &HeaderMap, hops: usize) -> Option<IpAddr> {
    if hops == 0 {
        return None;
    }
    let forwarded = headers.get("x-forwarded-for")?.to_str().ok()?;
    let entries: Vec<&str> = forwarded.split(',').map(str::trim).collect();
    // One hop trusts the rightmost entry, two hops the one before it. A header
    // with fewer entries than there are trusted proxies did not come through
    // those proxies, so nothing in it is vouched for.
    let index = entries.len().checked_sub(hops)?;
    entries.get(index)?.parse::<IpAddr>().ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn forwarded(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_str(value).expect("should build the test header"),
        );
        headers
    }

    #[test]
    fn no_trusted_proxy_means_the_header_is_never_read() {
        let headers = forwarded("2.125.160.216");

        assert_eq!(
            forwarded_client_ip_with_hops(&headers, 0),
            None,
            "a deployment that has said nothing must not let a visitor choose their own \
             address, and with it their own country and their own identity evidence"
        );
    }

    #[test]
    fn one_trusted_proxy_reads_the_entry_that_proxy_wrote() {
        // The client claimed to be 10.0.0.1. The proxy appended what it saw.
        let headers = forwarded("10.0.0.1, 2.125.160.216");

        assert_eq!(
            forwarded_client_ip_with_hops(&headers, 1),
            Some("2.125.160.216".parse().expect("should parse")),
            "the rightmost entry is the only one the nearest proxy vouches for, and \
             taking the leftmost would take whatever the client wrote"
        );
    }

    #[test]
    fn two_trusted_proxies_read_one_entry_further_in() {
        let headers = forwarded("10.0.0.1, 2.125.160.216, 203.0.113.7");

        assert_eq!(
            forwarded_client_ip_with_hops(&headers, 2),
            Some("2.125.160.216".parse().expect("should parse")),
            "with two proxies in front, the outermost saw this address"
        );
    }

    #[test]
    fn a_header_shorter_than_the_trusted_chain_is_refused() {
        let headers = forwarded("2.125.160.216");

        assert_eq!(
            forwarded_client_ip_with_hops(&headers, 2),
            None,
            "a request with fewer entries than there are trusted proxies did not come \
             through them, so nothing in the header is vouched for"
        );
    }

    #[test]
    fn an_entry_that_is_not_an_address_is_refused() {
        let headers = forwarded("10.0.0.1, not-an-address");

        assert_eq!(
            forwarded_client_ip_with_hops(&headers, 1),
            None,
            "the trusted position holding something that is not an address means the \
             chain is not what the deployment described"
        );
    }

    #[test]
    fn an_absent_header_resolves_nothing_even_when_a_proxy_is_trusted() {
        assert_eq!(forwarded_client_ip_with_hops(&HeaderMap::new(), 1), None);
    }

    use edgezero_core::body::Body as EdgeBody;

    /// The services graph a provider is handed, built the same way the request
    /// path builds it so the tests exercise the production shape.
    fn test_services() -> RuntimeServices {
        let req = edgezero_core::http::request_builder()
            .method("GET")
            .uri("https://example.com/")
            .body(EdgeBody::empty())
            .expect("should build test request");
        let ctx = edgezero_core::context::RequestContext::new(
            req,
            edgezero_core::params::PathParams::default(),
        );
        build_runtime_services(&ctx, &trusted_server_core::settings::Settings::default())
    }
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[test]
    fn config_store_reads_from_env_var() {
        temp_env::with_var(
            "TRUSTED_SERVER_CONFIG_MY_STORE_MY_KEY",
            Some("test-value"),
            || {
                let store = AxumPlatformConfigStore;
                let result = store
                    .get(&StoreName::from("my-store"), "my-key")
                    .expect("should read env var");
                assert_eq!(result, "test-value", "should return env var value");
            },
        );
    }

    #[test]
    fn config_store_returns_error_for_missing_env_var() {
        let store = AxumPlatformConfigStore;
        let result = store.get(
            &StoreName::from("nonexistent-store-zzz"),
            "nonexistent-key-zzz",
        );
        assert!(result.is_err(), "should error for missing env var");
    }

    #[test]
    fn secret_store_reads_bytes_from_env_var() {
        temp_env::with_var(
            "TRUSTED_SERVER_SECRET_MY_SECRETS_MY_SECRET",
            Some("hello"),
            || {
                let store = AxumPlatformSecretStore;
                let result = store
                    .get_bytes(&StoreName::from("my-secrets"), "my-secret")
                    .expect("should read env var as bytes");
                assert_eq!(result, b"hello", "should return raw bytes");
            },
        );
    }

    #[test]
    fn backend_predict_name_returns_deterministic_string() {
        let backend = AxumPlatformBackend;
        let spec = PlatformBackendSpec {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            port: None,
            certificate_check: true,
            first_byte_timeout: Duration::from_secs(15),
            between_bytes_timeout: Duration::from_secs(15),
            host_header_override: None,
            discriminator: None,
        };
        let name1 = backend.predict_name(&spec).expect("should return a name");
        let name2 = backend
            .predict_name(&spec)
            .expect("should return same name");
        assert!(!name1.is_empty(), "should return a non-empty name");
        assert_eq!(name1, name2, "should be deterministic");
    }

    #[test]
    fn backend_ensure_returns_same_name_as_predict() {
        let backend = AxumPlatformBackend;
        let spec = PlatformBackendSpec {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            port: None,
            certificate_check: true,
            first_byte_timeout: Duration::from_secs(15),
            between_bytes_timeout: Duration::from_secs(15),
            host_header_override: None,
            discriminator: None,
        };
        assert_eq!(
            backend.predict_name(&spec).expect("should return name"),
            backend.ensure(&spec).expect("should return name"),
            "ensure should equal predict_name"
        );
    }

    #[tokio::test]
    async fn geo_always_returns_none() {
        let geo = AxumPlatformGeo;
        let no_ip = geo
            .lookup(None, &test_services())
            .await
            .expect("should not error");
        assert!(no_ip.is_none(), "should return None for no IP");
        let with_ip = geo
            .lookup(
                Some("127.0.0.1".parse().expect("should parse IP")),
                &test_services(),
            )
            .await
            .expect("should not error");
        assert!(with_ip.is_none(), "should return None for any IP");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_client_strips_hop_by_hop_response_headers() {
        let url = serve_raw_response(
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: keep-alive, x-remove-me\r\n\
              Keep-Alive: timeout=5\r\n\
              X-Remove-Me: listed-by-connection\r\n\
              X-Preserve-Me: application-header\r\n\
              \r\n\
              2\r\n\
              ok\r\n\
              0\r\n\
              \r\n",
        )
        .await;

        let request = edgezero_core::http::request_builder()
            .uri(url)
            .body(EdgeBody::empty())
            .expect("should build outbound request");

        let response = AxumPlatformHttpClient::new()
            .send(PlatformHttpRequest::new(request, "test_backend"))
            .await
            .expect("should proxy raw response")
            .response;

        assert!(
            response.headers().get(header::TRANSFER_ENCODING).is_none(),
            "should strip transfer-encoding"
        );
        assert!(
            response.headers().get(header::CONNECTION).is_none(),
            "should strip connection"
        );
        assert!(
            response.headers().get("keep-alive").is_none(),
            "should strip keep-alive"
        );
        assert!(
            response.headers().get("x-remove-me").is_none(),
            "should strip headers named by connection"
        );
        assert_eq!(
            response
                .headers()
                .get("x-preserve-me")
                .and_then(|value| value.to_str().ok()),
            Some("application-header"),
            "should preserve end-to-end headers"
        );
        assert_eq!(
            response
                .into_body()
                .into_bytes()
                .unwrap_or_default()
                .as_ref(),
            b"ok",
            "should preserve decoded response body"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn select_attributes_failed_backend_name() {
        // Bind and immediately drop a listener so the port is closed — the
        // request fails with connection refused.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind probe listener");
        let addr = listener.local_addr().expect("should read local address");
        drop(listener);

        let request = edgezero_core::http::request_builder()
            .uri(format!("http://{addr}/"))
            .body(EdgeBody::empty())
            .expect("should build outbound request");

        let client = AxumPlatformHttpClient::new();
        let pending = client
            .send_async(PlatformHttpRequest::new(request, "failing_backend"))
            .await
            .expect("should spawn async request");

        let result = client
            .select(vec![pending])
            .await
            .expect("select should surface the failure via ready, not a fatal error");

        assert!(
            result.ready.is_err(),
            "request to a closed port should fail"
        );
        assert_eq!(
            result.failed_backend_name.as_deref(),
            Some("failing_backend"),
            "failed provider must be attributed to its backend so the orchestrator can record BidStatus::Error"
        );
        assert!(
            result.remaining.is_empty(),
            "no remaining requests expected"
        );
    }

    async fn serve_raw_response(response: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind raw HTTP test server");
        let addr = listener.local_addr().expect("should read local address");

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("should accept request");
            let mut request = [0; 1024];
            let _ = stream
                .read(&mut request)
                .await
                .expect("should read request");
            stream
                .write_all(response)
                .await
                .expect("should write response");
        });

        format!("http://{addr}/")
    }

    // -----------------------------------------------------------------------
    // Upstream response body cap
    // -----------------------------------------------------------------------

    /// Builds a header map carrying a single `Content-Length`.
    fn content_length_headers(value: usize) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_LENGTH,
            reqwest::header::HeaderValue::from_str(&value.to_string())
                .expect("should build content-length header"),
        );
        headers
    }

    #[test]
    fn content_length_at_the_cap_is_accepted() {
        assert!(
            reject_oversized_content_length(
                &content_length_headers(MAX_PLATFORM_RESPONSE_BODY_BYTES),
                "https://origin.example/asset"
            )
            .is_ok(),
            "a response exactly at the cap must still be served"
        );
    }

    #[test]
    fn content_length_over_the_cap_is_rejected() {
        assert!(
            reject_oversized_content_length(
                &content_length_headers(MAX_PLATFORM_RESPONSE_BODY_BYTES + 1),
                "https://origin.example/asset"
            )
            .is_err(),
            "a declared body one byte over the cap must be refused before it is copied"
        );
    }

    #[test]
    fn missing_content_length_is_accepted() {
        assert!(
            reject_oversized_content_length(
                &reqwest::header::HeaderMap::new(),
                "https://origin.example/asset"
            )
            .is_ok(),
            "a chunked response declares no length, so the post-buffer check is the guard"
        );
    }

    #[test]
    fn buffered_body_at_the_cap_is_accepted() {
        assert!(
            reject_oversized_body(
                MAX_PLATFORM_RESPONSE_BODY_BYTES,
                "https://origin.example/asset"
            )
            .is_ok(),
            "a body exactly at the cap must still be served"
        );
    }

    #[test]
    fn buffered_body_over_the_cap_is_rejected() {
        assert!(
            reject_oversized_body(
                MAX_PLATFORM_RESPONSE_BODY_BYTES + 1,
                "https://origin.example/asset"
            )
            .is_err(),
            "a chunked response over the cap must be refused once buffered"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_client_rejects_an_oversized_declared_response() {
        // 10 MiB + 1, one byte past MAX_PLATFORM_RESPONSE_BODY_BYTES.
        let url = serve_raw_response(
            b"HTTP/1.1 200 OK\r\n\
              Content-Length: 10485761\r\n\
              \r\n",
        )
        .await;

        let request = edgezero_core::http::request_builder()
            .uri(url)
            .body(EdgeBody::empty())
            .expect("should build outbound request");

        let result = AxumPlatformHttpClient::new()
            .send(PlatformHttpRequest::new(request, "test_backend"))
            .await;

        assert!(
            result.is_err(),
            "an origin declaring more than the cap must fail rather than be buffered"
        );
    }
}
