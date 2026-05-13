use std::net::IpAddr;
use std::sync::Arc;

use edgezero_core::key_value_store::NoopKvStore;
use error_stack::Report;
use fastly::http::{header, StatusCode};
use fastly::{Request, Response};
use trusted_server_core::auction::build_orchestrator;
use trusted_server_core::integrations::IntegrationRegistry;
use trusted_server_core::platform::{
    ClientInfo, GeoInfo, PlatformBackend, PlatformBackendSpec, PlatformConfigStore, PlatformError,
    PlatformGeo, PlatformHttpClient, PlatformHttpRequest, PlatformKvStore, PlatformPendingRequest,
    PlatformResponse, PlatformSecretStore, PlatformSelectResult, RuntimeServices, StoreId,
    StoreName,
};
use trusted_server_core::request_signing::JWKS_CONFIG_STORE_NAME;
use trusted_server_core::settings::Settings;

use super::route_request;

struct StubJwksConfigStore;

impl PlatformConfigStore for StubJwksConfigStore {
    fn get(&self, _store_name: &StoreName, key: &str) -> Result<String, Report<PlatformError>> {
        match key {
            "active-kids" => Ok("test-kid-1".to_string()),
            "test-kid-1" => Ok(
                r#"{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"test-kid-1","alg":"EdDSA"}"#
                    .to_string(),
            ),
            _ => Err(Report::new(PlatformError::ConfigStore)),
        }
    }

    fn put(
        &self,
        _store_id: &StoreId,
        _key: &str,
        _value: &str,
    ) -> Result<(), Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }

    fn delete(&self, _store_id: &StoreId, _key: &str) -> Result<(), Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }
}

struct NoopSecretStore;

impl PlatformSecretStore for NoopSecretStore {
    fn get_bytes(
        &self,
        _store_name: &StoreName,
        _key: &str,
    ) -> Result<Vec<u8>, Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }

    fn create(
        &self,
        _store_id: &StoreId,
        _name: &str,
        _value: &str,
    ) -> Result<(), Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }

    fn delete(&self, _store_id: &StoreId, _name: &str) -> Result<(), Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }
}

struct NoopBackend;

impl PlatformBackend for NoopBackend {
    fn predict_name(&self, _spec: &PlatformBackendSpec) -> Result<String, Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }

    fn ensure(&self, _spec: &PlatformBackendSpec) -> Result<String, Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }
}

struct NoopHttpClient;

#[async_trait::async_trait(?Send)]
impl PlatformHttpClient for NoopHttpClient {
    async fn send(
        &self,
        _request: PlatformHttpRequest,
    ) -> Result<PlatformResponse, Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }

    async fn send_async(
        &self,
        _request: PlatformHttpRequest,
    ) -> Result<PlatformPendingRequest, Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }

    async fn select(
        &self,
        _pending_requests: Vec<PlatformPendingRequest>,
    ) -> Result<PlatformSelectResult, Report<PlatformError>> {
        Err(Report::new(PlatformError::Unsupported))
    }
}

struct NoopGeo;

impl PlatformGeo for NoopGeo {
    fn lookup(&self, _client_ip: Option<IpAddr>) -> Result<Option<GeoInfo>, Report<PlatformError>> {
        Ok(None)
    }
}

fn create_test_settings() -> Settings {
    create_test_settings_with_consent_store(Some("missing-consent-store"))
}

fn create_test_settings_without_consent_store() -> Settings {
    create_test_settings_with_consent_store(None)
}

fn create_test_settings_with_consent_store(consent_store: Option<&str>) -> Settings {
    let consent_config = consent_store
        .map(|store| format!("\n            [consent]\n            consent_store = \"{store}\"\n"))
        .unwrap_or_default();
    let settings = Settings::from_toml(&format!(
        r#"
            [[handlers]]
            path = "^/admin"
            username = "admin"
            password = "admin-pass"

            [publisher]
            domain = "test-publisher.com"
            cookie_domain = ".test-publisher.com"
            origin_url = "https://origin.test-publisher.com"
            proxy_secret = "unit-test-proxy-secret"

            [edge_cookie]
            secret_key = "test-secret-key"

            [request_signing]
            enabled = false
            config_store_id = "test-config-store-id"
            secret_store_id = "test-secret-store-id"
            {consent_config}
            [integrations.prebid]
            enabled = true
            server_url = "https://test-prebid.com/openrtb2/auction"

            [auction]
            enabled = true
            providers = ["prebid"]
            timeout_ms = 2000
        "#,
    ))
    .expect("should parse adapter route test settings");

    assert_eq!(
        JWKS_CONFIG_STORE_NAME, "jwks_store",
        "should keep the stub discovery store aligned with the production constant"
    );

    settings
}

fn build_route_stack(
    settings: &Settings,
) -> (
    trusted_server_core::auction::AuctionOrchestrator,
    IntegrationRegistry,
) {
    let orchestrator = build_orchestrator(settings).expect("should build auction orchestrator");
    let integration_registry =
        IntegrationRegistry::new(settings).expect("should create integration registry");

    (orchestrator, integration_registry)
}

fn route_with_settings(settings: &Settings, req: Request) -> Option<Response> {
    let (orchestrator, integration_registry) = build_route_stack(settings);
    let runtime_services = test_runtime_services(&req);

    futures::executor::block_on(route_request(
        settings,
        &orchestrator,
        &integration_registry,
        &runtime_services,
        req,
    ))
}

fn test_runtime_services(req: &Request) -> RuntimeServices {
    RuntimeServices::builder()
        .config_store(Arc::new(StubJwksConfigStore))
        .secret_store(Arc::new(NoopSecretStore))
        .kv_store(Arc::new(NoopKvStore) as Arc<dyn PlatformKvStore>)
        .backend(Arc::new(NoopBackend))
        .http_client(Arc::new(NoopHttpClient))
        .geo(Arc::new(NoopGeo))
        .client_info(ClientInfo {
            client_ip: req.get_client_ip_addr(),
            tls_protocol: req.get_tls_protocol().map(str::to_string),
            tls_cipher: req.get_tls_cipher_openssl_name().map(str::to_string),
        })
        .build()
}

#[test]
fn static_tsjs_route_serves_unified_bundle() {
    let settings = create_test_settings();
    let req = Request::get("https://test.com/static/tsjs=tsjs-unified.min.js");

    let mut resp = route_with_settings(&settings, req).expect("should route static tsjs request");

    assert_eq!(
        resp.get_status(),
        StatusCode::OK,
        "should serve the unified static bundle"
    );
    assert_eq!(
        resp.get_header_str(header::CONTENT_TYPE),
        Some("application/javascript; charset=utf-8"),
        "should serve the unified bundle as JavaScript"
    );
    assert!(
        !resp.take_body_str().is_empty(),
        "should serve non-empty unified bundle content"
    );
}

#[test]
fn static_tsjs_route_returns_not_found_for_unknown_bundle() {
    let settings = create_test_settings();
    let req = Request::get("https://test.com/static/tsjs=unknown.js");

    let resp = route_with_settings(&settings, req).expect("should route static tsjs request");

    assert_eq!(
        resp.get_status(),
        StatusCode::NOT_FOUND,
        "should let the static tsjs branch own unknown bundle paths"
    );
}

#[test]
fn discovery_route_is_public() {
    let settings = create_test_settings();
    let req = Request::get("https://test.com/.well-known/trusted-server.json");

    let resp = route_with_settings(&settings, req).expect("should route discovery request");

    assert_eq!(
        resp.get_status(),
        StatusCode::OK,
        "should keep discovery available without authentication"
    );
}

#[test]
fn admin_route_rejects_unauthenticated_request() {
    let settings = create_test_settings();
    let req = Request::post("https://test.com/admin/keys/rotate");

    let resp = route_with_settings(&settings, req).expect("should route admin request");

    assert_eq!(
        resp.get_status(),
        StatusCode::UNAUTHORIZED,
        "should reject unauthenticated admin requests before handler dispatch"
    );
    assert!(
        resp.get_header_str(header::WWW_AUTHENTICATE).is_some(),
        "should advertise the Basic auth challenge"
    );
}

#[test]
fn auction_route_dispatches_to_consent_dependent_path() {
    let settings = create_test_settings();
    let req = Request::post("https://test.com/auction").with_body(r#"{"adUnits":[]}"#);

    let resp = route_with_settings(&settings, req).expect("should route auction request");

    assert_eq!(
        resp.get_status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "should reach the auction route and fail opening configured consent persistence"
    );
}

#[test]
fn unknown_route_falls_back_to_publisher_proxy_path() {
    let settings = create_test_settings_without_consent_store();
    let req = Request::get("https://test.com/articles/example");

    let resp = route_with_settings(&settings, req).expect("should route publisher fallback");

    assert_eq!(
        resp.get_status(),
        StatusCode::BAD_GATEWAY,
        "should reach publisher proxy fallback and fail as an origin proxy error"
    );
}

#[test]
fn configured_missing_consent_store_only_breaks_consent_routes() {
    let settings = create_test_settings();

    let discovery_resp = route_with_settings(
        &settings,
        Request::get("https://test.com/.well-known/trusted-server.json"),
    )
    .expect("should route discovery request");
    assert_eq!(
        discovery_resp.get_status(),
        StatusCode::OK,
        "should keep discovery available when the consent store is unavailable"
    );

    let admin_resp = route_with_settings(
        &settings,
        Request::post("https://test.com/admin/keys/rotate"),
    )
    .expect("should route admin request");
    assert_eq!(
        admin_resp.get_status(),
        StatusCode::UNAUTHORIZED,
        "should keep admin auth behavior unchanged when the consent store is unavailable"
    );

    let auction_resp = route_with_settings(
        &settings,
        Request::post("https://test.com/auction").with_body(r#"{"adUnits":[]}"#),
    )
    .expect("should return an error response for auction requests");
    assert_eq!(
        auction_resp.get_status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "should fail auction requests when consent persistence is configured but unavailable"
    );

    let publisher_resp =
        route_with_settings(&settings, Request::get("https://test.com/articles/example"))
            .expect("should return an error response for publisher fallback");
    assert_eq!(
        publisher_resp.get_status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "should scope consent store failures to the consent-dependent routes"
    );
}
