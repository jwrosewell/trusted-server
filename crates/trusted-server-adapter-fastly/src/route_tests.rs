use std::net::IpAddr;
use std::sync::Arc;

use edgezero_core::key_value_store::NoopKvStore;
use error_stack::Report;
use fastly::http::{header, StatusCode};
use fastly::Request;
use serde_json::json;
use trusted_server_core::auction::{build_orchestrator, AuctionOrchestrator};
use trusted_server_core::constants::{HEADER_X_TS_EC, HEADER_X_TS_EC_FRESH};
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
    let settings = Settings::from_toml(
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

            [consent]
            consent_store = "missing-consent-store"

            [integrations.prebid]
            enabled = true
            server_url = "https://test-prebid.com/openrtb2/auction"

            [auction]
            enabled = true
            providers = ["prebid"]
            timeout_ms = 2000
        "#,
    )
    .expect("should parse adapter route test settings");

    assert_eq!(
        JWKS_CONFIG_STORE_NAME, "jwks_store",
        "should keep the stub discovery store aligned with the production constant"
    );

    settings
}

fn create_auction_test_settings_without_consent_store(providers: &str) -> Settings {
    let config = format!(
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

            [auction]
            enabled = true
            providers = {providers}
            timeout_ms = 2000
        "#,
    );

    Settings::from_toml(&config).expect("should parse adapter auction route test settings")
}

fn build_route_stack(settings: &Settings) -> (AuctionOrchestrator, IntegrationRegistry) {
    let orchestrator = build_orchestrator(settings).expect("should build auction orchestrator");
    let integration_registry =
        IntegrationRegistry::new(settings).expect("should create integration registry");

    (orchestrator, integration_registry)
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

fn route_auction(settings: &Settings, body: impl Into<Vec<u8>>) -> fastly::Response {
    let (orchestrator, integration_registry) = build_route_stack(settings);
    let req = Request::post("https://test.com/auction")
        .with_header(header::CONTENT_TYPE, "application/json")
        .with_body(body.into());
    let services = test_runtime_services(&req);

    futures::executor::block_on(route_request(
        settings,
        &orchestrator,
        &integration_registry,
        &services,
        req,
    ))
    .expect("should route auction request")
}

fn valid_banner_ad_unit_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "adUnits": [
            {
                "code": "div-gpt-ad-1",
                "mediaTypes": {
                    "banner": {
                        "sizes": [[300, 250]]
                    }
                },
                "bids": [
                    {
                        "bidder": "missing-provider",
                        "params": {}
                    }
                ]
            }
        ]
    }))
    .expect("should serialize valid auction route test body")
}

#[test]
fn configured_missing_consent_store_only_breaks_consent_routes() {
    let settings = create_test_settings();
    let orchestrator = build_orchestrator(&settings).expect("should build auction orchestrator");
    let integration_registry =
        IntegrationRegistry::new(&settings).expect("should create integration registry");

    let discovery_req = Request::get("https://test.com/.well-known/trusted-server.json");
    let discovery_services = test_runtime_services(&discovery_req);
    let discovery_resp = futures::executor::block_on(route_request(
        &settings,
        &orchestrator,
        &integration_registry,
        &discovery_services,
        discovery_req,
    ))
    .expect("should route discovery request");
    assert_eq!(
        discovery_resp.get_status(),
        StatusCode::OK,
        "should keep discovery available when the consent store is unavailable"
    );

    let admin_req = Request::post("https://test.com/admin/keys/rotate");
    let admin_services = test_runtime_services(&admin_req);
    let admin_resp = futures::executor::block_on(route_request(
        &settings,
        &orchestrator,
        &integration_registry,
        &admin_services,
        admin_req,
    ))
    .expect("should route admin request");
    assert_eq!(
        admin_resp.get_status(),
        StatusCode::UNAUTHORIZED,
        "should keep admin auth behavior unchanged when the consent store is unavailable"
    );

    let auction_req = Request::post("https://test.com/auction").with_body(r#"{"adUnits":[]}"#);
    let auction_services = test_runtime_services(&auction_req);
    let auction_resp = futures::executor::block_on(route_request(
        &settings,
        &orchestrator,
        &integration_registry,
        &auction_services,
        auction_req,
    ))
    .expect("should return an error response for auction requests");
    assert_eq!(
        auction_resp.get_status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "should fail auction requests when consent persistence is configured but unavailable"
    );

    let publisher_req = Request::get("https://test.com/articles/example");
    let publisher_services = test_runtime_services(&publisher_req);
    let publisher_resp = futures::executor::block_on(route_request(
        &settings,
        &orchestrator,
        &integration_registry,
        &publisher_services,
        publisher_req,
    ))
    .expect("should return an error response for publisher fallback");
    assert_eq!(
        publisher_resp.get_status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "should scope consent store failures to the consent-dependent routes"
    );
}

#[test]
fn malformed_auction_json_returns_bad_request() {
    let settings = create_auction_test_settings_without_consent_store(r#"["missing-provider"]"#);

    let mut response = route_auction(&settings, "{not-json");

    assert_eq!(
        response.get_status(),
        StatusCode::BAD_REQUEST,
        "should reject malformed JSON as a client request error"
    );
    assert!(
        response.take_body_str().contains("Bad request"),
        "should return a client-facing bad request message"
    );
}

#[test]
fn invalid_auction_banner_size_returns_bad_request() {
    let settings = create_auction_test_settings_without_consent_store(r#"["missing-provider"]"#);
    let body = serde_json::to_vec(&json!({
        "adUnits": [
            {
                "code": "div-gpt-ad-1",
                "mediaTypes": {
                    "banner": {
                        "sizes": [[300]]
                    }
                }
            }
        ]
    }))
    .expect("should serialize invalid auction route test body");

    let response = route_auction(&settings, body);

    assert_eq!(
        response.get_status(),
        StatusCode::BAD_REQUEST,
        "should reject semantically invalid banner sizes as a client request error"
    );
}

#[test]
fn valid_auction_request_with_no_providers_returns_bad_gateway() {
    let settings = create_auction_test_settings_without_consent_store("[]");

    let response = route_auction(&settings, valid_banner_ad_unit_body());

    assert_eq!(
        response.get_status(),
        StatusCode::BAD_GATEWAY,
        "should surface no-provider orchestration failures as gateway errors"
    );
}

#[test]
fn valid_auction_request_with_unregistered_provider_returns_success_empty_openrtb_response() {
    let settings = create_auction_test_settings_without_consent_store(r#"["missing-provider"]"#);

    let mut response = route_auction(&settings, valid_banner_ad_unit_body());

    assert_eq!(
        response.get_status(),
        StatusCode::OK,
        "should produce a successful empty OpenRTB response when configured providers are skipped"
    );
    assert_eq!(
        response.get_header_str(header::CONTENT_TYPE),
        Some("application/json"),
        "should return JSON for successful auction responses"
    );
    assert!(
        response.get_header_str(HEADER_X_TS_EC).is_some(),
        "should include the auction EC identifier header"
    );
    assert!(
        response.get_header_str(HEADER_X_TS_EC_FRESH).is_some(),
        "should include the fresh EC identifier header"
    );

    let body: serde_json::Value = serde_json::from_str(&response.take_body_str())
        .expect("should parse successful auction response JSON");
    assert!(
        body.get("id").and_then(serde_json::Value::as_str).is_some(),
        "should include an OpenRTB response id"
    );
    assert!(
        body.get("seatbid")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty),
        "should not include bid entries when there are no bids"
    );
    assert!(
        body.pointer("/ext/orchestrator/strategy")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "should include orchestrator strategy metadata"
    );
    assert_eq!(
        body.pointer("/ext/orchestrator/providers")
            .and_then(serde_json::Value::as_u64),
        Some(0),
        "should report no provider responses"
    );
    assert_eq!(
        body.pointer("/ext/orchestrator/total_bids")
            .and_then(serde_json::Value::as_u64),
        Some(0),
        "should report no bids"
    );
    assert!(
        body.pointer("/ext/orchestrator/time_ms")
            .and_then(serde_json::Value::as_u64)
            .is_some(),
        "should include orchestration timing metadata"
    );
}
