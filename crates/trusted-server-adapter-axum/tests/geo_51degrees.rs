//! Round-trip test for the 51Degrees geo provider, through the real adapter.
//!
//! The provider's own unit tests prove that `register` returns a registration
//! declaring a geo provider. That is not the same as proving an adapter can
//! select it, and the difference is where a seam usually turns out to be
//! broken: a crate that compiles, whose tests pass, and that no deployment can
//! actually reach.
//!
//! So this drives `TrustedServerApp::routes_with_registrations` with
//! `[geo] provider = "fiftyone_degrees"` and the crate's own builder, which is
//! exactly what a deployment that wants this vendor does. The router either
//! builds or the selector fails at startup, and the negative case below proves
//! the check is real rather than vacuous.
//!
//! No request is served here and no call is made to a 51Degrees service. This
//! test answers "can an adapter select this provider", which is the question
//! the unit tests cannot answer from inside the crate.

use trusted_server_adapter_axum::app::TrustedServerApp;
use trusted_server_core::settings::Settings;
use trusted_server_geo_51degrees as geo_51degrees;

/// Settings shaped like the adapter's other tests, with `extra` appended.
///
/// The baked-in configuration carries placeholder secrets that deploy
/// validation refuses, so these are written out rather than loaded.
fn settings_with(extra: &str) -> Settings {
    Settings::from_toml(&format!(
        r#"
            [[handlers]]
            path = "^/_ts/admin"
            username = "admin"
            password = "admin-pass"

            [publisher]
            domain = "test-publisher.example.com"
            cookie_domain = ".test-publisher.example.com"
            origin_url = "https://origin.test-publisher.example.com"
            proxy_secret = "geo-51degrees-test-proxy-secret"

            [ec]
            passphrase = "test-secret-key-32-bytes-minimum"

            {extra}
        "#
    ))
    .expect("should parse the test settings")
}

/// Settings that write their own `[ec]` block, which `settings_with` bakes in.
fn settings_selecting_identity(extra: &str) -> Settings {
    Settings::from_toml(&format!(
        r#"
            [[handlers]]
            path = "^/_ts/admin"
            username = "admin"
            password = "admin-pass"

            [publisher]
            domain = "test-publisher.example.com"
            cookie_domain = ".test-publisher.example.com"
            origin_url = "https://origin.test-publisher.example.com"
            proxy_secret = "geo-51degrees-test-proxy-secret"

            [geo]
            provider = "fiftyone_degrees"

            [ec]
            provider = "fiftyone_degrees"

            [ec.providers.fiftyone_degrees]

            [integrations.fiftyone_degrees]
            endpoint = "http://127.0.0.1:8080/api/v4/json"

            {extra}
        "#
    ))
    .expect("should parse the identity test settings")
}

/// The configuration block a deployment writes to use this provider.
///
/// The endpoint is the self-hosted container's documented shape, which carries
/// no key in the path because that image is authorized by license key at
/// start-up.
const PROVIDER_BLOCK: &str = r#"
[geo]
provider = "fiftyone_degrees"

[integrations.fiftyone_degrees]
endpoint = "http://127.0.0.1:8080/api/v4/json"
"#;

#[test]
fn the_selector_resolves_this_vendors_provider_through_the_adapter() {
    let settings = settings_with(PROVIDER_BLOCK);

    let router =
        TrustedServerApp::routes_with_registrations(settings, &[geo_51degrees::builder()], &[]);

    assert!(
        router.is_ok(),
        "an adapter passing this crate's builder must be able to select it with \
         `[geo] provider = \"fiftyone_degrees\"`, otherwise the crate is unreachable \
         from any deployment: {:?}",
        router.err()
    );
}

#[test]
fn naming_the_module_without_supplying_its_builder_fails_at_startup() {
    let settings = settings_with(PROVIDER_BLOCK);

    // The same configuration, with no builder passed. This is the state the
    // adapter is in today, and it is why the test above is worth having: the
    // crate existing is not the same as a deployment being able to use it.
    let router = TrustedServerApp::routes_with_registrations(settings, &[], &[]);

    assert!(
        router.is_err(),
        "a selector naming a module nothing supplies must fail at startup rather \
         than resolve no location quietly, which would look like a working \
         deployment serving every visitor the policy default"
    );
}

#[test]
fn an_endpoint_that_is_not_a_url_stops_the_deployment() {
    let settings = settings_with(
        r#"
[geo]
provider = "fiftyone_degrees"

[integrations.fiftyone_degrees]
endpoint = "not-a-url"
"#,
    );

    let router =
        TrustedServerApp::routes_with_registrations(settings, &[geo_51degrees::builder()], &[]);

    assert!(
        router.is_err(),
        "a bad endpoint must stop the deployment rather than fail on the first visitor"
    );
}

/// The same module supplies the device provider, so the device selector must
/// reach it too.
///
/// Worth its own test rather than folding into the one above, because the two
/// selectors are separate code paths and a module that supplies two providers
/// is exactly where one of them gets forgotten. The device selector is also
/// validated in a different place from the geo selector, so a name that works
/// for one is not evidence about the other.
#[test]
fn the_device_selector_resolves_the_same_vendors_provider() {
    let settings = settings_with(
        r#"
[geo]
provider = "fiftyone_degrees"

[device]
provider = "fiftyone_degrees"

[integrations.fiftyone_degrees]
endpoint = "http://127.0.0.1:8080/api/v4/json"
"#,
    );

    let router =
        TrustedServerApp::routes_with_registrations(settings, &[geo_51degrees::builder()], &[]);

    assert!(
        router.is_ok(),
        "a deployment asking this vendor for device detection as well as location \
         must be able to select both from one module: {:?}",
        router.err()
    );
}

#[test]
fn naming_the_module_for_devices_without_supplying_its_builder_fails_at_startup() {
    // No geo selector here, so the device path is tested on its own. Leaving
    // geo unset without acknowledging it is itself refused, which is why the
    // single-jurisdiction acknowledgement is present rather than a geo
    // provider that would drag the other selector into this test.
    let settings = settings_with(
        r#"
[geo]
assume_single_jurisdiction = true

[device]
provider = "fiftyone_degrees"

[integrations.fiftyone_degrees]
endpoint = "http://127.0.0.1:8080/api/v4/json"
"#,
    );
    assert_eq!(
        settings.device.provider.as_deref(),
        Some("fiftyone_degrees"),
        "the selector must have parsed, or this test proves nothing"
    );

    let router = TrustedServerApp::routes_with_registrations(settings, &[], &[]);

    assert!(
        router.is_err(),
        "a device selector naming a module nothing supplies must stop the deployment          rather than fall back to the User-Agent, which would look like device          detection was working"
    );
}

/// The provider is reachable from the shipped binary, not just from a test
/// that hands the builder over itself.
///
/// Every test above passes the builder explicitly, which proves the seam works
/// and says nothing about whether the running server ever uses it. Before this
/// was checked, it did not: `build_state` composed an empty builder list, so a
/// deployment writing `[geo] provider = "fiftyone_degrees"` was refused at
/// startup by a binary that contained the module.
#[test]
fn the_running_binary_offers_this_vendor_to_a_deployment() {
    let offered = trusted_server_adapter_axum::app::vendor_builder_ids();

    assert!(
        offered.contains(&"fiftyone_degrees"),
        "the adapter must hand this module to the registry for any deployment to          select it, offered: {offered:?}"
    );
}

/// The same module supplies the Edge Cookie provider, so the identity selector
/// must reach it, and an identifier it creates must survive core's read-back
/// unchanged.
///
/// This is the acceptance gate for the seam, and it exists because this project
/// has already shipped the failure it checks for. A vendor identifier was
/// written to the cookie and silently dropped on read-back, because core judged
/// and rewrote it by the built-in HMAC provider's rules. Nothing errored, and
/// every visitor simply looked new on every request.
///
/// So the assertions below are on the three functions core actually uses,
/// driven through the trait object the registry resolved rather than through
/// the concrete type, because a wrapper that forgets to delegate one of them is
/// how the original fault reached production.
#[test]
fn a_51degrees_identifier_survives_core_read_back_verbatim() {
    // A real identifier shape from a live staging response, shortened. The
    // mixed case, the plus and the trailing equals are the parts that break
    // under the built-in rules.
    const IDENTIFIER: &str =
        "v5zpMhSCBhtlg5lPPDsacnjSwVYotOIo-oQd-99fsXtdaBgUAMPyE_fQnVliHW_LlthFKzlO6D";

    let settings = settings_selecting_identity("");

    let registry = trusted_server_core::integrations::IntegrationRegistry::with_registrations(
        &settings,
        &[geo_51degrees::builder()],
    )
    .expect("should build a registry with this vendor registered");

    let provider = registry
        .ec_provider()
        .expect("`[ec] provider = \"fiftyone_degrees\"` should resolve this module's provider");

    let full = trusted_server_core::ec::provider::apply_provider_code(&*provider, IDENTIFIER);

    assert_eq!(
        full,
        format!("51dd~{IDENTIFIER}"),
        "the cookie value should be this provider's registered code and its own value"
    );
    assert!(
        trusted_server_core::ec::provider::provider_owns_id(&*provider, &full),
        "an identifier this provider created must be one core reads back, or every \
         visitor looks new on every request and nothing reports an error"
    );
    // Core keeps the code prefix on the storage key and lets the provider
    // normalize only its own value part, so the key is the whole cookie value
    // and the part that matters is that the value half is untouched.
    let key = trusted_server_core::ec::provider::provider_kv_key(&*provider, &full);
    assert_eq!(
        key, full,
        "the identifier is base64 and case-sensitive, so the storage key must carry \
         the value unchanged rather than lowercased into a collision"
    );
    assert!(
        key.ends_with(IDENTIFIER),
        "the value half of the key must be byte-identical to what the service issued, \
         got {key}"
    );
}

/// The read-back check is not vacuous: an identifier from another provider is
/// refused.
#[test]
fn an_identifier_this_module_did_not_create_is_refused() {
    let settings = settings_selecting_identity("");

    let registry = trusted_server_core::integrations::IntegrationRegistry::with_registrations(
        &settings,
        &[geo_51degrees::builder()],
    )
    .expect("should build a registry with this vendor registered");
    let provider = registry.ec_provider().expect("should resolve the provider");

    let built_in = format!("hmac~{}.abc123", "a".repeat(64));

    assert!(
        !trusted_server_core::ec::provider::provider_owns_id(&*provider, &built_in),
        "another provider's identifier must not be adopted, or two providers would key \
         the same identity graph row from different evidence"
    );
}

/// The identifier also survives the wrapper production puts in front of the
/// provider.
///
/// The round-trip test above drives the provider the registry resolved. The
/// running server does not use that directly: it hands it to core, which wraps
/// it in an internal shared-provider type before anything calls it. A wrapper
/// that forgets to delegate one method is how the original identifier-dropping
/// bug reached production, so the same round trip is asked of the wrapped form.
#[test]
fn the_identifier_survives_the_wrapper_the_running_server_uses() {
    const IDENTIFIER: &str =
        "v5zpMhSCBhtlg5lPPDsacnjSwVYotOIo-oQd-99fsXtdaBgUAMPyE_fQnVliHW_LlthFKzlO6D";

    let settings = settings_selecting_identity("");
    let registry = trusted_server_core::integrations::IntegrationRegistry::with_registrations(
        &settings,
        &[geo_51degrees::builder()],
    )
    .expect("should build a registry with this vendor registered");

    let wrapped = trusted_server_core::ec::provider::build_shared_provider(
        &settings.ec,
        None,
        registry.ec_provider(),
    )
    .expect("the selection should resolve")
    .expect("a named provider should build");

    let full = trusted_server_core::ec::provider::apply_provider_code(&*wrapped, IDENTIFIER);

    assert_eq!(
        full,
        format!("51dd~{IDENTIFIER}"),
        "the wrapper must report the module's own code, not a default"
    );
    assert!(
        trusted_server_core::ec::provider::provider_owns_id(&*wrapped, &full),
        "the wrapper must delegate the module's read-back rule, or the identifier is \
         written and then dropped with nothing to see"
    );
    assert_eq!(
        trusted_server_core::ec::provider::provider_kv_key(&*wrapped, &full),
        full,
        "the wrapper must delegate the module's key rule, or distinct identifiers fold \
         onto one storage key"
    );
}

/// A publisher who locks down their proxy allow list must not lock this module
/// out by omission.
///
/// `proxy.allowed_domains` decides which hosts may be signed, fetched and
/// redirected to. A module missing from it is blocked quietly: the feature
/// stops working and nothing reports an error. So the module declares the host
/// it needs and the composition root adds it, naming the module in the log.
#[test]
fn a_restricted_allow_list_gains_the_host_this_module_needs() {
    let mut settings = settings_selecting_identity(
        r#"
            [proxy]
            allowed_domains = ["cdn.example.com"]
        "#,
    );

    trusted_server_core::integrations::apply_module_proxy_domains(
        &mut settings,
        &[geo_51degrees::builder()],
    )
    .expect("should apply the module declarations");

    assert!(
        settings
            .proxy
            .allowed_domains
            .iter()
            .any(|host| host == "127.0.0.1"),
        "the configured endpoint host must be permitted, or every call this module \
         makes through the first-party proxy is blocked with nothing to see, got {:?}",
        settings.proxy.allowed_domains
    );
    assert!(
        settings
            .proxy
            .allowed_domains
            .iter()
            .any(|host| host == "cdn.example.com"),
        "the operator's own entries must survive"
    );
}

/// An empty allow list is open mode and must be left alone.
///
/// This is the case that would do real damage if it were wrong. Empty means
/// every host is permitted. Adding one entry does not widen the list, it closes
/// it, and every other host the deployment reaches stops working. A deployment
/// in open mode already permits this module, so there is nothing to add.
#[test]
fn an_open_allow_list_is_left_open() {
    let mut settings = settings_selecting_identity("");
    assert!(
        settings.proxy.allowed_domains.is_empty(),
        "this test is about the empty case, so it has to start empty"
    );

    trusted_server_core::integrations::apply_module_proxy_domains(
        &mut settings,
        &[geo_51degrees::builder()],
    )
    .expect("should apply the module declarations");

    assert!(
        settings.proxy.allowed_domains.is_empty(),
        "adding to an empty list closes it, which would block every host this \
         deployment reaches other than the one added, got {:?}",
        settings.proxy.allowed_domains
    );
}

/// The declaration follows the configured endpoint, so a private cloud on the
/// operator's own domain declares that domain rather than the public one.
#[test]
fn the_declared_host_follows_the_configured_endpoint() {
    let mut settings = settings_with(
        r#"
[geo]
provider = "fiftyone_degrees"

[proxy]
allowed_domains = ["cdn.example.com"]

[integrations.fiftyone_degrees]
endpoint = "https://cloud.publisher-group.example/api/v4/json"
"#,
    );

    trusted_server_core::integrations::apply_module_proxy_domains(
        &mut settings,
        &[geo_51degrees::builder()],
    )
    .expect("should apply the module declarations");

    assert!(
        settings
            .proxy
            .allowed_domains
            .iter()
            .any(|host| host == "cloud.publisher-group.example"),
        "a deployment pointing at its own private cloud must declare that host, \
         not the public one, got {:?}",
        settings.proxy.allowed_domains
    );
}

/// A module that declares nothing changes nothing.
#[test]
fn a_module_declaring_no_host_leaves_the_list_untouched() {
    let mut settings = settings_selecting_identity(
        r#"
            [proxy]
            allowed_domains = ["cdn.example.com"]
        "#,
    );

    trusted_server_core::integrations::apply_module_proxy_domains(&mut settings, &[])
        .expect("should apply nothing");

    assert_eq!(
        settings.proxy.allowed_domains,
        vec!["cdn.example.com".to_owned()],
        "no modules means no additions"
    );
}
