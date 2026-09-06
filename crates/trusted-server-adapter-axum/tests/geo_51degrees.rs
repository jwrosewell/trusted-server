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
