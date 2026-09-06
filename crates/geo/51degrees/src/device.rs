//! Device detection backed by the same 51Degrees cloud answer.
//!
//! Two different questions are answered from one response, and keeping them
//! apart matters more here than anywhere else in this crate.
//!
//! [`DeviceProvider::detect`] answers the gate question, whether this request
//! looks like a real browser, and its answer decides whether an Edge Cookie is
//! written at all. It is infallible by contract, so **a failed call must not be
//! read as a bot**. Doing that would stop identity issuance for every visitor
//! during an outage, silently and with no error anywhere, which is the worst
//! shape this failure can take. So every path here starts from the built-in
//! User-Agent baseline and only improves on it when the service actually
//! answered.
//!
//! [`DeviceProvider::advertising_attributes`] answers the pricing question,
//! what the bidder is being asked to buy. That one is genuinely optional: an
//! absent field is read as unknown, and an invented one misprices the
//! inventory, so nothing is filled unless the service resolved it.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use trusted_server_core::ec::device::{DeviceAttributes, DeviceProvider, DeviceSignals};
use trusted_server_core::evidence::RequestInfo;
use trusted_server_core::platform::RuntimeServices;

use crate::client::{CloudAnswer, CloudClient, Evidence};
use crate::{PROVIDER_ID, usable};

/// Device provider backed by a 51Degrees cloud service.
#[derive(Debug)]
pub struct FiftyOneDegreesDevice {
    client: Arc<CloudClient>,
}

impl FiftyOneDegreesDevice {
    /// Creates a provider sharing one client, and so one call, with the other
    /// providers this crate supplies.
    #[must_use]
    pub const fn new(client: Arc<CloudClient>) -> Self {
        Self { client }
    }
}

/// Builds the evidence key for a request.
///
/// The address is parsed and written back out rather than passed through, so
/// that this key and the geo provider's key are byte-identical for the same
/// visitor. The geo provider builds its key from an [`IpAddr`], and
/// `2001:db8::1` and `2001:0db8:0000::0001` are the same address written two
/// ways. Two spellings would be two cache entries and two calls.
///
/// Shared with the identity provider, which must build the same key or it pays
/// for a second call to learn what the device provider already asked.
#[must_use]
pub fn evidence_for(request_info: &dyn RequestInfo) -> Evidence {
    let raw = request_info.client_ip();
    let client_ip = raw
        .parse::<IpAddr>()
        .map_or_else(|_| raw.to_owned(), |address| address.to_string());
    Evidence {
        client_ip,
        user_agent: request_info.user_agent().to_owned(),
    }
}

/// Reads a string property from the response's `device` element.
fn device_string<'a>(answer: &'a CloudAnswer, name: &str) -> Option<&'a str> {
    let value = answer.element("device")?.get(name)?;
    // A property with more than one value comes back as a list, and the first
    // entry is the most likely one. `HardwareName` is routinely a list of the
    // marketing names one model was sold under.
    let text = match value {
        serde_json::Value::Array(values) => values.first()?.as_str()?,
        other => other.as_str()?,
    };
    usable(Some(text))
}

/// Reads a whole number property from the response's `device` element.
fn device_number(answer: &CloudAnswer, name: &str) -> Option<i32> {
    let value = answer.element("device")?.get(name)?;
    let number = match value {
        serde_json::Value::String(text) => text.parse::<i64>().ok()?,
        other => other.as_i64()?,
    };
    i32::try_from(number).ok()
}

/// Reads a true or false property from the response's `device` element.
fn device_flag(answer: &CloudAnswer, name: &str) -> Option<bool> {
    let value = answer.element("device")?.get(name)?;
    match value {
        serde_json::Value::Bool(flag) => Some(*flag),
        serde_json::Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Maps a platform name onto the coarse family
/// [`DeviceSignals::platform_class`] carries.
///
/// Only the five families that field is documented to hold are mapped.
/// Anything else keeps whatever the User-Agent baseline decided, because a
/// name the gate does not recognize is worse than no name at all.
fn platform_class(name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    if name.contains("android") {
        return Some("android");
    }
    if name.contains("ios") || name.contains("ipados") {
        return Some("ios");
    }
    if name.contains("windows") {
        return Some("windows");
    }
    if name.contains("mac") {
        return Some("mac");
    }
    if name.contains("linux") || name.contains("chrome os") || name.contains("chromeos") {
        return Some("linux");
    }
    None
}

/// Improves the User-Agent baseline with whatever the service resolved.
///
/// Written as a free function taking the baseline so it can be tested without
/// a runtime, which is the only way the browser and bot decision gets tested
/// at all: `detect` needs a live service.
#[must_use]
pub fn signals_from_answer(baseline: DeviceSignals, answer: &CloudAnswer) -> DeviceSignals {
    let mut signals = baseline;

    if let Some(is_mobile) = device_flag(answer, "ismobile") {
        signals.is_mobile = u8::from(is_mobile);
    }

    // A crawler is the one thing the User-Agent heuristic is worst at, since
    // a crawler that wants to be taken for a browser simply says so. This is
    // the answer worth having from the service.
    if let Some(is_crawler) = device_flag(answer, "iscrawler") {
        signals.known_browser = Some(!is_crawler);
        signals.looks_like_browser = !is_crawler;
    }

    if let Some(class) = device_string(answer, "platformname").and_then(platform_class) {
        signals.platform_class = Some(class.to_owned());
    }

    signals
}

/// Builds bid request attributes from the response's `device` element.
///
/// Returns `None` when nothing was resolved, so the caller leaves the device
/// object as it found it rather than writing an empty one.
#[must_use]
pub fn attributes_from_answer(answer: &CloudAnswer) -> Option<DeviceAttributes> {
    let attributes = DeviceAttributes {
        device_type: device_string(answer, "devicetype")
            .and_then(DeviceAttributes::device_type_from_name),
        make: device_string(answer, "hardwarevendor").map(str::to_owned),
        // The model number is the precise answer. The marketing name is the
        // fallback, because a bidder that cannot match a model number can
        // still match a name, and neither is worth inventing.
        model: device_string(answer, "hardwaremodel")
            .or_else(|| device_string(answer, "hardwarename"))
            .map(str::to_owned),
        os: device_string(answer, "platformname").map(str::to_owned),
        os_version: device_string(answer, "platformversion").map(str::to_owned),
        screen_width: device_number(answer, "screenpixelswidth"),
        screen_height: device_number(answer, "screenpixelsheight"),
    };
    if attributes.is_empty() {
        return None;
    }
    Some(attributes)
}

#[async_trait(?Send)]
impl DeviceProvider for FiftyOneDegreesDevice {
    fn id(&self) -> &'static str {
        PROVIDER_ID
    }

    async fn detect(
        &self,
        request_info: &dyn RequestInfo,
        services: &RuntimeServices,
    ) -> DeviceSignals {
        let baseline = DeviceSignals::derive_ua_only(request_info.user_agent());
        let evidence = evidence_for(request_info);
        match self.client.answer(&evidence, services).await {
            Ok(answer) => signals_from_answer(baseline, &answer),
            Err(error) => {
                // Deliberately the baseline rather than a bot verdict. See the
                // module documentation: reading an outage as a bot would stop
                // identity issuance for everyone, with nothing to see.
                log::warn!(
                    "51Degrees device detection failed, falling back to the User-Agent: {error:?}"
                );
                baseline
            }
        }
    }

    async fn advertising_attributes(
        &self,
        request_info: &dyn RequestInfo,
        services: &RuntimeServices,
    ) -> Option<DeviceAttributes> {
        let evidence = evidence_for(request_info);
        match self.client.answer(&evidence, services).await {
            Ok(answer) => attributes_from_answer(&answer),
            Err(error) => {
                log::warn!(
                    "51Degrees device attributes unavailable, the bid request will carry none: {error:?}"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn answer(device: serde_json::Value) -> CloudAnswer {
        let mut body = serde_json::Map::new();
        body.insert("device".to_owned(), device);
        CloudAnswer::new(serde_json::Value::Object(body))
    }

    #[test]
    fn a_resolved_device_fills_the_bid_request_fields() {
        let resolved = attributes_from_answer(&answer(json!({
            "devicetype": "SmartPhone",
            "hardwarevendor": "ExampleCorp",
            "hardwaremodel": "EX-1",
            "platformname": "Android",
            "platformversion": "15.0",
            "screenpixelswidth": 1080,
            "screenpixelsheight": 2400,
        })))
        .expect("a resolved device should produce attributes");

        assert_eq!(resolved.device_type, Some(4), "SmartPhone is a phone");
        assert_eq!(resolved.make.as_deref(), Some("ExampleCorp"));
        assert_eq!(resolved.model.as_deref(), Some("EX-1"));
        assert_eq!(resolved.os.as_deref(), Some("Android"));
        assert_eq!(resolved.os_version.as_deref(), Some("15.0"));
        assert_eq!(resolved.screen_width, Some(1080));
        assert_eq!(resolved.screen_height, Some(2400));
    }

    #[test]
    fn the_services_unknown_spelling_never_reaches_a_bidder() {
        let resolved = attributes_from_answer(&answer(json!({
            "devicetype": "Unknown",
            "hardwarevendor": "Unknown",
            "hardwaremodel": "Unknown",
            "hardwarename": "Unknown",
            "platformname": "Unknown",
            "platformversion": "Unknown",
        })));

        assert!(
            resolved.is_none(),
            "a device the service could not identify must be sent as absent, not as a make called Unknown"
        );
    }

    #[test]
    fn a_hardware_name_list_contributes_its_first_entry() {
        let resolved = attributes_from_answer(&answer(json!({
            "hardwarename": ["Example One", "Example 1"],
        })))
        .expect("a list of names is still a name");

        assert_eq!(
            resolved.model.as_deref(),
            Some("Example One"),
            "one model is sold under several marketing names and the first is the likeliest"
        );
    }

    #[test]
    fn the_model_number_is_preferred_over_the_marketing_name() {
        let resolved = attributes_from_answer(&answer(json!({
            "hardwaremodel": "EX-1",
            "hardwarename": "Example One",
        })))
        .expect("should resolve a model");

        assert_eq!(resolved.model.as_deref(), Some("EX-1"));
    }

    #[test]
    fn screen_sizes_sent_as_strings_are_still_numbers() {
        let resolved = attributes_from_answer(&answer(json!({
            "screenpixelswidth": "1080",
            "screenpixelsheight": "2400",
        })))
        .expect("should resolve a screen size");

        assert_eq!(resolved.screen_width, Some(1080));
        assert_eq!(resolved.screen_height, Some(2400));
    }

    #[test]
    fn a_crawler_is_recognized_even_when_it_claims_to_be_a_browser() {
        let chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                      (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let baseline = DeviceSignals::derive_ua_only(chrome);
        assert!(
            baseline.looks_like_browser,
            "the User-Agent heuristic is taken in by a crawler that claims to be Chrome"
        );

        let improved = signals_from_answer(baseline, &answer(json!({ "iscrawler": true })));

        assert_eq!(improved.known_browser, Some(false));
        assert!(
            !improved.looks_like_browser,
            "the service knows what the User-Agent cannot say, and this is the point of using it"
        );
    }

    #[test]
    fn a_service_that_says_nothing_leaves_the_baseline_alone() {
        let chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                      (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let baseline = DeviceSignals::derive_ua_only(chrome);
        let improved = signals_from_answer(baseline.clone(), &answer(json!({})));

        assert_eq!(
            improved, baseline,
            "an answer with no device element must not downgrade what the User-Agent established"
        );
    }

    #[test]
    fn an_unrecognized_platform_name_does_not_overwrite_the_baseline() {
        let baseline = DeviceSignals::derive_ua_only(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        let improved = signals_from_answer(
            baseline.clone(),
            &answer(json!({ "platformname": "Fictional OS" })),
        );

        assert_eq!(
            improved.platform_class, baseline.platform_class,
            "a family the gate does not know is worse than the one it worked out"
        );
    }

    #[test]
    fn the_platform_families_map_to_the_documented_vocabulary() {
        assert_eq!(platform_class("Android"), Some("android"));
        assert_eq!(platform_class("iOS"), Some("ios"));
        assert_eq!(platform_class("Windows"), Some("windows"));
        assert_eq!(platform_class("macOS"), Some("mac"));
        assert_eq!(platform_class("Mac OS X"), Some("mac"));
        assert_eq!(platform_class("Debian"), None);
    }
}
