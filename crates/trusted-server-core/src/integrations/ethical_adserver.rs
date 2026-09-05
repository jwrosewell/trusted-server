//! Ethical Ad Server (EAS) auction mediator.
//!
//! Calls the Ethical Ad Server decision API for a direct-sold ad, compares its
//! effective CPM against the programmatic bids the orchestrator has already
//! collected, and returns one winning bid per slot.
//!
//! EAS is a Django ad server and its decision API is not `OpenRTB`. The
//! server-to-server entry point is `POST /api/v1/decision/`. It takes a
//! publisher slug and a list of candidate placements, each a `div_id` plus an
//! ad type slug, and returns at most one ad. There is no width or height in
//! the decision input, so the appliance maps each auction slot onto an EAS
//! placement through configuration. See [`EthicalAdServerConfig`] for that
//! mapping.
//!
//! Three details of that API shape the code below and are easy to get wrong.
//! The request body must be `application/json`, because the ad server
//! installs only the JSON parser and answers a form-encoded body with HTTP
//! 415. The click URL arrives in `link`, and there is no field named
//! `click_url`. A decision that fills nothing is HTTP 200 with an empty JSON
//! object rather than an error, and the ad server sends that same empty
//! object for an ad type slug it does not recognize, because it does not
//! validate the slug against its own database.
//!
//! # Rendering and tracking
//!
//! A winning decision is only worth something if the appliance stays in the
//! path between the reader and the ad server, and that is wiring outside this
//! module which an operator has to get right.
//!
//! The markup must be rewritten by
//! [`crate::creative::CreativeHtmlProcessor`], which points the view pixel at
//! `/first-party/proxy` and the anchor at `/first-party/click`. Without that
//! rewrite the browser fetches the pixel from the ad server
//! directly and the appliance is not involved at all. The click must keep
//! going to `/first-party/click` and never to `/first-party/proxy`, because
//! the proxy path would follow the ad server's redirect and serve the
//! advertiser's landing page under the publisher's own origin with no change
//! in the address bar.
//!
//! `proxy.allowed_domains` must also name the ad server's host, or be left
//! empty for open mode. An operator who fills that list without the ad server
//! in it gets no tracking and no error to explain it.
//!
//! The third tracking URL, `view_time_url`, is deliberately not put on the
//! bid. It cannot bill, since its ignore check returns nothing at all
//! (`adserver/views.py`, `AdViewTimeProxyView.ignore_tracking_reason`) and it
//! only writes a view duration, and it cannot work through the appliance
//! either, because the duration has to arrive as a query parameter and every
//! query parameter sits inside the signed token, so a browser that appends one
//! invalidates the token.
//!
//! Arbitration happens here rather than at the ad server, because EAS has no
//! concept of an incoming bid and the programmatic prices are never sent
//! upstream. Slots that EAS does not fill keep their best programmatic bid,
//! since the orchestrator builds its winning-bid set only from the bids a
//! mediator returns.
//!
//! This provider never returns an error from response parsing. On the
//! synchronous mediation path a parse error is propagated with `?` and aborts
//! the whole auction, which would blank every slot because an ad server call
//! failed. Every upstream fault therefore degrades to the programmatic
//! pass-through and is logged.

use async_trait::async_trait;
use edgezero_core::body::Body as EdgeBody;
use error_stack::{Report, ResultExt};
use http::{Method, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use validator::{Validate, ValidationError};

use crate::auction::context::{ContextQueryParams, build_url_with_context_params};
use crate::auction::provider::{AuctionProvider, ProviderRequestOutcome};
use crate::auction::types::{
    AuctionContext, AuctionRequest, AuctionResponse, Bid, BidStatus, MediaType,
};
use crate::error::TrustedServerError;
use crate::integrations::{
    UPSTREAM_RTB_MAX_RESPONSE_BYTES, collect_response_bounded,
    ensure_integration_backend_with_timeout, predict_integration_backend_name,
};
use crate::platform::{PlatformHttpRequest, PlatformResponse, RuntimeServices, StoreName};
use crate::redacted::Redacted;
use crate::settings::{IntegrationConfig, Settings};

// ============================================================================
// Configuration
// ============================================================================

/// Integration id the Ethical Ad Server provider is configured under.
const ETHICAL_ADSERVER_INTEGRATION_ID: &str = "ethical_adserver";

/// Provider name reported to the orchestrator and used in log lines.
const PROVIDER_NAME: &str = "ethical_adserver";

/// Currency of every price the Ethical Ad Server quotes.
///
/// EAS has no currency field on a flight or a publisher and bills in US
/// dollars (`adserver/models.py` passes a hard-coded `currency="USD"` to
/// Stripe with amounts "in US cents"), so a decision price is always USD.
const EAS_CURRENCY: &str = "USD";

/// Nonce the ad server sends for a decision it was forced to make.
///
/// A decision forced to one advertisement or campaign on a paid campaign is
/// deliberately never billed: the ad server throws away the real offer id so
/// that the view and the click cannot be counted (`adserver/models.py`, in
/// `offer_ad`). The value repeats across offers, so it does not identify one.
const FORCED_NONCE: &str = "forced";

/// Longest rejected-decision body written to the log.
const MAX_ERROR_DETAIL_CHARS: usize = 256;

/// Lowest placement priority the decision API accepts.
const MIN_PLACEMENT_PRIORITY: u8 = 1;

/// Highest placement priority the decision API accepts.
const MAX_PLACEMENT_PRIORITY: u8 = 10;

/// Reference to an API token held in a platform secret store.
///
/// The decision API requires authentication unless the publisher has
/// `unauthed_ad_decisions` set, and it authenticates with a Django REST
/// Framework token sent as `Authorization: Token <value>`. The token is a
/// credential, so it is read from the secret store at request time and never
/// held in the operator's configuration file.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct EthicalAdServerToken {
    /// Name of the secret store holding the token.
    #[validate(length(min = 1))]
    pub secret_store: String,

    /// Key the token is stored under.
    #[validate(length(min = 1))]
    pub secret_name: String,
}

/// Placement configuration for one auction slot.
///
/// The decision API has no width or height, so a slot is described by the ad
/// type slug offered for it and the `div_id` the response echoes back.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EthicalAdServerSlot {
    /// EAS ad type slug offered for this slot, for example `image-v1`.
    pub ad_type: String,

    /// `div_id` sent to EAS and echoed in the decision response.
    ///
    /// Defaults to the auction slot id. Set it only when the ad server is
    /// configured against different placement ids from the auction's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub div_id: Option<String>,

    /// Placement priority, 1 (lowest) to 10 (highest).
    ///
    /// EAS returns one ad for the whole request, so priority decides which
    /// placement it fills when more than one is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,

    /// Creative width stamped onto a winning EAS bid.
    ///
    /// Defaults to the width of the slot's banner format in the auction
    /// request. Set it when the ad type renders at a different size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,

    /// Creative height stamped onto a winning EAS bid.
    ///
    /// Defaults to the height of the slot's banner format in the auction
    /// request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

/// Configuration for the Ethical Ad Server mediator.
///
/// A minimal deployment names the decision endpoint, the publisher slug, and
/// the ad type offered for each slot:
///
/// ```toml
/// [integrations.ethical_adserver]
/// enabled = true
/// endpoint = "https://adserver.example.com/api/v1/decision/"
/// publisher = "example-publisher"
/// user_agent = "trusted-server/1.0 +examplepublisher"
///
/// [integrations.ethical_adserver.slots.header-banner]
/// ad_type = "ts-server-side-tpl-v1"
/// priority = 10
///
/// [integrations.ethical_adserver.ad_types_by_format]
/// "300x250" = "ts-server-side-tpl-v1"
/// ```
///
/// Name an ad type whose template renders the advertisement itself. The ad
/// server ships a default template that renders the view pixel alone for a
/// headline, content and call-to-action advertisement, and a slot won with
/// that markup would carry nothing a reader can see. See [`read_creative`]
/// for how a decision with no creative in its `html` is handled.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct EthicalAdServerConfig {
    /// Whether this integration is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Decision API endpoint, for example
    /// `https://adserver.example.com/api/v1/decision/`.
    #[validate(url)]
    pub endpoint: String,

    /// Publisher slug the decision is made for.
    #[validate(length(min = 1))]
    pub publisher: String,

    /// Timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    #[validate(range(min = 1, max = 60000))]
    pub timeout_ms: u32,

    /// `User-Agent` identifying this caller to the ad server.
    ///
    /// The decision API asks server-to-server callers to identify themselves
    /// in the `User-Agent`, for example `python-requests/2.26.0
    /// +YOURPUBLISHER`. The end user's own agent travels separately in
    /// `user_ua`. Replace the default with a value naming the publisher.
    #[serde(default = "default_user_agent")]
    #[validate(length(min = 1))]
    pub user_agent: String,

    /// Secret-store reference for the decision API token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub api_token: Option<EthicalAdServerToken>,

    /// Minimum effective CPM the ad server must clear to be considered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_floor: Option<f64>,

    /// Campaign types the decision is limited to, for example `paid`.
    ///
    /// Empty means the field is omitted and the ad server applies its own
    /// publisher settings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub campaign_types: Vec<String>,

    /// Keywords describing the page, used by the ad server for targeting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,

    /// Per-slot placement mapping, keyed by auction slot id.
    #[serde(default)]
    #[validate(custom(function = "validate_slot_placements"))]
    pub slots: BTreeMap<String, EthicalAdServerSlot>,

    /// Fallback ad type by banner format, keyed `"<width>x<height>"`.
    ///
    /// Used for a slot with no entry in [`slots`](Self::slots), so a
    /// deployment can map by creative size instead of naming every slot.
    #[serde(default)]
    #[validate(custom(function = "validate_format_ad_types"))]
    pub ad_types_by_format: BTreeMap<String, String>,

    /// Mapping from auction-request context keys to query-parameter names,
    /// so integration-supplied data reaches the decision endpoint without
    /// hard-coding integration knowledge here.
    #[serde(default)]
    pub context_query_params: ContextQueryParams,
}

fn default_enabled() -> bool {
    false
}

fn default_timeout_ms() -> u32 {
    500
}

fn default_user_agent() -> String {
    "trusted-server/1.0 +unconfigured".to_string()
}

/// Rejects a slot mapping with an empty ad type or an out-of-range priority.
fn validate_slot_placements(
    slots: &BTreeMap<String, EthicalAdServerSlot>,
) -> Result<(), ValidationError> {
    for (slot_id, slot) in slots {
        if slot_id.trim().is_empty() || slot.ad_type.trim().is_empty() {
            return Err(ValidationError::new("invalid_ethical_adserver_slot"));
        }
        if let Some(priority) = slot.priority
            && !(MIN_PLACEMENT_PRIORITY..=MAX_PLACEMENT_PRIORITY).contains(&priority)
        {
            return Err(ValidationError::new("invalid_ethical_adserver_priority"));
        }
    }
    Ok(())
}

/// Rejects a format mapping whose key is not `"<width>x<height>"` or whose ad
/// type is empty.
fn validate_format_ad_types(formats: &BTreeMap<String, String>) -> Result<(), ValidationError> {
    for (format, ad_type) in formats {
        if ad_type.trim().is_empty() || parse_format_key(format).is_none() {
            return Err(ValidationError::new("invalid_ethical_adserver_format"));
        }
    }
    Ok(())
}

/// Ad type slug the decision API silently renames on the way in.
///
/// The placement serializer rewrites this one legacy slug before the decision
/// is made, so the `display_type` echoed back is the new name and not the one
/// that was sent (`adserver/api/serializers.py`, `validate_ad_type`).
const RENAMED_AD_TYPE: (&str, &str) = ("text-only-large-v1", "logo-large-v1");

/// Resolves an ad type slug to the name the decision API reports it under.
fn canonical_ad_type(slug: &str) -> &str {
    if slug == RENAMED_AD_TYPE.0 {
        RENAMED_AD_TYPE.1
    } else {
        slug
    }
}

/// Parses a `"<width>x<height>"` format key into its dimensions.
fn parse_format_key(format: &str) -> Option<(u32, u32)> {
    let (width, height) = format.split_once('x')?;
    Some((width.parse().ok()?, height.parse().ok()?))
}

/// Reads the visitor's own `User-Agent` out of an auction request.
///
/// This is the end user's agent, which the decision API takes in `user_ua`.
/// It is never the appliance's own identifying agent, which travels in the
/// HTTP `User-Agent` header of the same call. Confusing the two makes every
/// impression the ad server offers unbillable.
fn visitor_user_agent(request: &AuctionRequest) -> Option<&str> {
    request
        .device
        .as_ref()
        .and_then(|device| device.user_agent.as_deref())
        .map(str::trim)
        .filter(|agent| !agent.is_empty())
}

/// Reads the visitor's own address out of an auction request.
fn visitor_ip(request: &AuctionRequest) -> Option<&str> {
    request
        .device
        .as_ref()
        .and_then(|device| device.ip.as_deref())
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
}

/// Builds the `"<width>x<height>"` key for a banner format.
fn format_key(width: u32, height: u32) -> String {
    format!("{width}x{height}")
}

impl Default for EthicalAdServerConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            endpoint: "https://adserver.example.com/api/v1/decision/".to_string(),
            publisher: "example-publisher".to_string(),
            timeout_ms: default_timeout_ms(),
            user_agent: default_user_agent(),
            api_token: None,
            price_floor: None,
            campaign_types: Vec::new(),
            keywords: Vec::new(),
            slots: BTreeMap::new(),
            ad_types_by_format: BTreeMap::new(),
            context_query_params: BTreeMap::new(),
        }
    }
}

impl IntegrationConfig for EthicalAdServerConfig {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ============================================================================
// Domain types
// ============================================================================

/// Effective cost per mille, the only price an auction can compare.
///
/// Always positive and finite, so a zero or absent ad server price can never
/// be mistaken for a bid of zero.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, derive_more::Display)]
pub struct Ecpm(f64);

impl Ecpm {
    /// Creates an effective CPM, rejecting a value that is not positive and
    /// finite.
    #[must_use]
    pub fn new(value: f64) -> Option<Self> {
        if value.is_finite() && value > 0.0 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the effective CPM as a plain number.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }
}

/// Why an ad server decision carries no CPM-comparable price.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum NoPrice {
    /// The flight is priced per click and the response carries no `ecpm`.
    ///
    /// A cost-per-click flight quotes `cpc` and never `cpm`, a flight may not
    /// carry both (`adserver/forms.py`, `FlightMixin.clean`), and the
    /// decision response has no click-through rate, so there is nothing to
    /// convert the cost per click into an effective CPM with. That is an
    /// absence of comparable demand rather than a fault, so it is reported at
    /// debug level.
    CostPerClick,
    /// The response carries no price field at all.
    ///
    /// One publisher setting, `send_bid_rate`, gates every price the ad
    /// server sends, `cpm`, `cpc` and `ecpm` alike (`adserver/models.py`, in
    /// `offer_ad`), so a deployment that leaves it unset can never win an
    /// arbitration however much demand it has. That is a configuration fault
    /// an operator can fix, so it is reported at warning level, unlike a
    /// decision that simply fills nothing.
    NoPriceField,
}

/// One auction slot resolved onto an EAS placement.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SlotPlacement {
    /// Auction slot this placement stands for.
    slot_id: String,
    /// `div_id` sent to and echoed by the ad server.
    div_id: String,
    /// EAS ad type slug offered for the slot.
    ad_type: String,
    /// Placement priority, when configured.
    priority: Option<u8>,
    /// Width stamped onto a winning bid.
    width: u32,
    /// Height stamped onto a winning bid.
    height: u32,
}

/// The fields of an ad server decision this provider uses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AdDecision {
    /// Advertisement slug, the decision's `id`.
    ad_slug: String,
    /// `div_id` echoed from the placement that was filled.
    div_id: Option<String>,
    /// Rendered ad markup.
    creative: Option<String>,
    /// Domain of the advertiser's landing page.
    ///
    /// The ad server takes it from the advertisement's own destination URL
    /// and not from the click proxy in `link`, so it is the domain an
    /// `adomain` is expected to name.
    link_domain: Option<String>,
    /// Single-use nonce identifying this offer.
    nonce: Option<String>,
    /// Tracking and provenance fields surfaced to the caller verbatim.
    tracking: BTreeMap<String, String>,
}

/// Best programmatic bid for each slot, keyed by slot id.
type ProgrammaticWinners = HashMap<String, Bid>;

/// Selects the highest priced bid per slot from the orchestrator's bidder
/// responses.
///
/// Only successful responses with a decoded numeric price take part, matching
/// the orchestrator's own rule that a bid without a price cannot win.
fn best_programmatic_bids(responses: &[AuctionResponse]) -> ProgrammaticWinners {
    let mut winners = ProgrammaticWinners::new();
    for response in responses.iter().filter(|r| r.status == BidStatus::Success) {
        for bid in &response.bids {
            let Some(price) = bid.price else {
                log::debug!(
                    "{PROVIDER_NAME}: ignoring bid from '{}' for slot '{}' without a decoded price",
                    response.provider,
                    bid.slot_id
                );
                continue;
            };
            let beats_current = winners
                .get(&bid.slot_id)
                .and_then(|current: &Bid| current.price)
                .is_none_or(|current| price > current);
            if beats_current {
                winners.insert(bid.slot_id.clone(), bid.clone());
            }
        }
    }
    winners
}

/// Builds the mediator response that hands every slot back to its best
/// programmatic bid.
///
/// Bids are ordered by slot id so the response is stable across runs.
fn pass_through(winners: ProgrammaticWinners, response_time_ms: u64) -> AuctionResponse {
    let mut bids: Vec<Bid> = winners.into_values().collect();
    bids.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));

    if bids.is_empty() {
        AuctionResponse::no_bid(PROVIDER_NAME, response_time_ms)
    } else {
        AuctionResponse::success(PROVIDER_NAME, bids, response_time_ms)
    }
}

/// Renders a rejected decision's body for a log line.
///
/// A rejected decision carries the reason in its body, for example
/// `{"publisher":["Invalid publisher"]}` for a slug the ad server does not
/// know, and without it an operator sees only a status code. The text is
/// trimmed to [`MAX_ERROR_DETAIL_CHARS`] so a large error page cannot flood
/// the log, and the ad server's validation messages name the field that was
/// rejected without echoing the value that was sent.
fn error_detail(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.is_empty() {
        return "no body".to_string();
    }
    match text.char_indices().nth(MAX_ERROR_DETAIL_CHARS) {
        Some((index, _)) => format!("{}...", &text[..index]),
        None => text.to_string(),
    }
}

/// Reads a price that the ad server may send as a JSON number or a string.
///
/// Django REST Framework renders a `Decimal` as a number under the ad
/// server's `COERCE_DECIMAL_TO_STRING = False` setting, but a proxy between
/// the appliance and the ad server may stringify it, so both are accepted.
fn read_price(value: Option<&Json>) -> Option<f64> {
    match value? {
        Json::Number(number) => number.as_f64(),
        Json::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Reads the CPM-comparable price from a decision.
///
/// `ecpm` wins when the ad server sends one, since only the ad server can
/// turn a cost per click into an effective CPM. Otherwise a cost-per-mille
/// flight's `cpm` is used directly and a cost-per-click flight has no
/// comparable price. All three fields are gated on the same publisher
/// setting, so a response with none of them says nothing about the flight.
///
/// # Errors
///
/// Returns [`NoPrice`] describing why the decision cannot be compared: the
/// flight is priced per click, or the response carries no price at all.
fn decision_ecpm(decision: &Json) -> Result<Ecpm, NoPrice> {
    if let Some(ecpm) = read_price(decision.get("ecpm")).and_then(Ecpm::new) {
        return Ok(ecpm);
    }
    if let Some(cpm) = read_price(decision.get("cpm")).and_then(Ecpm::new) {
        return Ok(cpm);
    }
    if read_price(decision.get("cpc")).is_some() {
        return Err(NoPrice::CostPerClick);
    }
    Err(NoPrice::NoPriceField)
}

/// Picks the markup to render out of a decision.
///
/// The ad server sends the creative twice. `text` is always the advertisement
/// wrapped in its click anchor. `html` is the ad type's own Django template
/// rendered, which additionally carries the view pixel, so it is the better
/// markup when a deployment has set a template up.
///
/// The ad server's default template cannot be trusted to carry the creative.
/// Its words sit behind a check on the obsolete `Advertisement.text` column,
/// which is blank on any modern headline, content and call-to-action
/// advertisement, and its pixel sits in the `else` branch of the image check.
/// A stock deployment therefore returns an `html` holding the pixel alone with
/// no words in it at all, and winning a slot with that markup would put an
/// invisible advertisement on the page.
///
/// `html` is used only when it links to the advertisement, which every
/// renderable creative does and the pixel-only markup does not. Anything else
/// falls back to `text` and says so at warning level, because an operator who
/// meant to configure a template needs to hear that it is not being used.
fn read_creative(decision: &Json, ad_slug: &str, click_url: Option<&str>) -> Option<String> {
    let html = decision
        .get("html")
        .and_then(Json::as_str)
        .filter(|markup| !markup.is_empty());
    let text = decision
        .get("text")
        .and_then(Json::as_str)
        .filter(|markup| !markup.is_empty());

    if let (Some(html), Some(click_url)) = (html, click_url)
        && html.contains(click_url)
    {
        return Some(html.to_string());
    }

    if html.is_some() {
        log::warn!(
            "{PROVIDER_NAME}: decision '{ad_slug}' sent `html` that does not link to the advertisement, so its ad type template renders no creative, so `text` is used instead"
        );
    }

    text.map(String::from)
}

/// Copies a decision string field into `tracking` when it is present and not
/// empty.
fn record_tracking_field(tracking: &mut BTreeMap<String, String>, decision: &Json, key: &str) {
    if let Some(value) = decision.get(key).and_then(Json::as_str)
        && !value.is_empty()
    {
        tracking.insert(key.to_string(), value.to_string());
    }
}

/// Reads the fields this provider uses out of a decision response.
///
/// Returns `None` for the empty object the ad server sends when it has no ad
/// to offer, and for a response with no advertisement slug.
fn read_decision(decision: &Json) -> Option<AdDecision> {
    let object = decision.as_object()?;
    if object.is_empty() {
        return None;
    }

    let ad_slug = object
        .get("id")
        .and_then(Json::as_str)
        .filter(|slug| !slug.is_empty())?
        .to_string();

    // The tracking URLs and the nonce are surfaced verbatim under the ad
    // server's own field names, `link` being the click URL. This provider
    // never fetches them: firing a view or a click is the tracking path's
    // job, and putting `view_url` in the bid's `nurl` would have the render
    // bridge fire it on sight.
    // `view_time_url` is left out on purpose. It can neither bill nor survive
    // the appliance's signed token, so putting it here would only invite
    // somebody to route it. The module documentation says why in full.
    let mut tracking = BTreeMap::new();
    for key in [
        "view_url",
        "link",
        "nonce",
        "link_domain",
        "display_type",
        "campaign_type",
    ] {
        record_tracking_field(&mut tracking, decision, key);
    }

    let creative = read_creative(decision, &ad_slug, tracking.get("link").map(String::as_str));

    Some(AdDecision {
        ad_slug,
        div_id: object
            .get("div_id")
            .and_then(Json::as_str)
            .filter(|div_id| !div_id.is_empty())
            .map(String::from),
        creative,
        link_domain: object
            .get("link_domain")
            .and_then(Json::as_str)
            .filter(|domain| !domain.is_empty())
            .map(String::from),
        nonce: object
            .get("nonce")
            .and_then(Json::as_str)
            .filter(|nonce| !nonce.is_empty())
            .map(String::from),
        tracking,
    })
}

// ============================================================================
// Provider
// ============================================================================

/// Ethical Ad Server mediator provider.
pub struct EthicalAdServerProvider {
    config: EthicalAdServerConfig,
}

impl EthicalAdServerProvider {
    /// Creates a new Ethical Ad Server provider.
    #[must_use]
    pub fn new(config: EthicalAdServerConfig) -> Self {
        Self { config }
    }

    /// Builds the decision endpoint URL, appending context values as query
    /// parameters according to the `context_query_params` mapping.
    fn build_endpoint_url(&self, request: &AuctionRequest) -> String {
        build_url_with_context_params(
            &self.config.endpoint,
            &request.context,
            &self.config.context_query_params,
        )
    }

    /// Resolves the EAS placements for the slots in `request`.
    ///
    /// A slot is offered when configuration names an ad type for it, either
    /// directly under `slots` or through `ad_types_by_format` for its banner
    /// size. A slot with no resolvable size is skipped, because a bid with no
    /// dimensions cannot be rendered.
    fn placements_for_request(&self, request: &AuctionRequest) -> Vec<SlotPlacement> {
        let mut placements = Vec::new();

        for slot in &request.slots {
            let banner = slot
                .formats
                .iter()
                .find(|format| format.media_type == MediaType::Banner);

            let configured = self.config.slots.get(&slot.id);
            let ad_type = match configured {
                Some(config) => config.ad_type.clone(),
                None => {
                    let Some(banner) = banner else {
                        log::debug!(
                            "{PROVIDER_NAME}: slot '{}' has no banner format and no slot mapping, skipping",
                            slot.id
                        );
                        continue;
                    };
                    let key = format_key(banner.width, banner.height);
                    let Some(ad_type) = self.config.ad_types_by_format.get(&key) else {
                        log::debug!(
                            "{PROVIDER_NAME}: slot '{}' ({key}) has no configured ad type, skipping",
                            slot.id
                        );
                        continue;
                    };
                    ad_type.clone()
                }
            };

            let width = configured
                .and_then(|config| config.width)
                .or_else(|| banner.map(|format| format.width))
                .unwrap_or(0);
            let height = configured
                .and_then(|config| config.height)
                .or_else(|| banner.map(|format| format.height))
                .unwrap_or(0);
            if width == 0 || height == 0 {
                log::debug!(
                    "{PROVIDER_NAME}: slot '{}' resolves to {width}x{height}, skipping",
                    slot.id
                );
                continue;
            }

            placements.push(SlotPlacement {
                slot_id: slot.id.clone(),
                div_id: configured
                    .and_then(|config| config.div_id.clone())
                    .unwrap_or_else(|| slot.id.clone()),
                ad_type,
                priority: configured.and_then(|config| config.priority),
                width,
                height,
            });
        }

        placements
    }

    /// Resolves placements from configuration alone.
    ///
    /// Serves the context-less parse path, where the auction request is not
    /// available, so only a slot whose configuration carries an explicit
    /// width and height can be resolved.
    fn placements_from_config(&self) -> Vec<SlotPlacement> {
        self.config
            .slots
            .iter()
            .filter_map(|(slot_id, config)| {
                let (Some(width), Some(height)) = (config.width, config.height) else {
                    log::debug!(
                        "{PROVIDER_NAME}: slot '{slot_id}' has no configured size, skipping"
                    );
                    return None;
                };
                Some(SlotPlacement {
                    slot_id: slot_id.clone(),
                    div_id: config.div_id.clone().unwrap_or_else(|| slot_id.clone()),
                    ad_type: config.ad_type.clone(),
                    priority: config.priority,
                    width,
                    height,
                })
            })
            .collect()
    }

    /// Builds the decision request body for the given placements.
    ///
    /// The end user's address and agent travel in `user_ip` and `user_ua`, as
    /// the decision API asks, and are taken from the auction request's device
    /// information rather than from the incoming HTTP request: a mediator runs
    /// after dispatch, where the context carries a placeholder request instead
    /// of the client's own headers.
    fn build_decision_request(
        &self,
        request: &AuctionRequest,
        placements: &[SlotPlacement],
    ) -> Json {
        let placements_json: Vec<Json> = placements
            .iter()
            .map(|placement| {
                let mut entry = json!({
                    "div_id": placement.div_id,
                    "ad_type": placement.ad_type,
                });
                if let Some(priority) = placement.priority
                    && let Some(object) = entry.as_object_mut()
                {
                    object.insert("priority".to_string(), json!(priority));
                }
                entry
            })
            .collect();

        let mut body = json!({
            "publisher": self.config.publisher,
            "placements": placements_json,
        });

        let Some(object) = body.as_object_mut() else {
            return body;
        };

        if !self.config.keywords.is_empty() {
            object.insert("keywords".to_string(), json!(self.config.keywords));
        }
        if !self.config.campaign_types.is_empty() {
            object.insert(
                "campaign_types".to_string(),
                json!(self.config.campaign_types),
            );
        }
        if let Some(page_url) = request.publisher.page_url.as_ref() {
            object.insert("url".to_string(), json!(page_url));
        }
        // The visitor's own agent, never the appliance's. The appliance
        // names itself in the HTTP `User-Agent` header instead.
        if let Some(user_agent) = visitor_user_agent(request) {
            object.insert("user_ua".to_string(), json!(user_agent));
        }
        match visitor_ip(request) {
            Some(ip) => {
                object.insert("user_ip".to_string(), json!(ip));
            }
            None => {
                // Without this the ad server targets on the appliance's own
                // address, which is the same address for every reader, so
                // geographic targeting and the ad server's own client id are
                // both wrong.
                log::warn!(
                    "{PROVIDER_NAME}: the auction request carries no visitor address, so the ad server will target on the appliance's own address instead"
                );
            }
        }

        body
    }

    /// Reads the decision API token from the secret store.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret cannot be read or is empty.
    fn load_api_token(
        &self,
        services: &RuntimeServices,
        token: &EthicalAdServerToken,
    ) -> Result<Redacted<String>, Report<TrustedServerError>> {
        let store_name = StoreName::from(token.secret_store.as_str());
        let value = services
            .secret_store()
            .get_string(&store_name, &token.secret_name)
            .change_context(TrustedServerError::Integration {
                integration: PROVIDER_NAME.to_string(),
                message: "Failed to read the decision API token from the secret store".to_string(),
            })?;
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(Report::new(TrustedServerError::Integration {
                integration: PROVIDER_NAME.to_string(),
                message: "Decision API token secret must not be empty".to_string(),
            }));
        }
        Ok(Redacted::new(value))
    }

    /// Builds the bid that represents a winning ad server decision.
    ///
    /// The tracking URLs and the nonce ride in [`Bid::metadata`] under the ad
    /// server's own field names, so the tracking path can fire them and this
    /// provider does not. `nurl` and `burl` stay empty for the same reason:
    /// the render bridge fires those verbatim.
    fn build_direct_bid(
        &self,
        decision: &AdDecision,
        placement: &SlotPlacement,
        ecpm: Ecpm,
    ) -> Bid {
        let mut metadata: HashMap<String, Json> = decision
            .tracking
            .iter()
            .map(|(key, value)| (key.clone(), json!(value)))
            .collect();
        metadata.insert("id".to_string(), json!(decision.ad_slug));

        Bid {
            slot_id: placement.slot_id.clone(),
            price: Some(ecpm.value()),
            currency: EAS_CURRENCY.to_string(),
            creative: decision.creative.clone(),
            adomain: decision
                .link_domain
                .as_ref()
                .map(|domain| vec![domain.clone()]),
            bidder: PROVIDER_NAME.to_string(),
            width: placement.width,
            height: placement.height,
            nurl: None,
            burl: None,
            // The nonce identifies this single offer, so it is the per-bid
            // identifier the render handshake needs. The advertisement slug
            // names the creative and repeats across offers, so it cannot
            // serve as one.
            bid_id: decision.nonce.clone(),
            ad_id: decision.nonce.clone(),
            creative_id: Some(decision.ad_slug.clone()),
            renderer: None,
            cache_id: None,
            cache_host: None,
            cache_path: None,
            metadata,
        }
    }

    /// Matches a decision back to the placement it filled.
    ///
    /// The ad server echoes both the `div_id` and the ad type slug of the
    /// placement it chose, and both are checked. The decision API sends no
    /// width or height, so the matched placement is the only thing that
    /// decides the size stamped on the bid, and a creative rendered at
    /// another placement's size is a broken advertisement rather than a
    /// visible failure.
    ///
    /// Returns `None`, loudly, whenever the decision cannot be tied to an
    /// offered placement. Guessing is confined to the one case where there is
    /// nothing to guess: a decision that echoes no `div_id` at all when a
    /// single placement was offered.
    fn match_placement<'a>(
        decision: &AdDecision,
        placements: &'a [SlotPlacement],
    ) -> Option<&'a SlotPlacement> {
        let placement = match decision.div_id.as_deref() {
            Some(div_id) => {
                let Some(placement) = placements.iter().find(|p| p.div_id == div_id) else {
                    log::warn!(
                        "{PROVIDER_NAME}: decision '{}' names div_id '{div_id}', which matches none of the {} offered placements, so the slot it belongs to is unknown",
                        decision.ad_slug,
                        placements.len()
                    );
                    return None;
                };
                placement
            }
            None => {
                let [only] = placements else {
                    log::warn!(
                        "{PROVIDER_NAME}: decision '{}' echoed no div_id and {} placements were offered, so the slot it belongs to is unknown",
                        decision.ad_slug,
                        placements.len()
                    );
                    return None;
                };
                log::debug!(
                    "{PROVIDER_NAME}: decision '{}' echoed no div_id, and only placement '{}' was offered",
                    decision.ad_slug,
                    only.div_id
                );
                only
            }
        };

        let offered = canonical_ad_type(&placement.ad_type);
        if let Some(display_type) = decision.tracking.get("display_type")
            && canonical_ad_type(display_type) != offered
        {
            log::warn!(
                "{PROVIDER_NAME}: decision '{}' for div_id '{}' reports ad type '{display_type}' but that placement offered '{offered}', so the size to render it at is unknown",
                decision.ad_slug,
                placement.div_id
            );
            return None;
        }

        Some(placement)
    }

    /// Compares an ad server decision against the programmatic bids and
    /// returns one winning bid per slot.
    ///
    /// Every slot keeps its best programmatic bid unless the ad server offers
    /// a higher effective CPM for it, because the orchestrator builds its
    /// winning-bid set only from the bids this mediator returns.
    fn decide_winners(
        &self,
        body: &Json,
        placements: &[SlotPlacement],
        mut programmatic: ProgrammaticWinners,
        response_time_ms: u64,
    ) -> AuctionResponse {
        let Some(decision) = read_decision(body) else {
            // The ad types are named because the decision API answers an ad
            // type slug it does not know with the same empty object it sends
            // for genuinely no demand, so a typo in configuration looks
            // exactly like an unsold slot.
            let offered: Vec<&str> = placements
                .iter()
                .map(|placement| placement.ad_type.as_str())
                .collect();
            log::debug!(
                "{PROVIDER_NAME}: no ad offered for ad types [{}], keeping the programmatic bids",
                offered.join(", ")
            );
            return pass_through(programmatic, response_time_ms);
        };

        let Some(placement) = Self::match_placement(&decision, placements) else {
            log::warn!(
                "{PROVIDER_NAME}: decision '{}' names div_id {:?}, which matches no offered placement",
                decision.ad_slug,
                decision.div_id
            );
            return pass_through(programmatic, response_time_ms);
        };

        let ecpm = match decision_ecpm(body) {
            Ok(ecpm) => ecpm,
            Err(NoPrice::CostPerClick) => {
                log::debug!(
                    "{PROVIDER_NAME}: decision '{}' for slot '{}' is a cost-per-click flight with no `ecpm`, so it has no CPM-comparable price and cannot bid",
                    decision.ad_slug,
                    placement.slot_id
                );
                return pass_through(programmatic, response_time_ms);
            }
            Err(NoPrice::NoPriceField) => {
                // Every price field is gated on one publisher setting, so an
                // ad returned with no price is a configuration fault that
                // silently costs the publisher every arbitration. It is named
                // loudly, and with the publisher slug, because the symptom on
                // its own looks exactly like having no direct-sold demand.
                log::warn!(
                    "{PROVIDER_NAME}: decision '{}' filled slot '{}' but carries no price, so the ad server can never win against a programmatic bid. Set `send_bid_rate` on publisher '{}' in the ad server, which is the one setting that gates `cpm`, `cpc` and `ecpm` alike",
                    decision.ad_slug,
                    placement.slot_id,
                    self.config.publisher
                );
                return pass_through(programmatic, response_time_ms);
            }
        };

        if decision.creative.is_none() {
            log::warn!(
                "{PROVIDER_NAME}: decision '{}' for slot '{}' has no markup to render, keeping the programmatic bid",
                decision.ad_slug,
                placement.slot_id
            );
            return pass_through(programmatic, response_time_ms);
        }

        if let Some(floor) = self.config.price_floor
            && ecpm.value() < floor
        {
            log::debug!(
                "{PROVIDER_NAME}: decision '{}' at {ecpm} is below the configured floor of {floor}",
                decision.ad_slug
            );
            return pass_through(programmatic, response_time_ms);
        }

        let programmatic_price = programmatic
            .get(&placement.slot_id)
            .and_then(|bid| bid.price);
        if let Some(price) = programmatic_price
            && price >= ecpm.value()
        {
            log::info!(
                "{PROVIDER_NAME}: programmatic bid of {price} beats the ad server's {ecpm} for slot '{}'",
                placement.slot_id
            );
            return pass_through(programmatic, response_time_ms);
        }

        if decision.nonce.as_deref() == Some(FORCED_NONCE) {
            log::warn!(
                "{PROVIDER_NAME}: decision '{}' carries the forced nonce, so the ad server will count neither its view nor its click and the bid has no identifier unique to this offer",
                decision.ad_slug
            );
        }

        log::info!(
            "{PROVIDER_NAME}: ad server wins slot '{}' at {ecpm} against {programmatic_price:?}",
            placement.slot_id
        );
        programmatic.insert(
            placement.slot_id.clone(),
            self.build_direct_bid(&decision, placement, ecpm),
        );

        pass_through(programmatic, response_time_ms)
    }

    /// Shared parse body for the context-aware and context-less trait methods.
    ///
    /// Never fails. An upstream fault degrades to the programmatic
    /// pass-through, because the synchronous mediation path turns a parse
    /// error into an aborted auction and every slot would go unfilled.
    async fn parse_response_inner(
        &self,
        response: PlatformResponse,
        response_time_ms: u64,
        placements: &[SlotPlacement],
        programmatic: ProgrammaticWinners,
    ) -> AuctionResponse {
        let response = response.response;

        let status = response.status();
        if !status.is_success() {
            let detail = match collect_response_bounded(
                response.into_body(),
                UPSTREAM_RTB_MAX_RESPONSE_BYTES,
                PROVIDER_NAME,
            )
            .await
            {
                Ok(bytes) => error_detail(&bytes),
                Err(error) => format!("body unreadable: {error}"),
            };
            log::warn!(
                "{PROVIDER_NAME}: decision API returned {status} ({detail}), keeping the programmatic bids"
            );
            return pass_through(programmatic, response_time_ms);
        }

        // collect_response_bounded caps memory from a misbehaving ad server.
        let body_bytes = match collect_response_bounded(
            response.into_body(),
            UPSTREAM_RTB_MAX_RESPONSE_BYTES,
            PROVIDER_NAME,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(error) => {
                log::warn!("{PROVIDER_NAME}: failed to read the decision response body: {error:?}");
                return pass_through(programmatic, response_time_ms);
            }
        };

        let body: Json = match serde_json::from_slice(&body_bytes) {
            Ok(body) => body,
            Err(error) => {
                log::warn!("{PROVIDER_NAME}: decision response is not valid JSON: {error}");
                return pass_through(programmatic, response_time_ms);
            }
        };

        log::trace!("{PROVIDER_NAME}: decision response: {body:?}");

        let auction_response =
            self.decide_winners(&body, placements, programmatic, response_time_ms);

        log::info!(
            "{PROVIDER_NAME}: returning {} winning bids in {response_time_ms}ms",
            auction_response.bids.len()
        );

        auction_response
    }
}

#[async_trait(?Send)]
impl AuctionProvider for EthicalAdServerProvider {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    async fn request_bids(
        &self,
        request: &AuctionRequest,
        context: &AuctionContext<'_>,
    ) -> Result<ProviderRequestOutcome, Report<TrustedServerError>> {
        let programmatic = best_programmatic_bids(context.provider_responses.unwrap_or(&[]));

        let placements = self.placements_for_request(request);
        if placements.is_empty() {
            log::info!(
                "{PROVIDER_NAME}: no slot maps to an ad type, returning {} programmatic bids unchanged",
                programmatic.len()
            );
            return Ok(ProviderRequestOutcome::Immediate(pass_through(
                programmatic,
                0,
            )));
        }

        // An offer the ad server creates without the visitor's own agent can
        // never be counted afterwards. The ad server stores the operating
        // system and browser it reads from this call on the offer, then throws
        // the later view away when the reader's browser does not match it
        // ("Mismatched OS", `adserver/views.py`), and throws it away as an
        // unrecognized user agent when a server-side agent is used for both.
        // Every one of those rejections answers HTTP 200, so an impression
        // that can never pay looks exactly like one that works. Taking the
        // slot away from a programmatic bid that can pay, to serve one that
        // cannot, is strictly worse than not bidding, so the call is not made.
        if visitor_user_agent(request).is_none() {
            log::warn!(
                "{PROVIDER_NAME}: the auction request carries no visitor User-Agent, so the ad server could never count an ad it offered, so {} programmatic bids are returned unchanged",
                programmatic.len()
            );
            return Ok(ProviderRequestOutcome::Immediate(pass_through(
                programmatic,
                0,
            )));
        }

        log::info!(
            "{PROVIDER_NAME}: requesting a decision for {} placements against {} programmatic bids",
            placements.len(),
            programmatic.len()
        );

        let decision_request = self.build_decision_request(request, &placements);
        log::trace!("{PROVIDER_NAME}: decision request: {decision_request:?}");

        let decision_body =
            serde_json::to_vec(&decision_request).change_context(TrustedServerError::Auction {
                message: "Failed to serialize the decision request".to_string(),
            })?;

        let mut builder = http::Request::builder()
            .method(Method::POST)
            .uri(self.build_endpoint_url(request))
            .header(header::CONTENT_TYPE, "application/json");

        // The decision API asks a server-to-server caller to name itself here
        // while the end user's own agent travels in `user_ua`.
        match header::HeaderValue::from_str(&self.config.user_agent) {
            Ok(value) => builder = builder.header(header::USER_AGENT, value),
            Err(error) => {
                log::warn!(
                    "{PROVIDER_NAME}: configured user_agent is not a valid header value: {error}"
                );
            }
        }

        if let Some(token) = self.config.api_token.as_ref() {
            // A credential the ad server cannot read is not a reason to blank
            // the page, so an unreadable secret falls back to the programmatic
            // bids rather than aborting the auction.
            let token = match self.load_api_token(context.services, token) {
                Ok(token) => token,
                Err(error) => {
                    log::error!(
                        "{PROVIDER_NAME}: cannot authenticate to the decision API: {error:?}"
                    );
                    return Ok(ProviderRequestOutcome::Immediate(pass_through(
                        programmatic,
                        0,
                    )));
                }
            };
            match header::HeaderValue::from_str(&format!("Token {}", token.expose())) {
                Ok(mut value) => {
                    value.set_sensitive(true);
                    builder = builder.header(header::AUTHORIZATION, value);
                }
                Err(error) => {
                    log::error!(
                        "{PROVIDER_NAME}: decision API token is not a valid header value: {error}"
                    );
                    return Ok(ProviderRequestOutcome::Immediate(pass_through(
                        programmatic,
                        0,
                    )));
                }
            }
        }

        // No Host header override is set, unlike a mediator that builds URLs
        // from the incoming request: the ad server builds its view and click
        // URLs from Django's configured site, not from the request host.
        let req = builder.body(EdgeBody::from(decision_body)).change_context(
            TrustedServerError::Auction {
                message: "Failed to build the decision request".to_string(),
            },
        )?;

        // Uses context.timeout_ms, which the orchestrator has already capped
        // to the auction's remaining budget.
        let backend_name = ensure_integration_backend_with_timeout(
            context.services,
            &self.config.endpoint,
            PROVIDER_NAME,
            Duration::from_millis(u64::from(context.timeout_ms)),
        )
        .change_context(TrustedServerError::Auction {
            message: format!(
                "Failed to resolve backend for the decision endpoint: {}",
                self.config.endpoint
            ),
        })?;

        let pending = context
            .services
            .http_client()
            .send_async(PlatformHttpRequest::new(req, backend_name))
            .await
            .change_context(TrustedServerError::Auction {
                message: "Failed to send the decision request".to_string(),
            })?;

        Ok(ProviderRequestOutcome::pending(pending))
    }

    async fn parse_response(
        &self,
        response: PlatformResponse,
        response_time_ms: u64,
    ) -> Result<AuctionResponse, Report<TrustedServerError>> {
        // No auction context, so there are no programmatic bids to compare
        // against and the placements come from configuration alone. The
        // orchestrator always calls [`parse_response_with_context`], so this
        // path only serves callers outside the orchestration flow.
        log::debug!(
            "{PROVIDER_NAME}: parsing without context, so no programmatic bid is available to arbitrate against"
        );
        let placements = self.placements_from_config();
        Ok(self
            .parse_response_inner(
                response,
                response_time_ms,
                &placements,
                ProgrammaticWinners::new(),
            )
            .await)
    }

    async fn parse_response_with_context(
        &self,
        response: PlatformResponse,
        response_time_ms: u64,
        request: &AuctionRequest,
        context: &AuctionContext<'_>,
    ) -> Result<AuctionResponse, Report<TrustedServerError>> {
        // The placements are rebuilt from the same request and configuration
        // the dispatch used, so request-scoped data stays off the shared
        // provider instance.
        let placements = self.placements_for_request(request);
        let programmatic = best_programmatic_bids(context.provider_responses.unwrap_or(&[]));
        Ok(self
            .parse_response_inner(response, response_time_ms, &placements, programmatic)
            .await)
    }

    fn supports_media_type(&self, media_type: &MediaType) -> bool {
        matches!(media_type, MediaType::Banner)
    }

    fn timeout_ms(&self) -> u32 {
        self.config.timeout_ms
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn backend_name(&self, services: &RuntimeServices, timeout_ms: u32) -> Option<String> {
        predict_integration_backend_name(
            services,
            &self.config.endpoint,
            PROVIDER_NAME,
            Duration::from_millis(u64::from(timeout_ms)),
        )
        .inspect_err(|error| {
            log::error!(
                "Failed to predict backend name for the Ethical Ad Server endpoint '{}': {error:?}",
                self.config.endpoint
            );
        })
        .ok()
    }
}

// ============================================================================
// Auto-Registration
// ============================================================================

/// Validates the Ethical Ad Server configuration for deployment and reports
/// whether the provider is enabled.
///
/// # Errors
///
/// Returns an error when the Ethical Ad Server configuration cannot be parsed
/// or fails validation.
pub(crate) fn validate(settings: &Settings) -> Result<bool, Report<TrustedServerError>> {
    settings
        .integration_config::<EthicalAdServerConfig>(ETHICAL_ADSERVER_INTEGRATION_ID)
        .map(|config| config.is_some())
}

/// Auto-registers the Ethical Ad Server provider from settings.
///
/// # Errors
///
/// Returns an error when the Ethical Ad Server provider is enabled with
/// invalid configuration.
pub fn register_providers(
    settings: &Settings,
) -> Result<Vec<Arc<dyn AuctionProvider>>, Report<TrustedServerError>> {
    let mut providers: Vec<Arc<dyn AuctionProvider>> = Vec::new();

    match settings.integration_config::<EthicalAdServerConfig>(ETHICAL_ADSERVER_INTEGRATION_ID) {
        Ok(Some(config)) => {
            log::info!(
                "Registering the Ethical Ad Server mediator (endpoint: {}, publisher: {})",
                config.endpoint,
                config.publisher
            );
            providers.push(Arc::new(EthicalAdServerProvider::new(config)));
        }
        Ok(None) => {
            log::debug!("Ethical Ad Server config found but is disabled");
        }
        Err(error) => {
            return Err(error);
        }
    }

    Ok(providers)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auction::types::{AdFormat, AdSlot, DeviceInfo, PublisherInfo, UserInfo};
    use http::StatusCode;

    const SLOT_ID: &str = "header-banner";

    fn test_config() -> EthicalAdServerConfig {
        let mut slots = BTreeMap::new();
        slots.insert(
            SLOT_ID.to_string(),
            EthicalAdServerSlot {
                ad_type: "image-v1".to_string(),
                div_id: None,
                priority: Some(10),
                width: None,
                height: None,
            },
        );

        EthicalAdServerConfig {
            enabled: true,
            endpoint: "https://adserver.example.com/api/v1/decision/".to_string(),
            publisher: "example-publisher".to_string(),
            slots,
            ..EthicalAdServerConfig::default()
        }
    }

    fn test_auction_request() -> AuctionRequest {
        AuctionRequest {
            id: "auction-eas-1".to_string(),
            slots: vec![AdSlot {
                id: SLOT_ID.to_string(),
                formats: vec![AdFormat {
                    media_type: MediaType::Banner,
                    width: 300,
                    height: 250,
                }],
                floor_price: Some(0.50),
                targeting: HashMap::new(),
                bidders: HashMap::new(),
            }],
            publisher: PublisherInfo {
                domain: "publisher.example".to_string(),
                page_url: Some("https://publisher.example/article".to_string()),
            },
            user: UserInfo {
                id: Some("edge-cookie-1".to_string()),
                consent: None,
                eids: None,
            },
            device: Some(DeviceInfo {
                user_agent: Some("Mozilla/5.0 (fictional test agent)".to_string()),
                ip: Some("203.0.113.7".to_string()),
                geo: None,
            }),
            site: None,
            context: HashMap::new(),
        }
    }

    fn programmatic_bid(price: f64) -> Bid {
        Bid {
            slot_id: SLOT_ID.to_string(),
            price: Some(price),
            currency: "USD".to_string(),
            creative: Some("<div>Programmatic ad</div>".to_string()),
            adomain: Some(vec!["advertiser.example".to_string()]),
            bidder: "example-ssp".to_string(),
            width: 300,
            height: 250,
            nurl: Some("https://ssp.example/win".to_string()),
            burl: Some("https://ssp.example/bill".to_string()),
            bid_id: Some("ssp-bid-1".to_string()),
            ad_id: Some("ssp-ad-1".to_string()),
            creative_id: Some("ssp-creative-1".to_string()),
            renderer: None,
            cache_id: None,
            cache_host: None,
            cache_path: None,
            metadata: HashMap::new(),
        }
    }

    fn programmatic_winners(price: f64) -> ProgrammaticWinners {
        let mut winners = ProgrammaticWinners::new();
        winners.insert(SLOT_ID.to_string(), programmatic_bid(price));
        winners
    }

    fn decision_body(extra: &Json) -> Json {
        let mut body = json!({
            "id": "example-ad-slug",
            "div_id": SLOT_ID,
            "html": "<a href=\"https://adserver.example.com/click/1/nonce-1\">Example ad</a>",
            "text": "Example ad",
            "link": "https://adserver.example.com/click/1/nonce-1",
            "link_domain": "sponsor.example",
            "view_url": "https://adserver.example.com/view/1/nonce-1",
            "view_time_url": "https://adserver.example.com/view-time/1/nonce-1",
            "nonce": "nonce-1",
            "display_type": "image-v1",
            "campaign_type": "paid"
        });
        if let (Some(object), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                object.insert(key.clone(), value.clone());
            }
        }
        body
    }

    fn platform_response(status: StatusCode, body: Vec<u8>) -> PlatformResponse {
        PlatformResponse::new(
            http::Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(EdgeBody::from(body))
                .expect("should build a decision platform response"),
        )
    }

    async fn parse(
        config: EthicalAdServerConfig,
        body: Vec<u8>,
        programmatic_price: f64,
    ) -> AuctionResponse {
        parse_with_status(config, StatusCode::OK, body, programmatic_price).await
    }

    async fn parse_with_status(
        config: EthicalAdServerConfig,
        status: StatusCode,
        body: Vec<u8>,
        programmatic_price: f64,
    ) -> AuctionResponse {
        let provider = EthicalAdServerProvider::new(config);
        let request = test_auction_request();
        let placements = provider.placements_for_request(&request);
        provider
            .parse_response_inner(
                platform_response(status, body),
                42,
                &placements,
                programmatic_winners(programmatic_price),
            )
            .await
    }

    #[test]
    fn builds_a_decision_request_from_the_slot_mapping() {
        let provider = EthicalAdServerProvider::new(EthicalAdServerConfig {
            keywords: vec!["rust".to_string(), "edge".to_string()],
            campaign_types: vec!["paid".to_string()],
            ..test_config()
        });
        let request = test_auction_request();
        let placements = provider.placements_for_request(&request);
        let body = provider.build_decision_request(&request, &placements);

        assert_eq!(
            body["publisher"], "example-publisher",
            "should send the configured publisher slug"
        );
        let placements_json = body["placements"]
            .as_array()
            .expect("should send placements as an array");
        assert_eq!(placements_json.len(), 1, "should offer one placement");
        assert_eq!(placements_json[0]["div_id"], SLOT_ID);
        assert_eq!(placements_json[0]["ad_type"], "image-v1");
        assert_eq!(placements_json[0]["priority"], 10);
        assert_eq!(body["keywords"], json!(["rust", "edge"]));
        assert_eq!(body["campaign_types"], json!(["paid"]));
        assert_eq!(body["url"], "https://publisher.example/article");
        assert_eq!(
            body["user_ip"], "203.0.113.7",
            "should send the end user's address, not the appliance's"
        );
        assert_eq!(body["user_ua"], "Mozilla/5.0 (fictional test agent)");
        assert!(
            body.get("w").is_none() && body.get("h").is_none(),
            "the decision API has no width or height"
        );
    }

    #[test]
    fn maps_a_slot_by_banner_format_when_it_has_no_slot_entry() {
        let mut config = test_config();
        config.slots.clear();
        config
            .ad_types_by_format
            .insert("300x250".to_string(), "image-v1".to_string());
        let provider = EthicalAdServerProvider::new(config);

        let placements = provider.placements_for_request(&test_auction_request());

        assert_eq!(
            placements,
            vec![SlotPlacement {
                slot_id: SLOT_ID.to_string(),
                div_id: SLOT_ID.to_string(),
                ad_type: "image-v1".to_string(),
                priority: None,
                width: 300,
                height: 250,
            }],
            "should fall back to the format mapping and take the size from the request"
        );
    }

    #[tokio::test]
    async fn cpm_decision_beating_the_programmatic_bid_wins_the_slot() {
        let body = decision_body(&json!({ "cpm": 4.50 }));
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            3.00,
        )
        .await;

        assert_eq!(response.provider, PROVIDER_NAME);
        assert_eq!(response.status, BidStatus::Success);
        assert_eq!(response.bids.len(), 1, "should return one bid for the slot");

        let bid = &response.bids[0];
        assert_eq!(bid.slot_id, SLOT_ID);
        assert_eq!(bid.price, Some(4.50), "should carry the ad server's CPM");
        assert_eq!(bid.bidder, PROVIDER_NAME);
        assert_eq!(bid.currency, "USD");
        assert_eq!(bid.width, 300, "should stamp the size the API cannot send");
        assert_eq!(bid.height, 250);
        assert_eq!(
            bid.creative.as_deref(),
            Some("<a href=\"https://adserver.example.com/click/1/nonce-1\">Example ad</a>")
        );
        assert_eq!(bid.adomain, Some(vec!["sponsor.example".to_string()]));
        assert_eq!(
            bid.ad_id.as_deref(),
            Some("nonce-1"),
            "the nonce is the per-offer identifier the render handshake needs"
        );
        assert_eq!(bid.creative_id.as_deref(), Some("example-ad-slug"));
        assert!(
            bid.nurl.is_none() && bid.burl.is_none(),
            "tracking URLs must not ride in nurl or burl, which the render bridge fires"
        );
        assert_eq!(
            bid.metadata.get("view_url"),
            Some(&json!("https://adserver.example.com/view/1/nonce-1")),
            "should surface the view URL for the tracking path to fire"
        );
        assert_eq!(
            bid.metadata.get("link"),
            Some(&json!("https://adserver.example.com/click/1/nonce-1"))
        );
        assert_eq!(bid.metadata.get("nonce"), Some(&json!("nonce-1")));
    }

    #[tokio::test]
    async fn cpm_decision_losing_to_the_programmatic_bid_keeps_that_bid() {
        let body = decision_body(&json!({ "cpm": 1.25 }));
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            3.00,
        )
        .await;

        assert_eq!(response.status, BidStatus::Success);
        assert_eq!(response.bids.len(), 1);

        let bid = &response.bids[0];
        assert_eq!(bid.bidder, "example-ssp", "the higher bid should win");
        assert_eq!(bid.price, Some(3.00));
        assert_eq!(
            bid.nurl.as_deref(),
            Some("https://ssp.example/win"),
            "a passed-through bid must keep its win notification URL"
        );
        assert_eq!(
            bid.ad_id.as_deref(),
            Some("ssp-ad-1"),
            "a passed-through bid must keep its accounting fields"
        );
    }

    #[tokio::test]
    async fn empty_decision_keeps_the_programmatic_bid() {
        let response = parse(test_config(), b"{}".to_vec(), 2.00).await;

        assert_eq!(response.status, BidStatus::Success);
        assert_eq!(response.bids.len(), 1);
        assert_eq!(response.bids[0].bidder, "example-ssp");
        assert_eq!(response.bids[0].price, Some(2.00));
    }

    #[tokio::test]
    async fn empty_decision_with_no_programmatic_bid_is_a_no_bid() {
        let provider = EthicalAdServerProvider::new(test_config());
        let request = test_auction_request();
        let placements = provider.placements_for_request(&request);

        let response = provider
            .parse_response_inner(
                platform_response(StatusCode::OK, b"{}".to_vec()),
                7,
                &placements,
                ProgrammaticWinners::new(),
            )
            .await;

        assert_eq!(response.status, BidStatus::NoBid);
        assert!(response.bids.is_empty());
    }

    #[tokio::test]
    async fn cost_per_click_decision_has_no_comparable_price() {
        // A CPC flight quotes `cpc` and never `cpm`, and the decision carries
        // no click-through rate, so there is nothing to compare.
        let body = decision_body(&json!({ "cpc": 2.50 }));
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            1.00,
        )
        .await;

        assert_eq!(response.bids.len(), 1);
        assert_eq!(
            response.bids[0].bidder, "example-ssp",
            "a cost-per-click decision must not win against a priced bid"
        );
        assert_eq!(response.bids[0].price, Some(1.00));
    }

    #[tokio::test]
    async fn cost_per_click_decision_with_an_ecpm_can_win() {
        // The ad server is the only party that can turn a cost per click into
        // an effective CPM, so `ecpm` is used whenever it is sent. Upstream
        // does not send the field yet, so this fixture is the only cover the
        // presence path has.
        let body = decision_body(&json!({ "cpc": 2.50, "ecpm": 5.00 }));
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            1.00,
        )
        .await;

        assert_eq!(response.bids.len(), 1);
        assert_eq!(response.bids[0].bidder, PROVIDER_NAME);
        assert_eq!(response.bids[0].price, Some(5.00));
    }

    #[tokio::test]
    async fn an_ecpm_is_preferred_over_the_flight_s_own_cpm() {
        // `ecpm` is the ad server's own comparable price, so it wins over the
        // raw rate whatever the flight is priced on. Fixture only, since
        // upstream sends no `ecpm`.
        let body = decision_body(&json!({ "cpm": 2.00, "ecpm": 7.50 }));
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            3.00,
        )
        .await;

        assert_eq!(response.bids.len(), 1);
        assert_eq!(response.bids[0].bidder, PROVIDER_NAME);
        assert_eq!(
            response.bids[0].price,
            Some(7.50),
            "should bid the effective CPM the ad server calculated, not the raw rate"
        );
    }

    #[tokio::test]
    async fn decision_without_any_price_field_cannot_win() {
        // An ad returned with no price is the publisher not having opted into
        // bid rates, which gates `cpm`, `cpc` and `ecpm` together. It is a
        // configuration fault rather than an absence of demand, so it is kept
        // separate from the empty decision two tests above.
        let body = decision_body(&json!({}));
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            0.75,
        )
        .await;

        assert_eq!(response.bids.len(), 1);
        assert_eq!(response.bids[0].bidder, "example-ssp");
    }

    #[tokio::test]
    async fn malformed_decision_keeps_the_programmatic_bid() {
        let response = parse(test_config(), b"{not json at all".to_vec(), 2.25).await;

        assert_eq!(
            response.status,
            BidStatus::Success,
            "a malformed decision must not abort the auction"
        );
        assert_eq!(response.bids.len(), 1);
        assert_eq!(response.bids[0].bidder, "example-ssp");
        assert_eq!(response.bids[0].price, Some(2.25));
    }

    #[tokio::test]
    async fn upstream_failure_keeps_the_programmatic_bid() {
        // The transport-level failure the orchestrator sees as a dead backend
        // surfaces here as a non-success status, and it must not blank a slot
        // that already has demand.
        let response = parse_with_status(
            test_config(),
            StatusCode::BAD_GATEWAY,
            b"upstream unavailable".to_vec(),
            1.80,
        )
        .await;

        assert_eq!(response.status, BidStatus::Success);
        assert_eq!(response.bids.len(), 1);
        assert_eq!(response.bids[0].bidder, "example-ssp");
        assert_eq!(response.bids[0].price, Some(1.80));
    }

    #[tokio::test]
    async fn decision_below_the_configured_floor_cannot_win() {
        let config = EthicalAdServerConfig {
            price_floor: Some(2.00),
            ..test_config()
        };
        let body = decision_body(&json!({ "cpm": 1.50 }));
        let response = parse(
            config,
            serde_json::to_vec(&body).expect("should serialize the decision"),
            0.10,
        )
        .await;

        assert_eq!(response.bids.len(), 1);
        assert_eq!(response.bids[0].bidder, "example-ssp");
    }

    #[tokio::test]
    async fn unfilled_slots_keep_their_programmatic_bids() {
        let mut config = test_config();
        config.slots.insert(
            "sidebar".to_string(),
            EthicalAdServerSlot {
                ad_type: "image-v1".to_string(),
                div_id: None,
                priority: Some(1),
                width: None,
                height: None,
            },
        );
        let provider = EthicalAdServerProvider::new(config);

        let mut request = test_auction_request();
        request.slots.push(AdSlot {
            id: "sidebar".to_string(),
            formats: vec![AdFormat {
                media_type: MediaType::Banner,
                width: 160,
                height: 600,
            }],
            floor_price: None,
            targeting: HashMap::new(),
            bidders: HashMap::new(),
        });

        let mut programmatic = programmatic_winners(1.00);
        let mut sidebar = programmatic_bid(2.20);
        sidebar.slot_id = "sidebar".to_string();
        sidebar.bidder = "sidebar-ssp".to_string();
        programmatic.insert("sidebar".to_string(), sidebar);

        let placements = provider.placements_for_request(&request);
        let body = decision_body(&json!({ "cpm": 6.00 }));
        let response = provider
            .parse_response_inner(
                platform_response(
                    StatusCode::OK,
                    serde_json::to_vec(&body).expect("should serialize the decision"),
                ),
                11,
                &placements,
                programmatic,
            )
            .await;

        assert_eq!(
            response.bids.len(),
            2,
            "the mediator must return a winner for every slot, not only the one it filled"
        );
        let filled = response
            .bids
            .iter()
            .find(|bid| bid.slot_id == SLOT_ID)
            .expect("should return a bid for the filled slot");
        assert_eq!(filled.bidder, PROVIDER_NAME);
        let untouched = response
            .bids
            .iter()
            .find(|bid| bid.slot_id == "sidebar")
            .expect("should return a bid for the slot the ad server did not fill");
        assert_eq!(untouched.bidder, "sidebar-ssp");
        assert_eq!(untouched.price, Some(2.20));
    }

    #[test]
    fn reads_a_price_sent_as_a_string() {
        assert_eq!(
            decision_ecpm(&json!({ "cpm": "3.25" })).map(Ecpm::value),
            Ok(3.25),
            "a proxy may stringify the decimal the ad server sends as a number"
        );
    }

    #[test]
    fn rejects_a_zero_or_negative_price() {
        assert_eq!(
            decision_ecpm(&json!({ "cpm": 0 })),
            Err(NoPrice::NoPriceField)
        );
        assert_eq!(
            decision_ecpm(&json!({ "cpm": -1.0 })),
            Err(NoPrice::NoPriceField)
        );
        assert_eq!(Ecpm::new(f64::NAN), None, "a price must be finite");
    }

    #[test]
    fn best_programmatic_bid_per_slot_is_the_highest_priced_one() {
        let responses = vec![
            AuctionResponse::success("ssp-one", vec![programmatic_bid(1.10)], 30),
            AuctionResponse::success("ssp-two", vec![programmatic_bid(4.40)], 25),
            AuctionResponse::no_bid("ssp-three", 20),
        ];

        let winners = best_programmatic_bids(&responses);

        assert_eq!(winners.len(), 1);
        assert_eq!(winners.get(SLOT_ID).and_then(|bid| bid.price), Some(4.40));
    }

    #[test]
    fn rejects_an_out_of_range_placement_priority() {
        let mut config = test_config();
        config
            .slots
            .get_mut(SLOT_ID)
            .expect("should have the test slot")
            .priority = Some(11);

        config
            .validate()
            .expect_err("should reject a priority above the API maximum");
    }

    #[test]
    fn rejects_a_format_key_that_is_not_width_by_height() {
        let mut config = test_config();
        config
            .ad_types_by_format
            .insert("medium-rectangle".to_string(), "image-v1".to_string());

        config
            .validate()
            .expect_err("should reject a format key that carries no dimensions");
    }

    #[test]
    fn accepts_a_complete_configuration() {
        test_config()
            .validate()
            .expect("should accept the documented configuration shape");
    }

    /// Field set and `html` shape of a real decision captured from an Ethical
    /// Ad Server 6.0.1, with the host, slugs and identifiers replaced by
    /// example values.
    ///
    /// `html` here is what the ad server's stock ad type template renders for
    /// a modern headline, content and call-to-action advertisement: the view
    /// pixel on its own, carrying none of the advertisement's words.
    fn captured_stock_template_decision() -> Json {
        json!({
            "id": "example-canary-ad",
            "text": "<a href=\"https://adserver.example.com/proxy/click/1/example-nonce/\" rel=\"nofollow noopener sponsored\" target=\"_blank\"><strong class=\"ea-headline\">EXAMPLE: </strong><span class=\"ea-body\">Example canary creative</span><strong class=\"ea-cta\"> Click here</strong></a>",
            "body": "EXAMPLE: Example canary creative Click here",
            "html": "<div class=\"ethical-ad\"><img src=\"https://adserver.example.com/proxy/view/1/example-nonce/\" class=\"ethical-pixel\"></div>",
            "copy": {
                "headline": "EXAMPLE:",
                "cta": "Click here",
                "content": "Example canary creative"
            },
            "image": null,
            "logo": null,
            "link": "https://adserver.example.com/proxy/click/1/example-nonce/",
            "link_domain": "sponsor.example",
            "view_url": "https://adserver.example.com/proxy/view/1/example-nonce/",
            "view_time_url": "https://adserver.example.com/proxy/viewtime/1/example-nonce/",
            "nonce": "example-nonce",
            "display_type": "image-v1",
            "campaign_type": "paid",
            "cpm": 5.0,
            "div_id": SLOT_ID
        })
    }

    /// Builds a decision carrying the `div_id` and ad type the placement
    /// matcher reads, plus a creative so the bid is otherwise renderable.
    fn ad_decision(div_id: Option<&str>, display_type: Option<&str>) -> AdDecision {
        let mut tracking = BTreeMap::new();
        if let Some(display_type) = display_type {
            tracking.insert("display_type".to_string(), display_type.to_string());
        }
        AdDecision {
            ad_slug: "example-ad-slug".to_string(),
            div_id: div_id.map(String::from),
            creative: Some(
                "<a href=\"https://adserver.example.com/click/1/nonce-1\">Example ad</a>"
                    .to_string(),
            ),
            link_domain: Some("sponsor.example".to_string()),
            nonce: Some("nonce-1".to_string()),
            tracking,
        }
    }

    fn single_placement() -> Vec<SlotPlacement> {
        let provider = EthicalAdServerProvider::new(test_config());
        let placements = provider.placements_for_request(&test_auction_request());
        assert_eq!(placements.len(), 1, "should offer exactly one placement");
        placements
    }

    #[tokio::test]
    async fn a_stock_template_decision_renders_the_words_not_the_pixel() {
        let body = captured_stock_template_decision();
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            1.00,
        )
        .await;

        assert_eq!(response.bids.len(), 1);
        let bid = &response.bids[0];
        assert_eq!(
            bid.bidder, PROVIDER_NAME,
            "the ad server's 5.00 should beat the programmatic 1.00"
        );
        assert_eq!(bid.price, Some(5.00));

        let creative = bid
            .creative
            .as_deref()
            .expect("should carry markup to render");
        assert!(
            creative.contains("Example canary creative"),
            "should render the advertisement's own words, not the pixel-only `html`: {creative}"
        );
        assert!(
            !creative.contains("ethical-pixel"),
            "the stock template renders no creative, so its `html` must not win a slot"
        );
        assert_eq!(
            bid.metadata.get("view_url"),
            Some(&json!(
                "https://adserver.example.com/proxy/view/1/example-nonce/"
            )),
            "the tracking path fires the view, so its URL must still reach the caller"
        );
        assert!(
            !bid.metadata.contains_key("view_time_url"),
            "view_time_url can neither bill nor survive the signed token, so it must not be offered as something to route"
        );
        assert_eq!(bid.adomain, Some(vec!["sponsor.example".to_string()]));
    }

    #[test]
    fn html_is_used_when_the_ad_type_template_renders_the_creative() {
        // A deployment that configures an ad type template gets the words and
        // the view pixel together, and that markup links to the ad.
        let decision = json!({
            "id": "example-ad-slug",
            "html": "<div><a href=\"https://adserver.example.com/click/1/nonce-1\">Example ad</a><img class=\"ethical-pixel\" src=\"https://adserver.example.com/view/1/nonce-1\"></div>",
            "text": "<a href=\"https://adserver.example.com/click/1/nonce-1\">Example ad</a>",
            "link": "https://adserver.example.com/click/1/nonce-1"
        });

        let creative = read_decision(&decision)
            .and_then(|decision| decision.creative)
            .expect("should read a creative");

        assert!(
            creative.contains("ethical-pixel"),
            "should prefer the ad type template's markup, which carries the pixel"
        );
    }

    #[test]
    fn a_div_id_that_matches_no_placement_is_refused_rather_than_guessed() {
        let placements = single_placement();

        let matched = EthicalAdServerProvider::match_placement(
            &ad_decision(Some("some-other-div"), Some("image-v1")),
            &placements,
        );

        assert!(
            matched.is_none(),
            "a decision for a div_id that was never offered must not be attributed to the only placement"
        );
    }

    #[test]
    fn a_decision_reporting_another_ad_type_is_refused() {
        let placements = single_placement();

        let matched = EthicalAdServerProvider::match_placement(
            &ad_decision(Some(SLOT_ID), Some("some-other-type-v1")),
            &placements,
        );

        assert!(
            matched.is_none(),
            "the placement decides the size, since the decision API sends none, so a mismatched ad type must not be rendered"
        );
    }

    #[test]
    fn a_decision_with_no_div_id_matches_the_only_offered_placement() {
        let placements = single_placement();

        let matched = EthicalAdServerProvider::match_placement(
            &ad_decision(None, Some("image-v1")),
            &placements,
        );

        assert_eq!(
            matched.map(|placement| placement.slot_id.as_str()),
            Some(SLOT_ID),
            "with one placement offered there is nothing to guess between"
        );
    }

    #[test]
    fn the_renamed_ad_type_slug_still_matches_its_placement() {
        // The decision API rewrites this one legacy slug on the way in, so the
        // ad type it reports back is not the slug that was offered.
        let mut config = test_config();
        config
            .slots
            .get_mut(SLOT_ID)
            .expect("should have the test slot")
            .ad_type = RENAMED_AD_TYPE.0.to_string();
        let provider = EthicalAdServerProvider::new(config);
        let placements = provider.placements_for_request(&test_auction_request());

        let matched = EthicalAdServerProvider::match_placement(
            &ad_decision(Some(SLOT_ID), Some(RENAMED_AD_TYPE.1)),
            &placements,
        );

        assert_eq!(
            matched.map(|placement| placement.slot_id.as_str()),
            Some(SLOT_ID),
            "the renamed slug names the same ad type"
        );
    }

    #[tokio::test]
    async fn a_decision_for_an_unoffered_div_id_keeps_the_programmatic_bid() {
        let body = decision_body(&json!({ "cpm": 9.00, "div_id": "some-other-div" }));
        let response = parse(
            test_config(),
            serde_json::to_vec(&body).expect("should serialize the decision"),
            1.00,
        )
        .await;

        assert_eq!(response.bids.len(), 1);
        assert_eq!(
            response.bids[0].bidder, "example-ssp",
            "an unattributable decision must not displace a bid that can be rendered"
        );
        assert_eq!(response.bids[0].price, Some(1.00));
    }

    #[test]
    fn the_decision_call_sends_the_visitor_s_agent_not_the_appliance_s() {
        let provider = EthicalAdServerProvider::new(EthicalAdServerConfig {
            user_agent: "trusted-server/1.0 +examplepublisher".to_string(),
            ..test_config()
        });
        let request = test_auction_request();
        let placements = provider.placements_for_request(&request);

        let body = provider.build_decision_request(&request, &placements);

        assert_eq!(
            body["user_ua"], "Mozilla/5.0 (fictional test agent)",
            "user_ua must be the reader's own agent, since the ad server records the browser from it and rejects any later view that does not match"
        );
        assert_ne!(
            body["user_ua"], "trusted-server/1.0 +examplepublisher",
            "the appliance names itself in the HTTP header, never in user_ua"
        );
        assert_eq!(body["user_ip"], "203.0.113.7");
    }

    #[test]
    fn a_request_with_no_visitor_agent_has_nothing_to_offer_the_ad_server() {
        let mut absent = test_auction_request();
        absent.device = None;
        assert!(
            visitor_user_agent(&absent).is_none(),
            "no device means no visitor agent, which is what stops the decision call being made"
        );

        let mut blank = test_auction_request();
        blank
            .device
            .as_mut()
            .expect("should have device information")
            .user_agent = Some("   ".to_string());
        assert!(
            visitor_user_agent(&blank).is_none(),
            "a blank agent is no agent, and an offer made with one could never be counted"
        );
    }

    #[test]
    fn a_missing_visitor_address_is_omitted_rather_than_invented() {
        let mut request = test_auction_request();
        request
            .device
            .as_mut()
            .expect("should have device information")
            .ip = None;
        let provider = EthicalAdServerProvider::new(test_config());
        let placements = provider.placements_for_request(&request);

        let body = provider.build_decision_request(&request, &placements);

        assert!(
            body.get("user_ip").is_none(),
            "should send no address rather than the appliance's own"
        );
        assert_eq!(
            body["user_ua"], "Mozilla/5.0 (fictional test agent)",
            "a missing address must not cost the call its agent"
        );
    }

    #[test]
    fn a_rejected_decision_reports_the_reason_the_ad_server_gave() {
        assert_eq!(
            error_detail(br#"{"publisher":["Invalid publisher"]}"#),
            r#"{"publisher":["Invalid publisher"]}"#,
            "an operator needs the reason, not only a status code"
        );
        assert_eq!(error_detail(b"   "), "no body");

        let trimmed = error_detail("e".repeat(MAX_ERROR_DETAIL_CHARS + 10).as_bytes());
        assert_eq!(
            trimmed.chars().count(),
            MAX_ERROR_DETAIL_CHARS + 3,
            "should trim a long error page and mark it as trimmed"
        );
    }
}
