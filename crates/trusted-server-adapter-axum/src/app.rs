use core::future::Future;
use std::sync::Arc;

use crate::ec_kv::{AxumEcKvStore, ec_identity_path};
use crate::platform::init_kv_store;
use edgezero_core::app::Hooks;
use edgezero_core::context::RequestContext;
use edgezero_core::env_config::EnvConfig;
use edgezero_core::error::EdgeError;
use edgezero_core::http::{
    HandlerFuture, HeaderValue, Method, Request, Response, StatusCode, header,
};
use edgezero_core::router::RouterService;
use error_stack::Report;
use trusted_server_core::auction::endpoints::handle_auction;
use trusted_server_core::auction::{
    AuctionOrchestrator, AuctionProviderBuilder, build_orchestrator_with_providers,
};
use trusted_server_core::cache_policy::EdgeCacheHeader;
use trusted_server_core::constants::{COOKIE_SHAREDID, COOKIE_TS_EIDS};
use trusted_server_core::cookies::extract_cookie_value;
use trusted_server_core::ec::EcContext;
use trusted_server_core::ec::admin::{
    admin_ec_lookup_not_supported, deny_admin_diagnostic_fallback, handle_admin_eids_lookup,
};
use trusted_server_core::ec::device::DeviceSignals;
use trusted_server_core::ec::finalize::ec_finalize_response;
use trusted_server_core::ec::kv::KvIdentityGraph;
use trusted_server_core::ec::provider::ensure_provider_available;
use trusted_server_core::ec::registry::PartnerRegistry;
use trusted_server_core::error::{IntoHttpResponse as _, TrustedServerError};
use trusted_server_core::evidence::BorrowedRequestInfo;
use trusted_server_core::http_util::is_navigation_request;
use trusted_server_core::integrations::{
    IntegrationBuilder, IntegrationRegistry, ProxyDispatchInput,
};
use trusted_server_core::proxy::{
    handle_first_party_click, handle_first_party_proxy, handle_first_party_proxy_rebuild,
    handle_first_party_proxy_sign,
};
use trusted_server_core::publisher::{
    AppContext, AuctionDispatch, PAGE_BIDS_LEGACY_PATH, PAGE_BIDS_PATH,
    buffer_publisher_response_async, handle_page_bids, handle_publisher_request,
    handle_tsjs_dynamic, page_bids_preflight_denied,
};
use trusted_server_core::request_signing::{
    handle_trusted_server_discovery, handle_verify_signature,
};
use trusted_server_core::settings::Settings;
use trusted_server_core::settings_data::{
    default_config_key, default_config_store_name, get_settings_from_config_store,
};

use trusted_server_core::platform::RuntimeServices;

use crate::middleware::{AuthMiddleware, FinalizeResponseMiddleware, SanitizeRequestMiddleware};
use crate::platform::{AxumPlatformConfigStore, build_runtime_services};

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// Application state built once at startup and shared across all requests.
///
/// Built once here, unlike on the other three adapters, because `main`
/// calls [`TrustedServerApp::routes`] before serving, so the router holds
/// one state for the process's lifetime.
pub struct AppState {
    settings: Arc<Settings>,
    orchestrator: Arc<AuctionOrchestrator>,
    registry: Arc<IntegrationRegistry>,
    /// The Edge Cookie identity graph, when the operator has named a store.
    ///
    /// Opened once here rather than per request, because `redb` locks the file
    /// exclusively and a second open would fail. Absent when `[ec] ec_store`
    /// is not configured, which is the operator declaring that identity is not
    /// persisted, and core then declines to issue an identifier rather than
    /// minting one with no row behind it.
    ec_identity_graph: Option<KvIdentityGraph>,
}

/// Build the application state, loading settings and constructing all per-application components.
///
/// Opens the persistent key-value store here rather than in `main`, so that a
/// store that cannot be opened fails the same way a missing identity store
/// already does: [`TrustedServerApp::routes`] turns the error into
/// [`startup_error_router`] and the process stays up answering every route with
/// it. In a container that is the more useful failure, because the healthcheck
/// then reports unhealthy, an orchestrator stops routing to it and an operator
/// can read the logs. Exiting instead restart-loops under
/// `restart: unless-stopped` and takes the logs with each restart.
///
/// This is the production path only. `routes_with_registrations` reaches
/// [`build_state_with_registrations`] directly, so tests neither open the store
/// nor contend on its exclusive file lock.
///
/// # Errors
///
/// Returns an error when settings, the key-value store, the auction
/// orchestrator, or the integration registry fail to initialise.
fn build_state() -> Result<Arc<AppState>, Report<TrustedServerError>> {
    let store_name = default_config_store_name();
    let config_key = default_config_key();
    let settings =
        get_settings_from_config_store(&AxumPlatformConfigStore, &store_name, &config_key)?;
    let kv_path = init_kv_store(&EnvConfig::from_env())?;
    log::info!("KV store opened at {}", kv_path.display());
    build_state_with_registrations(settings, &vendor_builders(), &[])
}

/// The vendor modules this adapter compiles in and offers to a deployment.
///
/// The adapter is the composition root, so a vendor crate is reachable only if
/// this list carries its builder. A crate that compiles, whose own tests pass,
/// and that nothing hands to the registry is a provider no deployment can
/// select, and the selector then fails at startup naming a module that is
/// physically present in the binary.
///
/// Offering a module is not enabling it. Every builder here reads its own
/// `[integrations.<id>]` block and declares nothing when the deployment has
/// written none, so a configuration that names no vendor behaves exactly as it
/// did before the crate was linked in.
fn vendor_builders() -> Vec<IntegrationBuilder> {
    vec![trusted_server_geo_51degrees::builder()]
}

/// The ids of the vendor modules [`vendor_builders`] offers.
///
/// Exposed so a test can assert that the shipped binary really offers a
/// module, which is a different question from whether a test that supplies the
/// builder itself can select one.
#[must_use]
pub fn vendor_builder_ids() -> Vec<&'static str> {
    vendor_builders()
        .iter()
        .map(IntegrationBuilder::id)
        .collect()
}

/// Build the application state from explicit settings.
///
/// # Errors
///
/// Returns an error when the selected Edge Cookie provider cannot be built for
/// this adapter, or when the auction orchestrator or the integration registry
/// fail to initialize.
fn build_state_with_settings(
    settings: Settings,
) -> Result<Arc<AppState>, Report<TrustedServerError>> {
    build_state_with_registrations(settings, &[], &[])
}

/// Build the application state from explicit settings, composing the built-in
/// integrations and auction providers with the externally supplied builders in
/// `integrations` and `auction_providers`.
///
/// A deployment that ships a vendor crate calls this to add that crate's
/// integration and auction provider builders without the adapter naming the
/// vendor.
///
/// # Errors
///
/// Returns an error when the selected Edge Cookie provider cannot be built for
/// this adapter, or when the auction orchestrator or the integration registry
/// fail to initialize, which includes two builders claiming the same
/// integration id or auction provider name.
pub fn build_state_with_registrations(
    mut settings: Settings,
    integrations: &[IntegrationBuilder],
    auction_providers: &[AuctionProviderBuilder],
) -> Result<Arc<AppState>, Report<TrustedServerError>> {
    // A module that needs to reach a host through the first-party proxy says
    // so, rather than the operator having to know. This runs before anything
    // reads the settings, so every later reader sees one effective list. It
    // leaves an empty list alone, because empty is open mode and adding an
    // entry would close it. Every addition is logged naming the module.
    trusted_server_core::integrations::apply_module_proxy_domains(&mut settings, integrations)?;
    let orchestrator = build_orchestrator_with_providers(&settings, auction_providers)?;
    let registry = IntegrationRegistry::with_registrations(&settings, integrations)?;

    // Composition root: reject a provider selection this adapter can never
    // supply, once, before any request is served.
    //
    // The registry is built first because the check has to be asked the same
    // question the request path answers. `build_per_request_services` injects
    // the module-supplied provider into `RuntimeServices`, so passing `None`
    // here refused every module-supplied Edge Cookie provider at start-up while
    // the request path would have used it perfectly well. That was the state of
    // this adapter until a vendor module first supplied one.
    //
    // This adapter checks rather than keeps what the check resolved, unlike the
    // Fastly, Cloudflare and Spin adapters, because it is a long-lived process
    // whose application state is built once at start-up while theirs is rebuilt
    // for every request. It supplies no host signals, so that argument is
    // `None`.
    ensure_provider_available(&settings.ec, None, registry.ec_provider())?;
    let ec_identity_graph = open_ec_identity_graph(&settings)?;

    Ok(Arc::new(AppState {
        settings: Arc::new(settings),
        orchestrator: Arc::new(orchestrator),
        registry: Arc::new(registry),
        ec_identity_graph,
    }))
}

// ---------------------------------------------------------------------------
// Per-request RuntimeServices
// ---------------------------------------------------------------------------

/// Build per-request [`RuntimeServices`], applying the module-supplied geo,
/// Edge Cookie and device providers selected by `[geo]`, `[ec]` and
/// `[device] provider`.
///
/// Unset and `"none"` both resolve nothing for geo, so no client IP reaches a
/// host geo service. `"platform"` opts in to this adapter's own lookup, and any
/// other key names an integration module that declares a geo provider. Identity
/// and device are applied the same way when a module supplies them.
fn build_per_request_services(state: &AppState, ctx: &RequestContext) -> RuntimeServices {
    let mut services = build_runtime_services(ctx, &state.settings);
    if let Some(provider) = state.registry.geo_provider() {
        services = services.with_geo(provider);
    }
    if let Some(provider) = state.registry.ec_provider() {
        services = services.with_ec_provider(provider);
    }
    if let Some(provider) = state.registry.device_provider() {
        services = services.with_device_provider(provider);
    }
    services
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

/// Convert a [`Report<TrustedServerError>`] into an HTTP [`Response`].
pub(crate) fn http_error(report: &Report<TrustedServerError>) -> Response {
    let root_error = report.current_context();
    log::error!("Error occurred: {:?}", report);

    let body = edgezero_core::body::Body::from(format!("{}\n", root_error.user_message()));
    let mut response = Response::new(body);
    *response.status_mut() = root_error.status_code();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Builds the local `404 Not Found` returned for legacy `/admin/keys/*`
/// aliases on the Axum dev server.
///
/// These non-`/_ts` aliases are not matched by the `^/_ts/admin` basic-auth
/// handler, so they fail closed locally rather than fall through to the
/// publisher fallback — which would forward the caller's `Authorization` header
/// and key-management payload to the origin, leaking admin credentials.
fn legacy_admin_alias_denied() -> Response {
    let mut response = Response::new(edgezero_core::body::Body::from("Not found\n"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

// ---------------------------------------------------------------------------
// Shared handler executor
// ---------------------------------------------------------------------------

async fn execute_handler<F, Fut>(
    state: Arc<AppState>,
    ctx: RequestContext,
    handler: F,
) -> Result<Response, EdgeError>
where
    F: FnOnce(Arc<AppState>, RuntimeServices, Request) -> Fut,
    Fut: Future<Output = Result<Response, Report<TrustedServerError>>>,
{
    let services = build_per_request_services(&state, &ctx);
    let mut req = ctx.into_request();
    // The single preparation point for the adapter. Every route in the table
    // except `/health` is registered to `named_route_handler` or
    // `fallback_handler`, and both wrap this function, so each request has its
    // modules' preparers run exactly once and always before routing.
    if let Err(error) = state.registry.prepare_request(&state.settings, &mut req) {
        return Ok(http_error(&error));
    }
    Ok(handler(state, services, req)
        .await
        .unwrap_or_else(|e| http_error(&e)))
}

// ---------------------------------------------------------------------------
// EC context
// ---------------------------------------------------------------------------

/// Builds the geo-aware [`EcContext`] for consent-gated endpoints (`/auction`,
/// `/_ts/page-bids`, and the publisher fallback).
///
/// The geo lookup runs inside
/// [`EcContext::read_from_request_resolving_geo`], so every adapter reports the
/// same distinction: no location falls back to the top of the
/// `permissions.yaml` rules tree, while a failed lookup resolves every
/// permission at the requires-signal floor and is logged at error level.
/// The platform geo is a no-op on the local Axum dev server, so a request there
/// resolves at that top node unless it carries a signal.
///
/// Mirrors the Fastly entry point, which keeps the report and answers with an
/// error response: when the Edge Cookie context cannot be read the request
/// fails rather than continuing with `EcContext::default()`, which would serve
/// every request with no identity. A malformed cookie value, a bad consent
/// string and a failed geo lookup do not reach this error path at all, so
/// failing here does not fail requests for ordinary parse problems.
///
/// # Errors
///
/// Returns an error when the selected Edge Cookie provider cannot be built for
/// this request, or when the request's `Cookie` header is not valid UTF-8.
async fn build_ec_context(
    state: &AppState,
    services: &RuntimeServices,
    req: &Request,
) -> Result<EcContext, Report<TrustedServerError>> {
    EcContext::read_from_request_resolving_geo(&state.settings, req, services).await
}

// ---------------------------------------------------------------------------
// Fallback dispatcher (tsjs / integration proxy / publisher)
// ---------------------------------------------------------------------------

/// Dispatches the fallback routes: tsjs assets, integration proxy routes, and
/// the publisher origin.
///
/// The request arrives already prepared. Every route that reaches here is
/// registered to [`fallback_handler`], which runs the request through
/// [`execute_handler`], and [`execute_handler`] calls
/// `registry.prepare_request` before it calls this function, so preparing
/// again here would run each module's preparer twice for one request.
async fn dispatch_fallback(
    state: &AppState,
    services: &RuntimeServices,
    req: Request,
) -> Result<Response, Report<TrustedServerError>> {
    if let Some(response) = deny_admin_diagnostic_fallback(&req) {
        return Ok(response);
    }

    let path = req.uri().path().to_string();
    let method = req.method().clone();

    if method == Method::GET && path.starts_with("/static/tsjs=") {
        return handle_tsjs_dynamic(&req, &state.registry, EdgeCacheHeader::SMaxageFallback);
    }

    if state.registry.has_route(&method, &path) {
        let mut ec_context = EcContext::default();
        return state
            .registry
            .handle_proxy(ProxyDispatchInput {
                method: &method,
                path: &path,
                settings: &state.settings,
                kv: None,
                ec_context: &mut ec_context,
                services,
                req,
            })
            .await
            .unwrap_or_else(|| {
                Err(Report::new(TrustedServerError::BadRequest {
                    message: format!("Unknown integration route: {path}"),
                }))
            });
    }

    // Run the server-side auction with the configured creative-opportunity
    // slots; `handle_publisher_request` matches them against the request path.
    // Read before routing consumes the request. `ec_finalize_response` needs
    // both, and by the time the response exists the request has been moved.
    let eids_cookie = extract_cookie_value(&req, COOKIE_TS_EIDS);
    let sharedid_cookie = extract_cookie_value(&req, COOKIE_SHAREDID);

    let mut ec_context = build_ec_context(state, services, &req).await?;

    // Classify the device, then generate an identifier when the request is a
    // document navigation by something that looks like a browser. Without this
    // the context resolves an identity decision on every request and never acts
    // on it, so `ec_finalize_response` below has nothing to write and every
    // visitor stays new for ever.
    //
    // Both conditions matter. A subresource request carries no consent signals
    // such as Sec-GPC, so generating from one would create an identity the
    // visitor never had a chance to refuse. And an identifier minted for a
    // crawler is an identity for something that is not a person.
    let client_ip = services
        .client_info()
        .client_ip
        .map_or_else(String::new, |ip| ip.to_string());
    let device_signals = match services.device_provider() {
        Some(provider) => {
            let info = BorrowedRequestInfo::new(&client_ip, Some(req.headers()));
            provider.detect(&info, services).await
        }
        // No module supplies one, so classify from the User-Agent alone.
        //
        // `derive_ua_only`, not `derive`. `derive` is the host-signals path and
        // decides `looks_like_browser` from `ja4_class.is_some()`, so on a host
        // that exposes no TLS fingerprint it calls every visitor a bot and no
        // identifier is ever created. That failure is silent: the page serves
        // correctly and no cookie appears.
        None => DeviceSignals::derive_ua_only(
            req.headers()
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or(""),
        ),
    };
    let looks_like_browser = device_signals.looks_like_browser;
    ec_context.set_device_signals(device_signals);

    if looks_like_browser
        && is_navigation_request(&req)
        && let Err(err) = ec_context
            .generate_if_needed(&state.settings, state.ec_identity_graph.as_ref(), services)
            .await
    {
        log::error!("Edge Cookie generation failed for the publisher path: {err:?}");
    }
    let auction = AuctionDispatch {
        orchestrator: &state.orchestrator,
        slots: state.settings.creative_opportunity_slots(),
        registry: None,
    };
    let publisher_response = handle_publisher_request(
        AppContext {
            settings: &state.settings,
            integration_registry: &state.registry,
        },
        services,
        None,
        &mut ec_context,
        auction,
        req,
        EdgeCacheHeader::SMaxageFallback,
    )
    .await?;
    // Async finalize so the dispatched auction is collected and its bids are
    // injected before `</body>` (the sync buffer path would drop them).
    let mut response = buffer_publisher_response_async(
        publisher_response,
        &method,
        &state.settings,
        &state.registry,
        &state.orchestrator,
        services,
    )
    .await?;

    // Write the Edge Cookie. Until this ran, this adapter resolved an identity
    // per request and then dropped it on the floor: the cookie was never set,
    // so every visitor looked new on their next request and no identity could
    // be carried at all.
    //
    // The identity graph is present when the operator named a store. Without
    // one, core declines to write a generated identifier rather than minting a
    // browser cookie with no row behind it.
    let partner_registry = PartnerRegistry::from_config(&state.settings.ec.partners)?;
    ec_finalize_response(
        &state.settings,
        &ec_context,
        state.ec_identity_graph.as_ref(),
        &partner_registry,
        eids_cookie.as_deref(),
        sharedid_cookie.as_deref(),
        &mut response,
    );

    Ok(response)
}

/// Opens the Edge Cookie identity graph when the operator has named a store.
///
/// Mirrors the Fastly adapter, which builds a graph only when `[ec] ec_store`
/// is set. The difference is that this adapter opens a local database file, so
/// the failure happens at startup rather than on the first request.
///
/// What that failure does is worth stating exactly, because this adapter is
/// inconsistent about it and the difference is not obvious from here. An error
/// returned from this function reaches `build_state`, and `routes` turns that
/// into `startup_error_router`, so **the process keeps running and answers
/// every route with the error**. It does not exit. `init_kv_store` in `main.rs`
/// does exit on the same class of fault, so the platform store and the identity
/// store, both durable state this appliance cannot work without, fail two
/// different ways. Neither is obviously wrong: refusing every request is
/// visible and does not restart-loop a container, exiting is unmissable. They
/// should agree, and today they do not.
fn open_ec_identity_graph(
    settings: &Settings,
) -> Result<Option<KvIdentityGraph>, Report<TrustedServerError>> {
    let Some(store_name) = settings.ec.ec_store.as_deref() else {
        return Ok(None);
    };
    let path = ec_identity_path(store_name);
    let store = AxumEcKvStore::open(&path)?;
    log::info!("Edge Cookie identity store opened at {}", path.display());
    Ok(Some(KvIdentityGraph::new(store)))
}

fn fallback_handler(
    state: Arc<AppState>,
) -> impl Fn(RequestContext) -> HandlerFuture + Clone + Send + Sync + 'static {
    move |ctx: RequestContext| {
        let state = Arc::clone(&state);
        Box::pin(execute_handler(
            state,
            ctx,
            |state, services, req| async move { dispatch_fallback(&state, &services, req).await },
        ))
    }
}

// ---------------------------------------------------------------------------
// Named route table
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum NamedRouteHandler {
    TrustedServerDiscovery,
    VerifySignature,
    AdminNotSupported,
    AdminEcNotSupported,
    AdminEidsLookup,
    /// Legacy `/admin/keys/*` aliases — denied locally with 404 so they never
    /// reach the publisher fallback (which would leak admin credentials).
    LegacyAdminDenied,
    Auction,
    PageBids,
    FirstPartyProxy,
    FirstPartyClick,
    FirstPartySign,
    FirstPartyProxyRebuild,
}

struct NamedRoute {
    path: &'static str,
    primary_methods: &'static [Method],
    handler: NamedRouteHandler,
}

const LEGACY_ADMIN_DENY_METHODS: &[Method] = &[
    Method::GET,
    Method::POST,
    Method::HEAD,
    Method::OPTIONS,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
];

fn named_routes() -> [NamedRoute; 16] {
    [
        NamedRoute {
            path: "/.well-known/trusted-server.json",
            primary_methods: &[Method::GET],
            handler: NamedRouteHandler::TrustedServerDiscovery,
        },
        NamedRoute {
            path: "/verify-signature",
            primary_methods: &[Method::POST],
            handler: NamedRouteHandler::VerifySignature,
        },
        // Canonical admin key routes. These match `Settings::ADMIN_ENDPOINTS`
        // and the production basic-auth handler regex (`^/_ts/admin`), so they
        // are auth-gated under a production-shaped config.
        NamedRoute {
            path: "/_ts/admin/keys/rotate",
            primary_methods: &[Method::POST],
            handler: NamedRouteHandler::AdminNotSupported,
        },
        NamedRoute {
            path: "/_ts/admin/keys/deactivate",
            primary_methods: &[Method::POST],
            handler: NamedRouteHandler::AdminNotSupported,
        },
        // Admin EC lookup routes. Registered explicitly (like the key routes
        // above) so they never fall through to the publisher fallback, and
        // they match `Settings::ADMIN_ENDPOINTS` for auth coverage.
        NamedRoute {
            path: "/_ts/admin/ec",
            primary_methods: &[Method::GET],
            handler: NamedRouteHandler::AdminEcNotSupported,
        },
        NamedRoute {
            path: "/_ts/admin/ec/{id}",
            primary_methods: &[Method::GET],
            handler: NamedRouteHandler::AdminEcNotSupported,
        },
        // Admin EIDs echo: pure request inspection (no KV), so the dev
        // server serves the real handler.
        NamedRoute {
            path: "/_ts/admin/eids",
            primary_methods: &[Method::GET],
            handler: NamedRouteHandler::AdminEidsLookup,
        },
        // The legacy non-`/_ts` aliases (`/admin/keys/*`) are denied locally with
        // a 404, matching the Fastly and Cloudflare adapters: the production
        // basic-auth handler regex `^/_ts/admin` does not match them, and letting
        // any publisher-fallback method fall through would forward the caller's
        // `Authorization` header and key-management payload to the origin,
        // leaking admin credentials.
        NamedRoute {
            path: "/admin/keys/rotate",
            primary_methods: LEGACY_ADMIN_DENY_METHODS,
            handler: NamedRouteHandler::LegacyAdminDenied,
        },
        NamedRoute {
            path: "/admin/keys/deactivate",
            primary_methods: LEGACY_ADMIN_DENY_METHODS,
            handler: NamedRouteHandler::LegacyAdminDenied,
        },
        NamedRoute {
            path: "/auction",
            primary_methods: &[Method::POST],
            handler: NamedRouteHandler::Auction,
        },
        // GET runs the SPA re-auction; OPTIONS is denied in-handler as a CORS
        // preflight guard for this side-effecting endpoint.
        NamedRoute {
            path: PAGE_BIDS_PATH,
            primary_methods: &[Method::GET, Method::OPTIONS],
            handler: NamedRouteHandler::PageBids,
        },
        // Deprecated double-underscore alias, kept so tsjs bundles served before
        // the `/_ts/page-bids` rename keep getting ads on SPA navigations until
        // they age out of browser caches. See `PAGE_BIDS_LEGACY_PATH`.
        NamedRoute {
            path: PAGE_BIDS_LEGACY_PATH,
            primary_methods: &[Method::GET, Method::OPTIONS],
            handler: NamedRouteHandler::PageBids,
        },
        NamedRoute {
            path: "/first-party/proxy",
            primary_methods: &[Method::GET],
            handler: NamedRouteHandler::FirstPartyProxy,
        },
        NamedRoute {
            path: "/first-party/click",
            primary_methods: &[Method::GET],
            handler: NamedRouteHandler::FirstPartyClick,
        },
        NamedRoute {
            path: "/first-party/sign",
            primary_methods: &[Method::GET, Method::POST],
            handler: NamedRouteHandler::FirstPartySign,
        },
        NamedRoute {
            path: "/first-party/proxy-rebuild",
            // GET serves the click guard's navigation fallback: the creative
            // iframe is an opaque origin (sandbox without `allow-same-origin`),
            // so its JSON POST is blocked by CORS and the guard navigates here
            // for a 302 instead.
            primary_methods: &[Method::GET, Method::POST],
            handler: NamedRouteHandler::FirstPartyProxyRebuild,
        },
    ]
}

fn named_route_handler(
    state: Arc<AppState>,
    handler: NamedRouteHandler,
) -> impl Fn(RequestContext) -> HandlerFuture + Clone + Send + Sync + 'static {
    move |ctx: RequestContext| {
        let state = Arc::clone(&state);
        Box::pin(execute_handler(
            state,
            ctx,
            move |state, services, req| async move {
                match handler {
                    NamedRouteHandler::TrustedServerDiscovery => {
                        handle_trusted_server_discovery(&state.settings, &services, req)
                    }
                    NamedRouteHandler::VerifySignature => {
                        handle_verify_signature(&state.settings, &services, req)
                    }
                    NamedRouteHandler::AdminNotSupported => {
                        // Config/secret-store writes are backed by read-only env vars on the
                        // Axum dev server. Returning 501 is clearer than failing on the first
                        // store write.
                        let body = edgezero_core::body::Body::from(
                            "Admin key management is not supported on the Axum dev server.\n\
                             Use the Fastly adapter (via Viceroy or deployed) to rotate or deactivate keys.\n",
                        );
                        let mut resp = Response::new(body);
                        *resp.status_mut() = StatusCode::NOT_IMPLEMENTED;
                        resp.headers_mut().insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("text/plain; charset=utf-8"),
                        );
                        Ok(resp)
                    }
                    NamedRouteHandler::AdminEcNotSupported => {
                        // The EC identity graph is Fastly KV backed; the Axum
                        // dev server has no store to read.
                        Ok(admin_ec_lookup_not_supported())
                    }
                    NamedRouteHandler::AdminEidsLookup => {
                        let partner_registry =
                            PartnerRegistry::from_config(&state.settings.ec.partners)?;
                        handle_admin_eids_lookup(&partner_registry, &req)
                    }
                    NamedRouteHandler::LegacyAdminDenied => Ok(legacy_admin_alias_denied()),
                    NamedRouteHandler::Auction => {
                        // Build the geo-aware EC context so the auction consent
                        // gate sees the caller's jurisdiction — `EcContext::default()`
                        // fails it closed for consented users.
                        let ec_context = build_ec_context(&state, &services, &req).await?;
                        handle_auction(
                            &state.settings,
                            &state.orchestrator,
                            None,
                            None,
                            &ec_context,
                            &services,
                            req,
                        )
                        .await
                    }
                    NamedRouteHandler::PageBids => {
                        // SPA re-auction endpoint. `OPTIONS` is a CORS preflight
                        // for this side-effecting GET and is always denied so the
                        // GET handler's `X-TSJS-Page-Bids` gate stays trustworthy.
                        if req.method() == Method::OPTIONS {
                            Ok(page_bids_preflight_denied())
                        } else {
                            let ec_context = build_ec_context(&state, &services, &req).await?;
                            let auction = AuctionDispatch {
                                orchestrator: &state.orchestrator,
                                slots: state.settings.creative_opportunity_slots(),
                                registry: None,
                            };
                            handle_page_bids(
                                &state.settings,
                                &services,
                                None,
                                auction,
                                &ec_context,
                                req,
                            )
                            .await
                        }
                    }
                    NamedRouteHandler::FirstPartyProxy => {
                        handle_first_party_proxy(&state.settings, &services, req).await
                    }
                    NamedRouteHandler::FirstPartyClick => {
                        handle_first_party_click(&state.settings, &services, req).await
                    }
                    NamedRouteHandler::FirstPartySign => {
                        handle_first_party_proxy_sign(&state.settings, &services, req).await
                    }
                    NamedRouteHandler::FirstPartyProxyRebuild => {
                        handle_first_party_proxy_rebuild(&state.settings, &services, req).await
                    }
                }
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// Startup error fallback
// ---------------------------------------------------------------------------

fn publisher_fallback_methods() -> [Method; 7] {
    [
        Method::GET,
        Method::POST,
        Method::HEAD,
        Method::OPTIONS,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
    ]
}

/// Returns a [`RouterService`] that responds to every route with the startup error.
fn startup_error_router(e: &Report<TrustedServerError>) -> RouterService {
    let message = Arc::new(format!("{}\n", e.current_context().user_message()));
    let status = e.current_context().status_code();

    let make_handler = |msg: Arc<String>| {
        move |_ctx: RequestContext| {
            let body = edgezero_core::body::Body::from((*msg).clone());
            let mut resp = Response::new(body);
            *resp.status_mut() = status;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            async move { Ok::<Response, EdgeError>(resp) }
        }
    };

    let mut router = RouterService::builder().middleware(FinalizeResponseMiddleware::new(
        Arc::new(Settings::default()),
    ));
    for method in publisher_fallback_methods() {
        router = router.route("/", method.clone(), make_handler(Arc::clone(&message)));
        router = router.route("/{*rest}", method, make_handler(Arc::clone(&message)));
    }
    router.build()
}

// ---------------------------------------------------------------------------
// TrustedServerApp
// ---------------------------------------------------------------------------

/// `EdgeZero` [`Hooks`] implementation for the Trusted Server application.
pub struct TrustedServerApp;

impl Hooks for TrustedServerApp {
    fn name() -> &'static str {
        "TrustedServer"
    }

    fn routes() -> RouterService {
        let state = match build_state() {
            Ok(s) => s,
            Err(ref e) => {
                log::error!("failed to build application state: {:?}", e);
                return startup_error_router(e);
            }
        };

        build_router(&state)
    }
}

impl TrustedServerApp {
    /// Build the full application router from explicit settings.
    ///
    /// Testing seam: integration tests use this to drive the router with
    /// known-good settings instead of the baked `get_settings()` result,
    /// whose embedded placeholder secrets fail validation by design.
    ///
    /// # Errors
    ///
    /// Returns an error when the auction orchestrator or the integration
    /// registry fail to initialise.
    pub fn routes_with_settings(
        settings: Settings,
    ) -> Result<RouterService, Report<TrustedServerError>> {
        let state = build_state_with_settings(settings)?;
        Ok(build_router(&state))
    }

    /// Build the full application router from explicit settings, composing the
    /// built-in integrations and auction providers with the externally supplied
    /// builders in `integrations` and `auction_providers`.
    ///
    /// The route table is the one [`TrustedServerApp::routes_with_settings`]
    /// builds, so a composed deployment routes exactly as the plain one does.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected Edge Cookie provider cannot be built
    /// for this adapter, or when the auction orchestrator or the integration
    /// registry fail to initialize, which includes two builders claiming the
    /// same integration id or auction provider name.
    pub fn routes_with_registrations(
        settings: Settings,
        integrations: &[IntegrationBuilder],
        auction_providers: &[AuctionProviderBuilder],
    ) -> Result<RouterService, Report<TrustedServerError>> {
        let state = build_state_with_registrations(settings, integrations, auction_providers)?;
        Ok(build_router(&state))
    }
}

fn build_router(state: &Arc<AppState>) -> RouterService {
    let fallback = fallback_handler(Arc::clone(state));

    let mut router = RouterService::builder()
        // Outermost middleware: strips the configured trusted-client-IP
        // headers before anything else sees the request. Must stay first —
        // any middleware registered ahead of it would observe the
        // shared-secret authentication header.
        .middleware(SanitizeRequestMiddleware::new(Arc::clone(&state.settings)))
        .middleware(FinalizeResponseMiddleware::new(Arc::clone(&state.settings)))
        .middleware(AuthMiddleware::new(Arc::clone(&state.settings)));

    router = router.route("/health", Method::GET, |_ctx: RequestContext| async {
        Ok::<Response, EdgeError>(
            edgezero_core::http::response_builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))
                .body(edgezero_core::body::Body::from("ok"))
                .expect("should build health response"),
        )
    });

    for route in named_routes() {
        for method in route.primary_methods {
            router = router.route(
                route.path,
                method.clone(),
                named_route_handler(Arc::clone(state), route.handler),
            );
        }
        for method in publisher_fallback_methods() {
            if !route.primary_methods.contains(&method) {
                router = router.route(route.path, method, fallback.clone());
            }
        }
    }

    for method in publisher_fallback_methods() {
        router = router.route("/", method.clone(), fallback.clone());
        router = router.route("/{*rest}", method, fallback.clone());
    }

    router.build()
}

#[cfg(test)]
mod tests {
    use edgezero_core::http::request_builder;
    use edgezero_core::params::PathParams;

    use super::*;

    /// Settings selecting a vendor Edge Cookie provider this adapter does not
    /// inject, with the `[ec.providers.<key>]` block configuration validation
    /// requires. `acme` is a fictional vendor key.
    const UNINJECTED_PROVIDER_TOML: &str = r#"
        [[handlers]]
        path = "^/_ts/admin"
        username = "admin"
        password = "admin-pass"

        [publisher]
        domain = "test-publisher.example.com"
        cookie_domain = ".test-publisher.example.com"
        origin_url = "https://origin.test-publisher.example.com"
        proxy_secret = "unit-test-proxy-secret"

        [ec]
        provider = "acme"

        [ec.providers.acme]
        endpoint = "https://ec.acme.example.com"

        # An Edge Cookie provider is configured, so single-jurisdiction
        # operation is acknowledged because no geo provider is selected.
        [geo]
        assume_single_jurisdiction = true
    "#;

    /// Builds application state directly, bypassing the composition root's
    /// startup check, so the per-request behavior can be exercised with a
    /// selection the adapter cannot supply.
    fn state_with_uninjected_provider() -> AppState {
        let settings = Settings::from_toml(UNINJECTED_PROVIDER_TOML)
            .expect("should parse settings selecting an uninjected provider");
        let orchestrator =
            build_orchestrator_with_providers(&settings, &[]).expect("should build orchestrator");
        let registry = IntegrationRegistry::new(&settings).expect("should build registry");
        AppState {
            settings: Arc::new(settings),
            orchestrator: Arc::new(orchestrator),
            registry: Arc::new(registry),
            // No identity graph: this fixture exercises the provider selection
            // error, and opening a database file would make it a slower test
            // of something it is not about.
            ec_identity_graph: None,
        }
    }

    /// The per-request Edge Cookie read must return its error rather than a
    /// default context.
    ///
    /// This adapter used to log the failure and continue with
    /// `EcContext::default()`, so a deployment whose selected provider could not
    /// be built served every request with no identity. The call sites propagate
    /// the error to `http_error`, matching the Fastly adapter.
    #[tokio::test]
    async fn build_ec_context_fails_when_the_selected_provider_is_unavailable() {
        let state = state_with_uninjected_provider();
        let req = request_builder()
            .method("POST")
            .uri("https://test-publisher.example.com/auction")
            .body(edgezero_core::body::Body::empty())
            .expect("should build test request");
        let ctx = RequestContext::new(req, PathParams::default());
        let services = build_runtime_services(&ctx, &state.settings);
        let req = ctx.into_request();

        let error = build_ec_context(&state, &services, &req)
            .await
            .expect_err("an unavailable Edge Cookie provider must fail the request");

        assert!(
            error.to_string().contains("acme"),
            "the error should name the selected provider, got: {error}"
        );
    }
}
