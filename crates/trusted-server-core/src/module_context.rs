//! One context for every module, and the values a module's process function
//! may name as parameters.
//!
//! Core builds one [`ModuleContext`] where it calls modules, from what the
//! request already holds. The context borrows everything it carries, so
//! building it copies no request data, and every module called there borrows
//! the same context. Each module is handed a [`ModuleCall`], being the context
//! together with the permissions that module declares.
//!
//! A module's process function names what it needs as parameters, and
//! [`ModuleCall::inject`] passes each one in from the context. A parameter may
//! be any type that implements [`FromModuleContext`], an `Option` of one, which
//! is `None` when the value cannot be passed, or a tuple of them. The function
//! shapes that can be called are in [`inject`].
//!
//! | Parameter | What it is | Absent where |
//! | --- | --- | --- |
//! | [`ModuleRequest`] | method, path, query, host and scheme | never |
//! | `&dyn RequestInfo` | the reader's evidence, headers and client IP | the work is shared by every reader |
//! | `&ClientInfo` | the reader's connection | as above |
//! | [`ModuleResponse`] | status and headers | no response exists yet |
//! | `&PermissionState` | the permissions resolved for the request | before they are resolved, and where the work is shared |
//! | `&ConsentContext` | the decoded consent signals | as above |
//! | `&Settings` | the deployment's settings | a stored page's fetch plan |
//! | `&RuntimeServices` | stores, caches, backends and the HTTP client | as above |
//! | `&GeoInfo` | the reader's location | no location resolved, or withheld |
//! | `&DeviceSignals` | the device classification | not classified, or withheld |
//! | [`EdgeCookie`] | the request's Edge Cookie identifier | none, or withheld |
//! | `&IntegrationDocumentState` | state shared by middleware on one document | outside a document |
//! | [`ModuleExtensions`] | the request's typed extension map | outside a page request |
//!
//! # Permissions
//!
//! Geo, the device signals and the Edge Cookie identifier each carry the
//! permissions the module that produced them declares. Such a value is passed
//! only to a module that declares every one of those permissions and is granted
//! them on this request. A value whose producer declares none is passed to
//! every module, because evidence is not rationed and its use is what the
//! permissions govern. When a value is withheld, an `Option` parameter is
//! `None`, and a call naming the value itself is skipped, with the reason in
//! the debug log.

use core::fmt;
use std::sync::Mutex;

use edgezero_core::body::Body as EdgeBody;
use http::{HeaderMap, Method, StatusCode};

use crate::consent::ConsentContext;
use crate::ec::EcContext;
use crate::ec::device::DeviceSignals;
use crate::error::TrustedServerError;
use crate::evidence::RequestInfo;
use crate::geo::GeoInfo;
use crate::integrations::IntegrationDocumentState;
use crate::permissions::{PermissionSet, PermissionState};
use crate::platform::{ClientInfo, RuntimeServices};
use crate::settings::Settings;

pub mod inject;

pub use inject::{Process, ProcessWith};

/// What a request resolved to: its method and address, and the host and
/// scheme it was made for.
///
/// Carries nothing about who asked, so it is in every context, including those
/// whose work is shared by every reader.
#[derive(Debug, Clone, Copy)]
pub struct ModuleRequest<'r> {
    method: &'r Method,
    path: &'r str,
    query: &'r str,
    host: &'r str,
    scheme: &'r str,
}

impl<'r> ModuleRequest<'r> {
    /// A request for `path` on `host` over `scheme`, with no query.
    #[must_use]
    pub fn new(method: &'r Method, host: &'r str, scheme: &'r str, path: &'r str) -> Self {
        Self {
            method,
            path,
            query: "",
            host,
            scheme,
        }
    }

    /// The same request with the query string, without its leading `?`.
    #[must_use]
    pub fn with_query(self, query: &'r str) -> Self {
        Self { query, ..self }
    }

    /// The request method.
    #[must_use]
    pub fn method(&self) -> &'r Method {
        self.method
    }

    /// The URL path, without the query string.
    #[must_use]
    pub fn path(&self) -> &'r str {
        self.path
    }

    /// The query string, without its leading `?`, or `""`.
    #[must_use]
    pub fn query(&self) -> &'r str {
        self.query
    }

    /// The publisher-facing host the reader asked for.
    #[must_use]
    pub fn host(&self) -> &'r str {
        self.host
    }

    /// The publisher-facing scheme the reader asked for.
    #[must_use]
    pub fn scheme(&self) -> &'r str {
        self.scheme
    }
}

/// A [`ModuleRequest`] that owns its parts, for a caller that must keep them
/// past the borrow of the request, such as one that hands the request on.
#[derive(Debug, Clone)]
pub struct ResolvedRequest {
    method: Method,
    path: String,
    query: String,
    host: String,
    scheme: String,
}

impl ResolvedRequest {
    /// The method, address, host and scheme of `request`, the host and
    /// scheme read as the publisher path reads them.
    #[must_use]
    pub fn of(request: &http::Request<EdgeBody>, client: &ClientInfo) -> Self {
        let resolved = crate::http_util::RequestInfo::from_request(request, client);
        Self {
            method: request.method().clone(),
            path: request.uri().path().to_owned(),
            query: request.uri().query().unwrap_or_default().to_owned(),
            host: resolved.host,
            scheme: resolved.scheme,
        }
    }

    /// The borrowed view a context carries.
    #[must_use]
    pub fn view(&self) -> ModuleRequest<'_> {
        ModuleRequest::new(&self.method, &self.host, &self.scheme, &self.path)
            .with_query(&self.query)
    }
}

/// The response a module runs on.
#[derive(Debug, Clone, Copy)]
pub struct ModuleResponse<'r> {
    status: StatusCode,
    headers: &'r HeaderMap,
}

impl<'r> ModuleResponse<'r> {
    /// A response with `status` and `headers`.
    #[must_use]
    pub fn new(status: StatusCode, headers: &'r HeaderMap) -> Self {
        Self { status, headers }
    }

    /// The response status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &'r HeaderMap {
        self.headers
    }
}

/// The request's Edge Cookie identifier, as the module that created it wrote
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeCookie<'r>(&'r str);

impl<'r> EdgeCookie<'r> {
    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &'r str {
        self.0
    }
}

/// The request's typed extension map, where a module leaves a value for a
/// later one on the same request.
///
/// A page request's preparers are handed it writable, and the serve
/// middleware read what they left. Everywhere else it is read only.
#[derive(Clone, Copy)]
pub struct ModuleExtensions<'r>(ExtensionsSource<'r>);

#[derive(Clone, Copy)]
enum ExtensionsSource<'r> {
    ReadOnly(&'r http::Extensions),
    Writable(&'r Mutex<http::Extensions>),
}

impl<'r> ModuleExtensions<'r> {
    /// The map, read only.
    #[must_use]
    pub fn read_only(extensions: &'r http::Extensions) -> Self {
        Self(ExtensionsSource::ReadOnly(extensions))
    }

    /// The map, which a module may add to.
    #[must_use]
    pub fn writable(extensions: &'r Mutex<http::Extensions>) -> Self {
        Self(ExtensionsSource::Writable(extensions))
    }

    /// A copy of the value of type `T`, when the map holds one.
    #[must_use]
    pub fn get<T: Clone + Send + Sync + 'static>(&self) -> Option<T> {
        match self.0 {
            ExtensionsSource::ReadOnly(extensions) => extensions.get::<T>().cloned(),
            ExtensionsSource::Writable(extensions) => extensions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get::<T>()
                .cloned(),
        }
    }

    /// Puts `value` in the map, in place of any value of its type.
    ///
    /// # Errors
    ///
    /// Gives `value` back when the map is read only here.
    pub fn insert<T: Clone + Send + Sync + 'static>(&self, value: T) -> Result<(), T> {
        match self.0 {
            ExtensionsSource::ReadOnly(_) => Err(value),
            ExtensionsSource::Writable(extensions) => {
                extensions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(value);
                Ok(())
            }
        }
    }
}

impl fmt::Debug for ModuleExtensions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let writable = matches!(self.0, ExtensionsSource::Writable(_));
        f.debug_struct("ModuleExtensions")
            .field("writable", &writable)
            .finish_non_exhaustive()
    }
}

/// A value whose use needs the permissions its producer declares.
struct Gated<'r, T: ?Sized> {
    value: &'r T,
    requires: PermissionSet,
}

impl<T: ?Sized> Clone for Gated<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for Gated<'_, T> {}

/// Everything a module may be passed for one request.
///
/// Built once where core calls modules, by borrowing what the request already
/// holds, and borrowed by every module called there. A module never sees it
/// directly. It is handed a [`ModuleCall`] and names what it needs, see
/// [`ModuleCall::inject`].
pub struct ModuleContext<'r> {
    request: ModuleRequest<'r>,
    evidence: Option<&'r dyn RequestInfo>,
    client: Option<&'r ClientInfo>,
    response: Option<ModuleResponse<'r>>,
    permissions: Option<&'r PermissionState>,
    consent: Option<&'r ConsentContext>,
    settings: Option<&'r Settings>,
    services: Option<&'r RuntimeServices>,
    geo: Option<Gated<'r, GeoInfo>>,
    device: Option<Gated<'r, DeviceSignals>>,
    edge_cookie: Option<Gated<'r, str>>,
    document_state: Option<&'r IntegrationDocumentState>,
    extensions: Option<ModuleExtensions<'r>>,
}

impl<'r> ModuleContext<'r> {
    /// A context carrying `request` and nothing else.
    ///
    /// This is the context of work shared by every reader, such as a stored
    /// page's fetch plan, until the builder methods add to it.
    #[must_use]
    pub fn new(request: ModuleRequest<'r>) -> Self {
        Self {
            request,
            evidence: None,
            client: None,
            response: None,
            permissions: None,
            consent: None,
            settings: None,
            services: None,
            geo: None,
            device: None,
            edge_cookie: None,
            document_state: None,
            extensions: None,
        }
    }

    /// The same context carrying the reader's evidence.
    #[must_use]
    pub fn with_evidence(self, evidence: &'r dyn RequestInfo) -> Self {
        Self {
            evidence: Some(evidence),
            ..self
        }
    }

    /// The same context carrying the reader's connection.
    #[must_use]
    pub fn with_client(self, client: &'r ClientInfo) -> Self {
        Self {
            client: Some(client),
            ..self
        }
    }

    /// The same context carrying the response a module runs on.
    #[must_use]
    pub fn with_response(self, response: ModuleResponse<'r>) -> Self {
        Self {
            response: Some(response),
            ..self
        }
    }

    /// The same context carrying the permissions resolved for the request.
    #[must_use]
    pub fn with_permissions(self, permissions: &'r PermissionState) -> Self {
        Self {
            permissions: Some(permissions),
            ..self
        }
    }

    /// The same context carrying the request's decoded consent signals.
    #[must_use]
    pub fn with_consent(self, consent: &'r ConsentContext) -> Self {
        Self {
            consent: Some(consent),
            ..self
        }
    }

    /// The same context carrying the deployment's settings.
    #[must_use]
    pub fn with_settings(self, settings: &'r Settings) -> Self {
        Self {
            settings: Some(settings),
            ..self
        }
    }

    /// The same context carrying the request's services.
    #[must_use]
    pub fn with_services(self, services: &'r RuntimeServices) -> Self {
        Self {
            services: Some(services),
            ..self
        }
    }

    /// The same context carrying the reader's location, whose use needs
    /// `requires`, being what the geo module that resolved it declares.
    #[must_use]
    pub fn with_geo(self, geo: &'r GeoInfo, requires: PermissionSet) -> Self {
        Self {
            geo: Some(Gated {
                value: geo,
                requires,
            }),
            ..self
        }
    }

    /// The same context carrying the device signals, whose use needs
    /// `requires`, being what the device module that derived them declares.
    #[must_use]
    pub fn with_device(self, device: &'r DeviceSignals, requires: PermissionSet) -> Self {
        Self {
            device: Some(Gated {
                value: device,
                requires,
            }),
            ..self
        }
    }

    /// The same context carrying the request's Edge Cookie identifier, whose
    /// use needs `requires`, being what the Edge Cookie module declares.
    #[must_use]
    pub fn with_edge_cookie(self, id: &'r str, requires: PermissionSet) -> Self {
        Self {
            edge_cookie: Some(Gated {
                value: id,
                requires,
            }),
            ..self
        }
    }

    /// The same context carrying the state shared by the middleware working
    /// on one document.
    #[must_use]
    pub fn with_document_state(self, document_state: &'r IntegrationDocumentState) -> Self {
        Self {
            document_state: Some(document_state),
            ..self
        }
    }

    /// The same context carrying the request's typed extension map.
    #[must_use]
    pub fn with_extensions(self, extensions: ModuleExtensions<'r>) -> Self {
        Self {
            extensions: Some(extensions),
            ..self
        }
    }

    /// The same context carrying what the request's Edge Cookie state holds,
    /// being its permissions, consent, location, device signals and Edge
    /// Cookie identifier, and the request's services and connection.
    ///
    /// Each gated value needs what its producer declares. The location needs
    /// what the geo module in `services` declares, the device signals what the
    /// device module in `services` declares, and the identifier what the Edge
    /// Cookie module the state was built with declares.
    #[must_use]
    pub fn with_request_state(self, state: &'r EcContext, services: &'r RuntimeServices) -> Self {
        let mut context = self
            .with_services(services)
            .with_client(services.client_info())
            .with_permissions(state.permissions())
            .with_consent(state.consent());
        if let Some(geo) = state.geo_info() {
            context = context.with_geo(geo, services.geo().required_permissions());
        }
        if let Some(device) = state.device_signals() {
            let requires = services
                .device_module()
                .map_or_else(PermissionSet::none, |module| module.required_permissions());
            context = context.with_device(device, requires);
        }
        if let (Some(id), Some(module)) = (state.ec_value(), state.selected_module()) {
            context = context.with_edge_cookie(id, module.required_permissions());
        }
        context
    }

    /// What the request resolved to.
    #[must_use]
    pub fn request(&self) -> ModuleRequest<'r> {
        self.request
    }

    /// The call to one module, named `module`, which declares the permissions
    /// in `declared`.
    #[must_use]
    pub fn call(&self, module: &'static str, declared: PermissionSet) -> ModuleCall<'_> {
        ModuleCall {
            context: self,
            module,
            declared,
        }
    }
}

impl fmt::Debug for ModuleContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleContext")
            .field("request", &self.request)
            .field("evidence", &self.evidence.is_some())
            .field("response", &self.response.map(|response| response.status))
            .field("permissions", &self.permissions.is_some())
            .field("settings", &self.settings.is_some())
            .field("services", &self.services.is_some())
            .field("geo", &self.geo.is_some())
            .field("device", &self.device.is_some())
            .field("edge_cookie", &self.edge_cookie.is_some())
            .finish_non_exhaustive()
    }
}

/// Core's call to one module, being the request's [`ModuleContext`] and the
/// permissions the module declares.
///
/// A module's process function is handed its parameters through
/// [`inject`](Self::inject).
#[derive(Debug, Clone, Copy)]
pub struct ModuleCall<'c> {
    context: &'c ModuleContext<'c>,
    module: &'static str,
    declared: PermissionSet,
}

impl<'c> ModuleCall<'c> {
    /// The module being called.
    #[must_use]
    pub fn module(&self) -> &'static str {
        self.module
    }

    /// The permissions the module declares.
    #[must_use]
    pub fn declared(&self) -> PermissionSet {
        self.declared
    }

    /// A gated value, when this module may be passed it.
    fn gated<T: ?Sized>(
        &self,
        value: Option<Gated<'c, T>>,
        name: &'static str,
    ) -> Result<&'c T, Withheld> {
        let gated = value.ok_or(Withheld::absent(name))?;
        if gated.requires.is_empty() {
            return Ok(gated.value);
        }
        let undeclared = gated.requires.difference(self.declared);
        if !undeclared.is_empty() {
            return Err(Withheld::new(name, WithheldReason::NotDeclared(undeclared)));
        }
        let state = self
            .context
            .permissions
            .ok_or(Withheld::new(name, WithheldReason::Unresolved))?;
        let unset = gated.requires.difference(state.permissions());
        if !unset.is_empty() {
            return Err(Withheld::new(name, WithheldReason::NotGranted(unset)));
        }
        Ok(gated.value)
    }
}

/// Why a value is not passed to a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withheld {
    value: &'static str,
    reason: WithheldReason,
}

/// What kept a value from a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithheldReason {
    /// The context carries no such value where this module runs.
    Absent,
    /// The module does not declare these permissions, which the value's use
    /// needs.
    NotDeclared(PermissionSet),
    /// These permissions, which the value's use needs, are not set on this
    /// request.
    NotGranted(PermissionSet),
    /// The value's use needs permissions, and none are resolved where this
    /// module runs.
    Unresolved,
}

impl Withheld {
    fn new(value: &'static str, reason: WithheldReason) -> Self {
        Self { value, reason }
    }

    fn absent(value: &'static str) -> Self {
        Self::new(value, WithheldReason::Absent)
    }

    /// The value that was withheld, such as `geo`.
    #[must_use]
    pub fn value(&self) -> &'static str {
        self.value
    }

    /// Why it was withheld.
    #[must_use]
    pub fn reason(&self) -> WithheldReason {
        self.reason
    }
}

impl fmt::Display for Withheld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.value;
        match self.reason {
            WithheldReason::Absent => write!(f, "there is no {value} where this module runs"),
            WithheldReason::NotDeclared(missing) => write!(
                f,
                "{value} is withheld because the module does not declare {missing}, which its \
                 use needs"
            ),
            WithheldReason::NotGranted(missing) => write!(
                f,
                "{value} is withheld because {missing} is not set on this request"
            ),
            WithheldReason::Unresolved => write!(
                f,
                "{value} is withheld because its use needs permissions and none are resolved \
                 where this module runs"
            ),
        }
    }
}

impl core::error::Error for Withheld {}

/// A route whose parameter is withheld answers `403`, the same as a route
/// refusing a permission itself.
impl From<Withheld> for error_stack::Report<TrustedServerError> {
    fn from(withheld: Withheld) -> Self {
        error_stack::Report::new(TrustedServerError::Forbidden {
            message: withheld.to_string(),
        })
    }
}

/// A value a module's process function can name as a parameter.
///
/// Implemented for each value a [`ModuleContext`] carries, for an `Option` of
/// one, which is `None` rather than withheld, and for tuples of up to eight.
pub trait FromModuleContext<'c>: Sized {
    /// The value for this call.
    ///
    /// # Errors
    ///
    /// [`Withheld`] when the context carries no such value here, or when the
    /// value's use needs a permission this module does not declare or is not
    /// granted.
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld>;
}

impl<'c, T: FromModuleContext<'c>> FromModuleContext<'c> for Option<T> {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        Ok(T::from_module_context(call).ok())
    }
}

impl<'c> FromModuleContext<'c> for ModuleRequest<'c> {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        Ok(call.context.request)
    }
}

impl<'c> FromModuleContext<'c> for &'c dyn RequestInfo {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context
            .evidence
            .ok_or(Withheld::absent("request evidence"))
    }
}

impl<'c> FromModuleContext<'c> for &'c ClientInfo {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context.client.ok_or(Withheld::absent("client info"))
    }
}

impl<'c> FromModuleContext<'c> for ModuleResponse<'c> {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context.response.ok_or(Withheld::absent("response"))
    }
}

impl<'c> FromModuleContext<'c> for &'c PermissionState {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context
            .permissions
            .ok_or(Withheld::absent("permissions"))
    }
}

impl<'c> FromModuleContext<'c> for &'c ConsentContext {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context.consent.ok_or(Withheld::absent("consent"))
    }
}

impl<'c> FromModuleContext<'c> for &'c Settings {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context.settings.ok_or(Withheld::absent("settings"))
    }
}

impl<'c> FromModuleContext<'c> for &'c RuntimeServices {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context.services.ok_or(Withheld::absent("services"))
    }
}

impl<'c> FromModuleContext<'c> for &'c GeoInfo {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.gated(call.context.geo, "geo")
    }
}

impl<'c> FromModuleContext<'c> for &'c DeviceSignals {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.gated(call.context.device, "device signals")
    }
}

impl<'c> FromModuleContext<'c> for EdgeCookie<'c> {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.gated(call.context.edge_cookie, "the Edge Cookie")
            .map(EdgeCookie)
    }
}

impl<'c> FromModuleContext<'c> for &'c IntegrationDocumentState {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context
            .document_state
            .ok_or(Withheld::absent("document state"))
    }
}

impl<'c> FromModuleContext<'c> for ModuleExtensions<'c> {
    fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
        call.context
            .extensions
            .ok_or(Withheld::absent("request extensions"))
    }
}

/// A tuple of values is passed when every one of them is.
macro_rules! tuple_from_module_context {
    ($($value:ident),+) => {
        impl<'c, $($value: FromModuleContext<'c>),+> FromModuleContext<'c> for ($($value,)+) {
            fn from_module_context(call: &ModuleCall<'c>) -> Result<Self, Withheld> {
                Ok(($($value::from_module_context(call)?,)+))
            }
        }
    };
}

tuple_from_module_context!(A1);
tuple_from_module_context!(A1, A2);
tuple_from_module_context!(A1, A2, A3);
tuple_from_module_context!(A1, A2, A3, A4);
tuple_from_module_context!(A1, A2, A3, A4, A5);
tuple_from_module_context!(A1, A2, A3, A4, A5, A6);
tuple_from_module_context!(A1, A2, A3, A4, A5, A6, A7);
tuple_from_module_context!(A1, A2, A3, A4, A5, A6, A7, A8);

#[cfg(test)]
mod tests;
