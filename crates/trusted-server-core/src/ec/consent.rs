//! EC-specific permission gating, resolved through the permission model.
//!
//! The Edge Cookie provider advertises the [`Permission`]s its data use
//! requires. [`assemble_permissions`] resolves which permissions are set for a
//! request, from its session signals and the country it maps to, and the
//! context construction gates the provider on that state. The EC permission
//! decision lives here, in the EC subsystem, and nowhere else, so callers
//! route every EC permission check through this module rather than
//! re-deriving one.

use crate::consent::ConsentContext;
use crate::consent::jurisdiction::Jurisdiction;
use std::sync::Arc;

use crate::permission_signal::{PermissionSignalSource, SignalInput};
use crate::permissions::{
    Acquisition, ConsentSignal, OptOutSource, Permission, PermissionMaps, PermissionState,
    SignalPolicy,
};
use crate::platform::GeoInfo;

/// The outcome of the geo lookup for a request, separating "no location
/// resolved" from "the lookup failed".
///
/// The two must not collapse: with no location (the provider is disabled, or
/// had no data for the address) the permission policy's top node applies, but
/// when the lookup errored the request's place is unknown in a way that top
/// node must not paper over, so every permission resolves to the
/// requires-signal floor instead.
#[derive(Debug, Clone, Copy)]
pub enum GeoStatus<'a> {
    /// The provider resolved a location.
    Located(&'a GeoInfo),
    /// The provider resolved no location, so the policy's top node applies.
    NoLocation,
    /// The lookup errored, so the requires-signal floor applies.
    Failed,
}

impl<'a> GeoStatus<'a> {
    /// The resolved location, when one exists.
    #[must_use]
    pub fn info(self) -> Option<&'a GeoInfo> {
        match self {
            GeoStatus::Located(info) => Some(info),
            GeoStatus::NoLocation | GeoStatus::Failed => None,
        }
    }
}

impl<'a> From<Option<&'a GeoInfo>> for GeoStatus<'a> {
    fn from(geo: Option<&'a GeoInfo>) -> Self {
        match geo {
            Some(info) => GeoStatus::Located(info),
            None => GeoStatus::NoLocation,
        }
    }
}

/// The jurisdiction the consent gates apply to a request, from its resolved
/// location or, with none, from the permission policy's top node.
///
/// The consent gates (for example the server-side auction gate) detect a
/// jurisdiction from geolocation. With no location they would resolve
/// `Unknown` and fail closed even where the policy declares what to do, so the
/// same fallback the permission model applies is offered here: the top node's
/// `jurisdiction` stands in for the missing location. A failed lookup stays
/// unknown, so the consent gates fail closed alongside the requires-signal
/// floor.
#[must_use]
pub fn default_jurisdiction(geo: GeoStatus<'_>) -> Jurisdiction {
    match geo {
        GeoStatus::NoLocation => PermissionMaps::standard().default_jurisdiction(),
        GeoStatus::Located(_) | GeoStatus::Failed => Jurisdiction::Unknown,
    }
}

/// Assembles the permission state for a request: the place baseline from the
/// tree in `permissions.yaml`, augmented by the session's signals.
///
/// Permissions exist without a consent model. With no signal present the result
/// is simply the baseline for the request's country and region. When the geo
/// provider resolves no location, or a country/region that has no rule, the
/// policy's top node applies, and the top node's `group` is required so one is
/// always available. A failed lookup ([`GeoStatus::Failed`]) instead resolves
/// every permission to the requires-signal floor, so an outage is handled
/// protectively rather than as the policy's declared default.
#[must_use]
pub fn assemble_permissions(consent: &ConsentContext, geo: GeoStatus<'_>) -> PermissionState {
    assemble_permissions_with(consent, geo, &all_sources())
}

/// As [`assemble_permissions`], for a deployment that has named which signal
/// models run and in what order.
///
/// A model missing from `sources` does not run, so a publisher removes one by
/// leaving it out rather than by configuring it off. An empty slice runs none
/// of them, which leaves every permission at its country and region baseline.
#[must_use]
pub fn assemble_permissions_with(
    consent: &ConsentContext,
    geo: GeoStatus<'_>,
    sources: &[Arc<dyn PermissionSignalSource>],
) -> PermissionState {
    let maps = PermissionMaps::standard();
    let signal = permission_signal(consent, maps.signals(), sources);
    match geo {
        GeoStatus::Failed => PermissionMaps::floor_with(signal),
        GeoStatus::Located(_) | GeoStatus::NoLocation => {
            let info = geo.info();
            maps.resolve_with(
                info.map(|info| info.country.as_str()),
                info.and_then(|info| info.region.as_deref()),
                signal,
            )
        }
    }
}

/// The acquisition rule for Edge Cookie storage in the request's resolved
/// jurisdiction, used to scope destructive withdrawal.
///
/// Resolves the same rules as [`assemble_permissions`] (the request's
/// country/region, the policy's top node when unmatched, and the
/// requires-signal floor when the lookup failed) and returns the rule for
/// [`Permission::StoreOnDevice`].
#[must_use]
pub fn storage_acquisition(geo: GeoStatus<'_>) -> Acquisition {
    match geo {
        GeoStatus::Failed => Acquisition::RequiresSignal,
        GeoStatus::Located(_) | GeoStatus::NoLocation => {
            let info = geo.info();
            PermissionMaps::standard()
                .rules_or_default(
                    info.map(|info| info.country.as_str()),
                    info.and_then(|info| info.region.as_deref()),
                )
                .map_or(Acquisition::RequiresSignal, |rules| {
                    rules.rule_for(Permission::StoreOnDevice)
                })
        }
    }
}

/// Maps a consent context to a [`ConsentSignal`] for each permission, applying
/// the [`SignalPolicy`] the permission model parsed from `permissions.yaml`.
///
/// This is the only place the EC subsystem reads consent signals. The policy,
/// not this function, decides which sources are authoritative, which TCF purpose
/// maps to which Data Use, and what a US-style opt-out revokes. This function
/// only decodes the request and applies that policy, so no signal-to-permission
/// policy lives in the code.
///
/// The models it asks are the ones core supplies (see [`builtin_sources`]),
/// each of which amends what the ones before it settled on. The order is the
/// policy, and [`combine`] documents why. This function only assembles the
/// list and hands each source the request.
///
/// Whether an amendment changes anything is then decided by the country/region
/// map, which drops a `granted` baseline on a `Revoke` and has nothing to drop
/// where the permission is `requires_signal` or `denied`.
///
/// [`combine`]: crate::permission_signal::combine
fn permission_signal<'a>(
    consent: &'a ConsentContext,
    signals: &'a SignalPolicy,
    sources: &'a [Arc<dyn PermissionSignalSource>],
) -> impl Fn(Permission, Acquisition) -> ConsentSignal + 'a {
    move |permission, baseline| {
        // A record that arrived and could not be read fails closed, ahead of
        // every configured model and regardless of which are configured.
        //
        // This is not a signalling model and is deliberately not in the
        // configured list. A publisher chooses which signals to act on; they do
        // not choose what happens when one of those signals arrives unreadable.
        // An unreadable record is a preference someone expressed that cannot be
        // read, which is different from no record at all, so it must not
        // degrade to the no-signal baseline.
        //
        // It overrides rather than taking a place in the order because the
        // ordered rule would otherwise let a readable record from one model
        // overwrite the refusal caused by an unreadable one from another.
        if consent.has_malformed_record() {
            return ConsentSignal::Revoke;
        }
        crate::permission_signal::combine(sources, permission, consent, signals, baseline)
    }
}

/// The identifiers of every signal model core supplies, in the default order.
///
/// Configuration names sources from this list, and
/// [`PermissionSignalConfig::validate_selection`] rejects a name that is not in
/// it at startup rather than silently ignoring it.
///
/// [`PermissionSignalConfig::validate_selection`]:
///     crate::settings::PermissionSignalConfig::validate_selection
pub const SOURCE_IDS: &[&str] = &["gpc", "gpp-sale-opt-out", "us-privacy", "tcf"];

/// Every signal model core supplies, in the default order.
///
/// These were decoded inline until the seam existed. They are the same rules,
/// moved behind [`PermissionSignalSource`] so a further model can be added by a
/// module instead of by editing core.
///
/// The order runs the signals needing no interaction before the ones following
/// a prompt, so a visitor who arrives with an opt-out and then answers a prompt
/// has their answer applied. A deployment wanting the opposite reorders the
/// list in configuration.
///
/// [`PermissionSignalSource`]: crate::permission_signal::PermissionSignalSource
#[must_use]
pub fn all_sources() -> Vec<Arc<dyn PermissionSignalSource>> {
    vec![
        Arc::new(GpcSource),
        Arc::new(GppSaleOptOutSource),
        Arc::new(UsPrivacySource),
        Arc::new(TcfSource),
    ]
}

/// The sources a deployment named, in the order it named them.
///
/// `None` means nothing was configured, which runs all of them in the default
/// order. That is deliberate: a publisher gets every model the build knows
/// about until they say otherwise, so a signal is never quietly ignored because
/// someone forgot to list it.
///
/// A name that matches nothing is dropped here, having already been rejected at
/// startup by [`PermissionSignalConfig::validate_selection`].
///
/// [`PermissionSignalConfig::validate_selection`]:
///     crate::settings::PermissionSignalConfig::validate_selection
#[must_use]
pub fn sources_for(configured: Option<&[String]>) -> Vec<Arc<dyn PermissionSignalSource>> {
    let all = all_sources();
    let Some(names) = configured else {
        return all;
    };
    names
        .iter()
        .filter_map(|name| {
            all.iter()
                .find(|source| source.id() == name.as_str())
                .map(Arc::clone)
        })
        .collect()
}

/// Whether one US-style opt-out takes `permission` away on this request.
///
/// Shared by the three sources below, which differ only in the signal they
/// read. They are separate sources rather than one so that a publisher who does
/// not want to act on Global Privacy Control can leave that source out of the
/// configured list without also losing the GPP and US Privacy opt-outs.
///
/// Which signals count at all, and what an opt-out takes away, remain the
/// policy's decisions. A source that the policy does not list stays silent even
/// when configuration names it, so removing it from `opt_out_sources` in
/// `permissions.yaml` and leaving it out of the list have the same effect.
fn opt_out_signal(
    source: OptOutSource,
    permission: Permission,
    input: &SignalInput<'_>,
) -> ConsentSignal {
    if input.policy.opt_out_sources().contains(&source)
        && opt_out_present(input.consent, &[source])
        && input.policy.opt_out_revokes(permission)
    {
        return ConsentSignal::Revoke;
    }
    ConsentSignal::Neutral
}

/// The `Sec-GPC` request header, Global Privacy Control.
struct GpcSource;

impl PermissionSignalSource for GpcSource {
    fn id(&self) -> &'static str {
        "gpc"
    }

    fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
        opt_out_signal(OptOutSource::Gpc, permission, input)
    }
}

/// A GPP US sale opt-out.
struct GppSaleOptOutSource;

impl PermissionSignalSource for GppSaleOptOutSource {
    fn id(&self) -> &'static str {
        "gpp-sale-opt-out"
    }

    fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
        opt_out_signal(OptOutSource::GppSaleOptOut, permission, input)
    }
}

/// A US Privacy string sale opt-out.
struct UsPrivacySource;

impl PermissionSignalSource for UsPrivacySource {
    fn id(&self) -> &'static str {
        "us-privacy"
    }

    fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
        opt_out_signal(OptOutSource::UsPrivacyOptOut, permission, input)
    }
}

/// TCF v2, when the policy says TCF answers for this deployment.
///
/// The mapping from permission to purpose is the policy's, so this source
/// decodes and does not interpret. A permission no purpose maps to gets
/// silence, not a refusal.
struct TcfSource;

impl PermissionSignalSource for TcfSource {
    fn id(&self) -> &'static str {
        "tcf"
    }

    fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
        if !input.policy.tcf_authoritative() {
            return ConsentSignal::Neutral;
        }
        let Some(tcf) = crate::consent::effective_tcf(input.consent) else {
            return ConsentSignal::Neutral;
        };
        match input.policy.tcf_purpose(permission) {
            Some(purpose) => {
                if tcf.has_purpose_consent(usize::from(purpose)) {
                    ConsentSignal::Grant
                } else {
                    // A purpose the visitor did not consent to is a refusal,
                    // not silence. Reading it as silence would leave the place
                    // baseline standing and grant what they declined.
                    ConsentSignal::Revoke
                }
            }
            None => ConsentSignal::Neutral,
        }
    }
}

/// Whether the request carries any of the `sources` a US-style opt-out is
/// declared to use. Decoding only, so the policy (not this function) decides
/// which sources count and what the opt-out revokes.
fn opt_out_present(consent: &ConsentContext, sources: &[OptOutSource]) -> bool {
    sources.iter().any(|source| match source {
        OptOutSource::Gpc => consent.gpc,
        OptOutSource::GppSaleOptOut => {
            consent.gpp.as_ref().and_then(|gpp| gpp.us_sale_opt_out) == Some(true)
        }
        OptOutSource::UsPrivacyOptOut => consent
            .us_privacy
            .as_ref()
            .is_some_and(|usp| usp.opt_out_sale == crate::consent::PrivacyFlag::Yes),
    })
}

/// Reports whether the request carries an explicit signal withdrawing Edge
/// Cookie storage, rather than merely lacking the permission.
///
/// This separates an affirmative withdrawal (which expires the browser cookie
/// and writes the authoritative identity-graph tombstone) from suppression,
/// where the permission is simply not set for this request (which strips EC
/// response headers but must not destroy an already-issued identifier, or a
/// returning user would be permanently withdrawn before they ever get to
/// consent).
///
/// Only a TCF record refusing storage (Purpose 1) withdraws, and only where
/// the jurisdiction's storage baseline is not `granted`: under a
/// `requires_signal` baseline the refusal is the visitor declining the very
/// signal storage depends on, while under a `granted` baseline storage never
/// depended on the record, so the refusal suppresses use without destroying
/// the identifier. US-style opt-outs (GPC, a GPP sale opt-out, or a US
/// Privacy opt-out) suppress the permissions the policy revokes but are
/// never destructive, and no signal at all is not a withdrawal.
#[must_use]
pub fn ec_storage_withdrawn(consent: &ConsentContext, storage_baseline: Acquisition) -> bool {
    if let Some(tcf) = crate::consent::effective_tcf(consent) {
        return !tcf.has_storage_consent() && !matches!(storage_baseline, Acquisition::Granted);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::TcfConsent;
    use crate::test_support::tests::create_test_settings;

    /// Builds a minimal decoded TCF record consenting to the given 1-indexed
    /// purposes, with everything else refused.
    fn tcf_with_purposes(consented: &[usize]) -> TcfConsent {
        let mut purpose_consents = vec![false; 24];
        for &purpose in consented {
            purpose_consents[purpose - 1] = true;
        }
        TcfConsent {
            version: 2,
            cmp_id: 0,
            cmp_version: 0,
            consent_screen: 0,
            consent_language: "EN".to_owned(),
            vendor_list_version: 0,
            tcf_policy_version: 2,
            created_ds: 0,
            last_updated_ds: 0,
            purpose_consents,
            purpose_legitimate_interests: vec![false; 24],
            vendor_consents: Vec::new(),
            vendor_legitimate_interests: Vec::new(),
            special_feature_opt_ins: vec![false; 12],
        }
    }

    #[test]
    fn hmac_provider_is_blocked_without_a_storage_signal() {
        let settings = create_test_settings();
        // The test settings select the HMAC provider, which requires
        // necessary.operations.storage. The policy's top node resolves storage
        // as requires-signal, so with no signal the permission is not set and
        // the provider's requirement is not met.
        let provider = crate::ec::provider::build_provider(&settings.ec, None, None)
            .expect("should build the configured provider")
            .expect("should select the hmac provider");
        let state = assemble_permissions(&ConsentContext::default(), GeoStatus::NoLocation);
        assert!(
            !state.all_set(provider.required_permissions()),
            "the requires-signal default should not satisfy the HMAC provider without a signal"
        );
    }

    fn us_ca_geo() -> GeoInfo {
        GeoInfo {
            city: String::new(),
            country: "US".to_owned(),
            continent: String::new(),
            latitude: 0.0,
            longitude: 0.0,
            metro_code: 0,
            region: Some("CA".to_owned()),
            asn: None,
        }
    }

    #[test]
    fn no_signal_uses_the_us_opt_out_baseline() {
        // US/CA maps to the us-opt-out group, where every purpose is granted
        // without a signal, so EC identity and bidstream EIDs are both permitted.
        let geo = us_ca_geo();
        let state = assemble_permissions(&ConsentContext::default(), GeoStatus::Located(&geo));
        assert!(
            state.is_set(Permission::StoreOnDevice)
                && state.is_set(Permission::SelectPersonalisedAds),
            "a US opt-out state should grant necessary.operations.storage and advertising_marketing.first_party.targeted"
        );
    }

    #[test]
    fn gpc_revokes_the_granted_baseline_in_a_us_opt_out_state() {
        // A US-style opt-out drops a granted baseline with no jurisdiction match:
        // the map granted these purposes, and GPC revokes them.
        let consent = ConsentContext {
            gpc: true,
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));
        assert!(
            !state.is_set(Permission::StoreOnDevice)
                && !state.is_set(Permission::SelectPersonalisedAds),
            "GPC should revoke the granted necessary.operations.storage and advertising_marketing.first_party.targeted baseline"
        );
    }

    // ------------------------------------------------------------------
    // An unreadable record. Not a model a publisher lists, so it applies
    // whatever they configured, and it is not subject to the ordering.
    // ------------------------------------------------------------------

    #[test]
    fn an_unreadable_record_revokes_even_with_no_models_configured() {
        let consent = ConsentContext {
            raw_tc_string: Some("this is not a TC string".to_owned()),
            ..ConsentContext::default()
        };
        assert!(
            consent.has_malformed_record(),
            "the fixture has to actually be unreadable for this to test anything"
        );
        let geo = us_ca_geo();
        let state = assemble_permissions_with(&consent, GeoStatus::Located(&geo), &[]);
        assert!(
            !state.is_set(Permission::StoreOnDevice),
            "a preference someone expressed that cannot be read must not degrade to the \
             no-signal baseline, and a publisher cannot configure that away"
        );
    }

    #[test]
    fn a_readable_record_does_not_overwrite_an_unreadable_one() {
        // The regression the override exists to prevent: under the ordered
        // rule alone, a TCF record that consents would be asked after the
        // unreadable GPP string and would overwrite the refusal it caused.
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&[1, 4])),
            raw_gpp_string: Some("this is not a GPP string".to_owned()),
            ..ConsentContext::default()
        };
        assert!(consent.has_malformed_record());
        let geo = us_ca_geo();
        let state = assemble_permissions_with(&consent, GeoStatus::Located(&geo), &all_sources());
        assert!(
            !state.is_set(Permission::StoreOnDevice),
            "one model arriving unreadable is not cured by another model arriving readable"
        );
    }

    // ------------------------------------------------------------------
    // Which models run. A publisher names them in [permission_signal]
    // sources, and one left off the list does not run at all.
    // ------------------------------------------------------------------

    /// Every identifier except the one named, in the declared order.
    fn every_source_except(excluded: &str) -> Vec<String> {
        SOURCE_IDS
            .iter()
            .filter(|id| **id != excluded)
            .map(|id| (*id).to_owned())
            .collect()
    }

    #[test]
    fn the_declared_identifiers_match_the_models_that_run() {
        // Configuration is validated against SOURCE_IDS and resolved against
        // all_sources, so the two drifting apart would let a name validate and
        // then match nothing, silently dropping a model.
        let running: Vec<&str> = all_sources().iter().map(|source| source.id()).collect();
        assert_eq!(
            running, SOURCE_IDS,
            "SOURCE_IDS is what configuration is checked against, so it has to be what runs"
        );
    }

    #[test]
    fn naming_nothing_runs_every_model() {
        let ids: Vec<&str> = sources_for(None).iter().map(|source| source.id()).collect();
        assert_eq!(
            ids, SOURCE_IDS,
            "a publisher who configures nothing acts on every signal the build knows, so \
             one is never ignored because they forgot to list it"
        );
    }

    #[test]
    fn the_configured_order_is_the_order_they_are_asked_in() {
        let reversed: Vec<String> = SOURCE_IDS.iter().rev().map(|id| (*id).to_owned()).collect();
        let ids: Vec<String> = sources_for(Some(&reversed))
            .iter()
            .map(|source| source.id().to_owned())
            .collect();
        assert_eq!(
            ids, reversed,
            "the list is the order, not merely the membership"
        );
    }

    #[test]
    fn a_model_left_off_the_list_does_not_run() {
        let consent = ConsentContext {
            gpc: true,
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();

        let everything =
            assemble_permissions_with(&consent, GeoStatus::Located(&geo), &all_sources());
        assert!(
            !everything.is_set(Permission::StoreOnDevice),
            "with every model running, the header takes storage away"
        );

        let without_gpc = every_source_except("gpc");
        let pruned = assemble_permissions_with(
            &consent,
            GeoStatus::Located(&geo),
            &sources_for(Some(&without_gpc)),
        );
        assert!(
            pruned.is_set(Permission::StoreOnDevice),
            "a publisher who does not want to act on Global Privacy Control removes it from \
             the list, and the header then changes nothing"
        );
    }

    #[test]
    fn removing_one_opt_out_leaves_the_others_working() {
        // The reason the three opt-outs are separate sources rather than one.
        let consent = ConsentContext {
            us_privacy: Some(crate::consent::types::UsPrivacy {
                version: 1,
                notice_given: crate::consent::PrivacyFlag::Yes,
                opt_out_sale: crate::consent::PrivacyFlag::Yes,
                lspa_covered: crate::consent::PrivacyFlag::NotApplicable,
            }),
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let without_gpc = every_source_except("gpc");
        let state = assemble_permissions_with(
            &consent,
            GeoStatus::Located(&geo),
            &sources_for(Some(&without_gpc)),
        );
        assert!(
            !state.is_set(Permission::StoreOnDevice),
            "dropping Global Privacy Control must not drop the US Privacy opt-out with it"
        );
    }

    #[test]
    fn running_no_models_leaves_the_place_baseline() {
        let consent = ConsentContext {
            gpc: true,
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions_with(&consent, GeoStatus::Located(&geo), &[]);
        assert!(
            state.is_set(Permission::StoreOnDevice),
            "an empty list is a publisher acting on no signal at all, so only the country \
             and region rules apply"
        );
    }

    #[test]
    fn an_unknown_name_resolves_to_nothing_rather_than_a_wrong_model() {
        // Startup validation rejects this first. The check here is that if one
        // ever reached this far it would drop out rather than match by position.
        let named = vec!["not-a-source".to_owned(), "tcf".to_owned()];
        let ids: Vec<&str> = sources_for(Some(&named))
            .iter()
            .map(|source| source.id())
            .collect();
        assert_eq!(ids, vec!["tcf"]);
    }

    // ------------------------------------------------------------------
    // Opt-out and prompt precedence.
    //
    // These replace an earlier set asserting the opposite, that an opt-out
    // suppressed storage and sharing whatever else the request carried. The
    // sources are now asked in order and each amends what the ones before it
    // settled, so a later source can amend an opt-out.
    //
    // The default order asks the signals needing no interaction first and the
    // ones following a prompt after, which is why a visitor who arrives with
    // an opt-out and then answers a prompt has their answer applied. A
    // deployment wanting the opposite puts the opt-out source last.
    //
    // The layering, the configuration and what a source may consult are in
    // crates/trusted-server-core/src/permission_signal/README.md.
    // ------------------------------------------------------------------

    #[test]
    fn a_prompt_answer_applies_over_a_gpc_signal() {
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&[1, 4])),
            gpc: true,
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));
        assert!(
            state.is_set(Permission::StoreOnDevice),
            "the visitor answered a prompt after arriving with GPC set, and under the \
             default order the answer they gave is applied over the header they sent"
        );
    }

    #[test]
    fn a_prompt_answer_applies_over_a_us_privacy_opt_out_signal() {
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&[1, 4])),
            us_privacy: Some(crate::consent::types::UsPrivacy {
                version: 1,
                notice_given: crate::consent::PrivacyFlag::Yes,
                opt_out_sale: crate::consent::PrivacyFlag::Yes,
                lspa_covered: crate::consent::PrivacyFlag::NotApplicable,
            }),
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));
        assert!(
            state.is_set(Permission::StoreOnDevice),
            "the visitor answered a prompt after arriving with a US Privacy opt-out, and under the \
             default order the answer they gave amends the signal they sent"
        );
    }

    #[test]
    fn a_prompt_answer_applies_over_a_gpp_sale_opt_out_signal() {
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&[1, 4])),
            gpp: Some(crate::consent::types::GppConsent {
                version: 1,
                section_ids: vec![7],
                eu_tcf: None,
                us_sale_opt_out: Some(true),
            }),
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));
        assert!(
            state.is_set(Permission::StoreOnDevice),
            "the visitor answered a prompt after arriving with a GPP sale opt-out, and under the \
             default order the answer they gave amends the signal they sent"
        );
    }

    #[test]
    fn gpc_suppresses_storage_even_when_us_privacy_reports_no_opt_out() {
        let consent = ConsentContext {
            gpc: true,
            us_privacy: Some(crate::consent::types::UsPrivacy {
                version: 1,
                notice_given: crate::consent::PrivacyFlag::Yes,
                opt_out_sale: crate::consent::PrivacyFlag::No,
                lspa_covered: crate::consent::PrivacyFlag::NotApplicable,
            }),
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));
        assert!(
            !state.is_set(Permission::StoreOnDevice),
            "any one opt-out source should suppress, whatever the others say"
        );
    }

    // ------------------------------------------------------------------
    // Withdrawal scoping: only a TCF storage refusal withdraws, and only
    // where the baseline did not grant storage outright. Opt-outs suppress
    // use but never destroy an already-issued identifier.
    // ------------------------------------------------------------------

    #[test]
    fn tcf_storage_refusal_withdraws_under_a_requires_signal_baseline() {
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&[4])),
            ..ConsentContext::default()
        };
        assert!(
            ec_storage_withdrawn(&consent, Acquisition::RequiresSignal),
            "refusing the signal storage depends on should withdraw"
        );
    }

    #[test]
    fn tcf_storage_refusal_does_not_withdraw_under_a_granted_baseline() {
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&[4])),
            ..ConsentContext::default()
        };
        assert!(
            !ec_storage_withdrawn(&consent, Acquisition::Granted),
            "storage never depended on the record here, so refusal suppresses without destroying"
        );
    }

    #[test]
    fn tcf_storage_consent_is_not_a_withdrawal() {
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&[1])),
            ..ConsentContext::default()
        };
        assert!(
            !ec_storage_withdrawn(&consent, Acquisition::RequiresSignal),
            "a consenting record is not a withdrawal"
        );
    }

    #[test]
    fn gpc_alone_never_withdraws() {
        let consent = ConsentContext {
            gpc: true,
            ..ConsentContext::default()
        };
        assert!(
            !ec_storage_withdrawn(&consent, Acquisition::Granted)
                && !ec_storage_withdrawn(&consent, Acquisition::RequiresSignal),
            "GPC suppresses use for the request but never destroys the identifier"
        );
    }

    #[test]
    fn us_style_opt_outs_never_withdraw() {
        let consent = ConsentContext {
            us_privacy: Some(crate::consent::types::UsPrivacy {
                version: 1,
                notice_given: crate::consent::PrivacyFlag::Yes,
                opt_out_sale: crate::consent::PrivacyFlag::Yes,
                lspa_covered: crate::consent::PrivacyFlag::NotApplicable,
            }),
            gpp: Some(crate::consent::types::GppConsent {
                version: 1,
                section_ids: vec![7],
                eu_tcf: None,
                us_sale_opt_out: Some(true),
            }),
            ..ConsentContext::default()
        };
        assert!(
            !ec_storage_withdrawn(&consent, Acquisition::RequiresSignal),
            "sale opt-outs suppress use but never destroy the identifier"
        );
    }

    #[test]
    fn no_signal_is_not_a_withdrawal() {
        assert!(
            !ec_storage_withdrawn(&ConsentContext::default(), Acquisition::RequiresSignal),
            "absence of a signal must never destroy an identifier"
        );
    }

    #[test]
    fn a_malformed_record_is_not_a_withdrawal() {
        let consent = ConsentContext {
            raw_tc_string: Some("not-a-tc-string".to_owned()),
            ..ConsentContext::default()
        };
        assert!(
            !ec_storage_withdrawn(&consent, Acquisition::RequiresSignal),
            "an unreadable record fails closed (suppression), not destructively"
        );
    }

    // ------------------------------------------------------------------
    // Malformed-but-present records block baseline grants (fail closed)
    // instead of degrading to the no-signal baseline.
    // ------------------------------------------------------------------

    #[test]
    fn a_malformed_tcf_record_blocks_baseline_grants() {
        let consent = ConsentContext {
            raw_tc_string: Some("not-a-tc-string".to_owned()),
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));
        assert!(
            !state.is_set(Permission::StoreOnDevice),
            "an unreadable record should block the granted baseline, not vanish"
        );
    }

    #[test]
    fn a_malformed_gpp_or_us_privacy_record_is_detected() {
        let gpp = ConsentContext {
            raw_gpp_string: Some("not-a-gpp-string".to_owned()),
            ..ConsentContext::default()
        };
        let usp = ConsentContext {
            raw_us_privacy: Some("bogus".to_owned()),
            ..ConsentContext::default()
        };
        assert!(
            gpp.has_malformed_record() && usp.has_malformed_record(),
            "each undecodable record form should be detected"
        );
    }

    #[test]
    fn an_expired_tcf_record_is_not_treated_as_malformed() {
        let consent = ConsentContext {
            raw_tc_string: Some("CPc-old-string".to_owned()),
            expired: true,
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));
        assert!(
            state.is_set(Permission::StoreOnDevice),
            "expiry is its own explicit state, deliberately distinct from malformed"
        );
    }

    // ------------------------------------------------------------------
    // Geo status: a failed lookup resolves at the requires-signal floor and
    // never consults the tree, while no location resolves at the policy's top
    // node.
    // ------------------------------------------------------------------

    #[test]
    fn a_failed_geo_lookup_resolves_to_the_requires_signal_floor() {
        // The same request, located in a US opt-out state, grants storage
        // without a signal. A failed lookup must not reach that rule, or any
        // other, so nothing is set without a signal.
        let geo = us_ca_geo();
        assert!(
            assemble_permissions(&ConsentContext::default(), GeoStatus::Located(&geo))
                .is_set(Permission::StoreOnDevice),
            "the located baseline must grant storage, or this test proves nothing"
        );
        let state = assemble_permissions(&ConsentContext::default(), GeoStatus::Failed);
        assert!(
            !state.is_set(Permission::StoreOnDevice),
            "a lookup failure must not fall back to any node of the policy tree"
        );
        assert_eq!(
            storage_acquisition(GeoStatus::Failed),
            Acquisition::RequiresSignal,
            "the storage baseline follows the same floor on failure"
        );
    }

    #[test]
    fn no_location_falls_back_to_the_policy_top_node() {
        // The shipped policy's top node is the gdpr-eu group, which requires a
        // signal for storage, so an unplaced visitor gets no identifier until
        // one arrives.
        let state = assemble_permissions(&ConsentContext::default(), GeoStatus::NoLocation);
        assert!(
            !state.is_set(Permission::StoreOnDevice),
            "the top node requires a signal for storage"
        );
        assert_eq!(
            storage_acquisition(GeoStatus::NoLocation),
            Acquisition::RequiresSignal,
            "the storage baseline follows the top node on no location"
        );
    }

    #[test]
    fn no_location_takes_the_jurisdiction_from_the_policy_top_node() {
        assert_eq!(
            default_jurisdiction(GeoStatus::NoLocation),
            Jurisdiction::Gdpr,
            "no location should resolve the top node's declared jurisdiction"
        );
        assert_eq!(
            default_jurisdiction(GeoStatus::Failed),
            Jurisdiction::Unknown,
            "a failed lookup must not adopt the policy's declared jurisdiction"
        );
    }

    #[test]
    fn tcf_resolves_every_mapped_purpose_not_just_storage_and_ads() {
        // A TCF record now grants or revokes every one of the eleven mapped
        // purposes, not only Purpose 1 and Purpose 4. Consent to all purposes
        // except Purpose 7 (measure ad performance), in a US opt-out state where
        // the baseline granted them all, so a revoke is observable as a drop.
        let consented: Vec<usize> = (1..=11).filter(|&p| p != 7).collect();
        let consent = ConsentContext {
            tcf: Some(tcf_with_purposes(&consented)),
            ..ConsentContext::default()
        };
        let geo = us_ca_geo();
        let state = assemble_permissions(&consent, GeoStatus::Located(&geo));

        // Purpose 2 is now resolved (it was neutral before), so consent sets it.
        assert!(
            state.is_set(Permission::SelectBasicAds),
            "Purpose 2 consent should set advertising_marketing.first_party.contextual"
        );
        // Purpose 7 was refused, so the granted baseline is revoked.
        assert!(
            !state.is_set(Permission::MeasureAdPerformance),
            "Purpose 7 refusal should revoke analytics.ad_reporting.measure_ad_performance"
        );
        // The originally wired purposes still behave.
        assert!(
            state.is_set(Permission::StoreOnDevice)
                && state.is_set(Permission::SelectPersonalisedAds),
            "Purposes 1 and 4 remain resolved from the TCF record"
        );
    }
}
