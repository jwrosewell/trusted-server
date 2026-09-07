//! Where a permission signal comes from.
//!
//! # Why this is a seam
//!
//! Permissions are the primitive, and consent is only one of several ways a
//! permission is established. The permission model says so and the language
//! throughout enforces it. The **sources** did not follow: TCF, GPP, US Privacy
//! and Global Privacy Control were decoded inside core and reachable only
//! through one struct, so a fifth way of learning a permission could not exist
//! without changing core.
//!
//! That is the same closed list the provider work already opened for geo,
//! device detection and Edge Cookie identity. This opens it for signals.
//!
//! # How sources differ from providers
//!
//! Geo, device and identity **select** one implementation: a request has one
//! country, one device answer, one identifier. Signals **compose**: a request
//! can carry a TCF string and a Global Privacy Control header at once, and both
//! have something to say. So a deployment collects a list rather than choosing
//! one, and [`combine`] decides what the list means together.
//!
//! # The combining rule
//!
//! A refusal beats a grant, and a grant beats silence:
//!
//! 1. Any source saying [`ConsentSignal::Revoke`] decides the answer.
//! 2. Otherwise any source saying [`ConsentSignal::Grant`] decides it.
//! 3. Otherwise [`ConsentSignal::Neutral`], and the place baseline stands.
//!
//! This is not a new policy. It is the precedence the hard-coded version
//! already had, written down: an opt-out revoked whatever TCF said, a malformed
//! record revoked, and an absent signal left the baseline alone. Expressing it
//! as a rule rather than as the order of three `if` statements is the point,
//! because a rule can take a fourth source without being rewritten.
//!
//! A source that has nothing to say about a permission returns `Neutral`, which
//! is different from `Revoke`. Silence is not refusal, and a source that
//! confused the two would revoke every permission it had no opinion on.

use std::sync::Arc;

use crate::permissions::{ConsentSignal, Permission, SignalPolicy};

use super::ConsentContext;

/// What a signal source may read about a request.
///
/// Deliberately a struct rather than a parameter list, so a source that needs
/// something new does not change every implementation. Today that is the
/// decoded consent record and the policy; a source reading a cookie of its own
/// will need the request, and adding it here will not disturb the four below.
pub struct SignalInput<'a> {
    /// The decoded consent record for this request.
    pub consent: &'a ConsentContext,
    /// The policy from `permissions.yaml`, which decides what a signal means
    /// rather than leaving each source to invent its own meaning.
    pub policy: &'a SignalPolicy,
}

/// A source of permission signals.
///
/// An implementation answers for one signalling model. It reads the request,
/// applies whatever the policy says about its own model, and returns what it
/// knows about one permission.
///
/// # Contract
///
/// Answer `Neutral` for a permission this source has no opinion on, including
/// when the signal it reads is absent from the request. Returning `Revoke` for
/// an absent signal would turn silence into refusal and revoke every permission
/// on every request that did not carry this model.
pub trait PermissionSignalSource: Send + Sync {
    /// Stable identifier, used in configuration and logs.
    fn id(&self) -> &'static str;

    /// What this source knows about `permission` for this request.
    fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal;
}

/// The answer of several sources taken together.
///
/// See the module documentation for the rule and why it is the existing
/// precedence rather than a new policy.
#[must_use]
pub fn combine(
    sources: &[Arc<dyn PermissionSignalSource>],
    permission: Permission,
    input: &SignalInput<'_>,
) -> ConsentSignal {
    let mut granted = false;
    for source in sources {
        match source.signal(permission, input) {
            // A refusal is final and there is no point asking the rest.
            ConsentSignal::Revoke => return ConsentSignal::Revoke,
            ConsentSignal::Grant => granted = true,
            ConsentSignal::Neutral => {}
        }
    }
    if granted {
        ConsentSignal::Grant
    } else {
        ConsentSignal::Neutral
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that always answers the same thing, for testing the rule
    /// rather than any particular model.
    struct Fixed(&'static str, ConsentSignal);

    impl PermissionSignalSource for Fixed {
        fn id(&self) -> &'static str {
            self.0
        }

        fn signal(&self, _permission: Permission, _input: &SignalInput<'_>) -> ConsentSignal {
            self.1
        }
    }

    fn sources(signals: &[ConsentSignal]) -> Vec<Arc<dyn PermissionSignalSource>> {
        signals
            .iter()
            .map(|signal| Arc::new(Fixed("test", *signal)) as Arc<dyn PermissionSignalSource>)
            .collect()
    }

    fn combined(signals: &[ConsentSignal]) -> ConsentSignal {
        let consent = ConsentContext::default();
        let policy = SignalPolicy::default();
        let input = SignalInput {
            consent: &consent,
            policy: &policy,
        };
        combine(&sources(signals), Permission::StoreOnDevice, &input)
    }

    #[test]
    fn no_sources_leaves_the_place_baseline_alone() {
        assert_eq!(combined(&[]), ConsentSignal::Neutral);
    }

    #[test]
    fn a_refusal_beats_a_grant_whatever_the_order() {
        assert_eq!(
            combined(&[ConsentSignal::Grant, ConsentSignal::Revoke]),
            ConsentSignal::Revoke
        );
        assert_eq!(
            combined(&[ConsentSignal::Revoke, ConsentSignal::Grant]),
            ConsentSignal::Revoke,
            "an opt-out revoked whatever TCF said, and that has to survive the refactor"
        );
    }

    #[test]
    fn a_grant_beats_silence() {
        assert_eq!(
            combined(&[ConsentSignal::Neutral, ConsentSignal::Grant]),
            ConsentSignal::Grant
        );
    }

    #[test]
    fn silence_from_every_source_is_not_a_refusal() {
        // The failure this guards is a source that reads an absent signal as a
        // refusal. It would revoke every permission on every request that did
        // not carry that model, which is most of them.
        assert_eq!(
            combined(&[ConsentSignal::Neutral, ConsentSignal::Neutral]),
            ConsentSignal::Neutral
        );
    }
}
