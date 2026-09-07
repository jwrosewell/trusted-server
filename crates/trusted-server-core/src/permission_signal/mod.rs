#![doc = include_str!("README.md")]

use std::sync::Arc;

use crate::consent::ConsentContext;
use crate::permissions::{Acquisition, ConsentSignal, Permission, SignalPolicy};

/// What a signal source may read about a request.
///
/// A struct rather than a parameter list, so a source needing something new
/// does not change every implementation.
pub struct SignalInput<'a> {
    /// The decoded consent record for this request.
    pub consent: &'a ConsentContext,
    /// The policy from `permissions.yaml`, which decides what a signal means
    /// rather than leaving each source to invent its own meaning.
    pub policy: &'a SignalPolicy,
    /// What the country and region rules say about this permission, before any
    /// source is asked. A source amends this rather than deciding alone.
    pub baseline: Acquisition,
    /// What the sources asked before this one settled on.
    ///
    /// [`ConsentSignal::Neutral`] means none of them had an opinion, so the
    /// baseline still stands.
    pub settled: ConsentSignal,
    /// Every source in configured order, this one included.
    sources: &'a [Arc<dyn PermissionSignalSource>],
    /// Where in that order the source being asked sits.
    position: usize,
    /// Whether this source may consult a peer.
    ///
    /// False while answering a consultation, which is what stops two sources
    /// that consult each other from looping.
    may_ask: bool,
}

impl<'a> SignalInput<'a> {
    /// An input for a source asked on its own, outside an ordered run.
    #[must_use]
    pub fn new(
        consent: &'a ConsentContext,
        policy: &'a SignalPolicy,
        baseline: Acquisition,
    ) -> Self {
        Self {
            consent,
            policy,
            baseline,
            settled: ConsentSignal::Neutral,
            sources: &[],
            position: 0,
            may_ask: true,
        }
    }

    /// Every source in configured order, this one included.
    ///
    /// A source consults the list to decide whether a peer it cares about is
    /// configured at all, and where it sits relative to this one.
    #[must_use]
    pub fn sources(&self) -> &[Arc<dyn PermissionSignalSource>] {
        self.sources
    }

    /// Where the source being asked sits in that order.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Whether a source with this identifier is configured.
    #[must_use]
    pub fn has(&self, id: &str) -> bool {
        self.sources.iter().any(|source| source.id() == id)
    }

    /// What a peer makes of `permission`, asked directly.
    ///
    /// The peer answers as if it were first, so the reply is that peer's own
    /// opinion rather than what the run has settled on so far. That is the
    /// useful question: a source wanting to know whether the prior value came
    /// from a particular peer asks that peer what it says.
    ///
    /// Returns `None` when no source carries the identifier, when the caller
    /// names itself, and when this input is itself answering a consultation.
    /// A source must handle `None` rather than assume a peer is present.
    #[must_use]
    pub fn ask(&self, id: &str, permission: Permission) -> Option<ConsentSignal> {
        if !self.may_ask {
            return None;
        }
        let (position, source) = self
            .sources
            .iter()
            .enumerate()
            .find(|(position, source)| source.id() == id && *position != self.position)?;
        let input = Self {
            consent: self.consent,
            policy: self.policy,
            baseline: self.baseline,
            settled: ConsentSignal::Neutral,
            sources: self.sources,
            position,
            may_ask: false,
        };
        Some(source.signal(permission, &input))
    }
}

/// A source of permission signals.
///
/// An implementation answers for one signalling model. It reads the request,
/// applies whatever the policy says about its own model, and returns how it
/// would amend one permission.
///
/// # Contract
///
/// Answer [`ConsentSignal::Neutral`] for a permission this source has no
/// opinion on, including when the signal it reads is absent from the request.
/// Returning [`ConsentSignal::Revoke`] for an absent signal would turn silence
/// into refusal and revoke the permission on every request that did not carry
/// this model.
pub trait PermissionSignalSource: Send + Sync {
    /// Stable identifier, used in configuration, in logs, and by a peer
    /// looking this source up through [`SignalInput::ask`].
    fn id(&self) -> &'static str;

    /// How this source would amend `permission` for this request.
    fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal;
}

/// Asks every source in order and returns what they settle on together.
///
/// See the module documentation for the layering and why the order is the
/// configuration.
#[must_use]
pub fn combine(
    sources: &[Arc<dyn PermissionSignalSource>],
    permission: Permission,
    consent: &ConsentContext,
    policy: &SignalPolicy,
    baseline: Acquisition,
) -> ConsentSignal {
    let mut settled = ConsentSignal::Neutral;
    for (position, source) in sources.iter().enumerate() {
        let input = SignalInput {
            consent,
            policy,
            baseline,
            settled,
            sources,
            position,
            may_ask: true,
        };
        // Every source is asked, because a later one may amend what an earlier
        // one settled. Stopping at the first answer would make the order mean
        // the opposite of what it says.
        match source.signal(permission, &input) {
            ConsentSignal::Neutral => {}
            answer => settled = answer,
        }
    }
    settled
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

    /// A source that answers by consulting a peer, which is the behavior the
    /// peer visibility exists for.
    struct Consulting {
        id: &'static str,
        peer: &'static str,
    }

    impl PermissionSignalSource for Consulting {
        fn id(&self) -> &'static str {
            self.id
        }

        fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
            match input.ask(self.peer, permission) {
                // The peer refused, and this source takes the opposite view of
                // the same request, which is the override the seam allows.
                Some(ConsentSignal::Revoke) => ConsentSignal::Grant,
                _ => ConsentSignal::Neutral,
            }
        }
    }

    fn combined(sources: &[Arc<dyn PermissionSignalSource>]) -> ConsentSignal {
        let consent = ConsentContext::default();
        let policy = SignalPolicy::default();
        combine(
            sources,
            Permission::StoreOnDevice,
            &consent,
            &policy,
            Acquisition::RequiresSignal,
        )
    }

    /// The same, for a run whose sources differ only in what they answer.
    fn combined_signals(signals: &[ConsentSignal]) -> ConsentSignal {
        let sources: Vec<Arc<dyn PermissionSignalSource>> = signals
            .iter()
            .map(|signal| Arc::new(Fixed("test", *signal)) as Arc<dyn PermissionSignalSource>)
            .collect();
        combined(&sources)
    }

    #[test]
    fn no_sources_leaves_the_place_baseline_alone() {
        assert_eq!(combined_signals(&[]), ConsentSignal::Neutral);
    }

    #[test]
    fn the_last_source_with_an_opinion_decides() {
        assert_eq!(
            combined_signals(&[ConsentSignal::Revoke, ConsentSignal::Grant]),
            ConsentSignal::Grant,
            "a visitor who answers a prompt after arriving with an opt-out header has \
             their answer applied over it, which is why the order is the policy"
        );
        assert_eq!(
            combined_signals(&[ConsentSignal::Grant, ConsentSignal::Revoke]),
            ConsentSignal::Revoke,
            "and a deployment that wants the opt-out to win puts it last"
        );
    }

    #[test]
    fn silence_leaves_an_earlier_answer_standing() {
        // The failure this guards is a later source overwriting a settled
        // answer with its own absence, which would let adding a source nobody
        // uses undo the one that was working.
        assert_eq!(
            combined_signals(&[ConsentSignal::Grant, ConsentSignal::Neutral]),
            ConsentSignal::Grant
        );
        assert_eq!(
            combined_signals(&[ConsentSignal::Revoke, ConsentSignal::Neutral]),
            ConsentSignal::Revoke
        );
    }

    #[test]
    fn silence_from_every_source_is_not_a_refusal() {
        // The failure this guards is a source that reads an absent signal as a
        // refusal. It would revoke the permission on every request that did not
        // carry that model, which is most of them.
        assert_eq!(
            combined_signals(&[ConsentSignal::Neutral, ConsentSignal::Neutral]),
            ConsentSignal::Neutral
        );
    }

    #[test]
    fn a_source_sees_what_the_earlier_ones_settled() {
        struct Recording;

        impl PermissionSignalSource for Recording {
            fn id(&self) -> &'static str {
                "recording"
            }

            fn signal(&self, _permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
                assert_eq!(
                    input.settled,
                    ConsentSignal::Revoke,
                    "a source is asked with the value the sources before it settled on"
                );
                assert_eq!(input.position(), 1, "and with its own place in the order");
                assert_eq!(input.sources().len(), 2, "and with the whole list");
                assert_eq!(
                    input.baseline,
                    Acquisition::RequiresSignal,
                    "and with what the place rules said before anyone was asked"
                );
                ConsentSignal::Neutral
            }
        }

        let sources: Vec<Arc<dyn PermissionSignalSource>> = vec![
            Arc::new(Fixed("opt-out", ConsentSignal::Revoke)),
            Arc::new(Recording),
        ];
        assert_eq!(combined(&sources), ConsentSignal::Revoke);
    }

    #[test]
    fn a_source_can_override_a_peer_by_consulting_it() {
        // The worked example from the README: a later source overrides a
        // refusal because of who made it, not merely that one was made.
        let sources: Vec<Arc<dyn PermissionSignalSource>> = vec![
            Arc::new(Fixed("gpc", ConsentSignal::Revoke)),
            Arc::new(Consulting {
                id: "prompt",
                peer: "gpc",
            }),
        ];
        assert_eq!(combined(&sources), ConsentSignal::Grant);

        // The same source leaves the refusal alone when it came from a peer it
        // was not told to override.
        let sources: Vec<Arc<dyn PermissionSignalSource>> = vec![
            Arc::new(Fixed("other", ConsentSignal::Revoke)),
            Arc::new(Consulting {
                id: "prompt",
                peer: "gpc",
            }),
        ];
        assert_eq!(combined(&sources), ConsentSignal::Revoke);
    }

    #[test]
    fn asking_reaches_a_peer_wherever_it_sits_in_the_order() {
        // A source may consult one configured after it, not only before, so a
        // reordering does not silently change what a source can see.
        let sources: Vec<Arc<dyn PermissionSignalSource>> = vec![
            Arc::new(Consulting {
                id: "prompt",
                peer: "gpc",
            }),
            Arc::new(Fixed("gpc", ConsentSignal::Revoke)),
        ];
        assert_eq!(
            combined(&sources),
            ConsentSignal::Revoke,
            "the consultation succeeded, and the later opt-out then settled it"
        );
    }

    #[test]
    fn asking_for_a_source_that_is_not_configured_answers_nothing() {
        struct Absent;

        impl PermissionSignalSource for Absent {
            fn id(&self) -> &'static str {
                "absent"
            }

            fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
                assert!(
                    input.ask("not-configured", permission).is_none(),
                    "a source must be able to tell a missing peer from a silent one"
                );
                assert!(!input.has("not-configured"));
                assert!(input.has("absent"), "and can see itself in the list");
                ConsentSignal::Neutral
            }
        }

        let sources: Vec<Arc<dyn PermissionSignalSource>> = vec![Arc::new(Absent)];
        assert_eq!(combined(&sources), ConsentSignal::Neutral);
    }

    #[test]
    fn a_source_cannot_consult_itself() {
        struct SelfAsking;

        impl PermissionSignalSource for SelfAsking {
            fn id(&self) -> &'static str {
                "self-asking"
            }

            fn signal(&self, permission: Permission, input: &SignalInput<'_>) -> ConsentSignal {
                // Without the guard this recurses until the stack is gone.
                assert!(input.ask("self-asking", permission).is_none());
                ConsentSignal::Grant
            }
        }

        let sources: Vec<Arc<dyn PermissionSignalSource>> = vec![Arc::new(SelfAsking)];
        assert_eq!(combined(&sources), ConsentSignal::Grant);
    }

    #[test]
    fn two_sources_that_consult_each_other_do_not_loop() {
        // Each consults the other, and the one answering a consultation is
        // refused a consultation of its own, so the pair settles instead of
        // recursing.
        let sources: Vec<Arc<dyn PermissionSignalSource>> = vec![
            Arc::new(Consulting {
                id: "first",
                peer: "second",
            }),
            Arc::new(Consulting {
                id: "second",
                peer: "first",
            }),
        ];
        assert_eq!(combined(&sources), ConsentSignal::Neutral);
    }
}
