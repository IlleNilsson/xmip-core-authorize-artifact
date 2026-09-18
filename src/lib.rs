#![forbid(unsafe_code)]

//! Artifact authorization — a technology of `xmip-core-authorize`.
//!
//! One policy: what this identity may do to this named artifact. The artifact
//! is what the Attempt names — a Receive Location, an Xmip Process, a Send
//! Location — and the three points ask three different questions of it:
//! whether this connection may post into it, whether this Party's work may
//! run in it, whether Xmip may present this identity through it. A [`Grant`]
//! answers those for one subject on one artifact, or on every artifact under
//! a prefix.
//!
//! The policy has an opinion only about artifacts a grant names. An attempt
//! on an artifact no grant names is left to the next policy — `None` —
//! because a list of grants for Billing says nothing about Payroll, and
//! pretending it did would close every artifact the moment the first grant
//! was written. Where a grant names the artifact and none admits this
//! identity for this action, the answer is a denial that says which subject
//! may not do what, where.
//!
//! Transport layer (ADR-0050 section 5): the identity judged is the one
//! accountable for the transmission, `IdentityFacts::accountable()`. Roles
//! and attribute rules are other policies' business; this one is a list.

pub mod grant;

use authorize::{Attempt, Authorizer, Decision};
use context::IdentityFacts;
pub use grant::{Grant, Pattern, Subject};
use xcore::Layer;

/// The manifest leaf, and what a denial says it was denied by.
pub const NAME: &str = "artifact";

/// The grants, in the order they were written. Order does not matter: any
/// grant admitting the identity for the action is enough.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Artifact {
    grants: Vec<Grant>,
}

impl Artifact {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn granting(mut self, grant: Grant) -> Self {
        self.grants.push(grant);
        self
    }

    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }
}

impl Authorizer for Artifact {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let named: Vec<&Grant> = self
            .grants
            .iter()
            .filter(|grant| grant.names(&attempt.artifact))
            .collect();

        if named.is_empty() {
            return None;
        }

        let who = identity.accountable();

        if named.iter().any(|grant| grant.admits(who, attempt.action)) {
            return Some(Decision::Allowed);
        }

        let may: Vec<String> = named
            .iter()
            .filter(|grant| grant.subject.matches(who))
            .flat_map(|grant| grant.actions.iter().map(ToString::to_string))
            .collect();

        let reason = if may.is_empty() {
            format!("'{}' has no grant on '{}'", who.value, attempt.artifact)
        } else {
            format!(
                "'{}' may not {} on '{}'; it may {}",
                who.value,
                attempt.action,
                attempt.artifact,
                may.join(", ")
            )
        };

        Some(Decision::denied(NAME, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, PartyId, mechanism};

    fn partner_x(party: Option<PartyId>) -> IdentityFacts {
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
            Established::Passed,
            Verified::Proven,
        );
        let identity = match party {
            Some(party_id) => identity.resolving_to(party_id),
            None => identity,
        };

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn billing() -> Artifact {
        Artifact::new()
            .granting(Grant::new(Subject::Party(PartyId::new(7)), "Billing").allowing(Action::Send))
            .granting(
                Grant::new(
                    Subject::Identity("CN=partner-x.example".into()),
                    "partner-*",
                )
                .allowing(Action::Receive),
            )
    }

    #[test]
    fn a_grant_to_the_party_admits_the_identity_that_resolved_to_it() {
        let decision = billing().decide(
            &partner_x(Some(PartyId::new(7))),
            &Attempt::new(Action::Send, "Billing"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
    }

    #[test]
    fn an_action_the_grant_does_not_name_is_denied_by_artifact_saying_what_it_may() {
        // The Party may send through Billing. Running work in it is a different
        // question, and the denial says which one was answered.
        let decision = billing().decide(
            &partner_x(Some(PartyId::new(7))),
            &Attempt::new(Action::Process, "Billing"),
        );

        assert_eq!(
            decision.map(|decision| decision.to_string()),
            Some(
                "denied by artifact: 'CN=partner-x.example' may not process on 'Billing'; \
                 it may send"
                    .to_string()
            )
        );
    }

    #[test]
    fn an_artifact_no_grant_names_is_left_to_the_next_policy() {
        let decision = billing().decide(
            &partner_x(Some(PartyId::new(7))),
            &Attempt::new(Action::Send, "Payroll"),
        );

        assert_eq!(decision, None);
    }

    #[test]
    fn an_identity_with_no_grant_on_a_named_artifact_is_denied_not_ignored() {
        // Not resolved to Party 7, and the value grant covers partner-* only.
        // Billing is named, so the policy has an opinion, and it is no.
        let decision = billing().decide(&partner_x(None), &Attempt::new(Action::Send, "Billing"));

        assert_eq!(
            decision,
            Some(Decision::denied(
                NAME,
                "'CN=partner-x.example' has no grant on 'Billing'"
            ))
        );
    }

    #[test]
    fn a_prefix_grant_admits_by_presented_value_across_every_artifact_under_it() {
        let policy = billing();

        for artifact in ["partner-x", "partner-x-orders", "partner-"] {
            let decision =
                policy.decide(&partner_x(None), &Attempt::new(Action::Receive, artifact));

            assert_eq!(decision, Some(Decision::Allowed), "{artifact}");
        }
    }

    #[test]
    fn the_policy_is_named_artifact_and_judges_the_transport_layer() {
        let policy = Artifact::new();

        assert_eq!(policy.name(), "artifact");
        assert_eq!(policy.layer(), Layer::Transport);
        assert!(policy.grants().is_empty());
    }
}
