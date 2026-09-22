//! A grant: one subject, one artifact or prefix, the actions it may take there.

use authorize::Action;
use context::AuthenticatedIdentity;
use std::fmt;
use xcore::PartyId;

/// Whom a grant is for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Subject {
    /// Every identity, resolved to a Party or not.
    Any,
    /// The identity whose presented value is exactly this —
    /// `CN=partner-x.example`.
    Identity(String),
    /// Whatever identity resolved to this Party. A Party is a shortcut to an
    /// identity, not a permission (ADR-0019 clause 4), so this is the grant a
    /// partner reaching Xmip through two endpoints with two certificates gets
    /// once rather than twice.
    Party(PartyId),
}

impl Subject {
    #[must_use]
    pub fn matches(&self, identity: &AuthenticatedIdentity) -> bool {
        match self {
            Self::Any => true,
            Self::Identity(value) => identity.value == *value,
            Self::Party(party) => identity.party_id == Some(*party),
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("anyone"),
            Self::Identity(value) => write!(f, "'{value}'"),
            Self::Party(party) => write!(f, "party {party}"),
        }
    }
}

/// An artifact's name as a pattern in the gate's one language
/// (`authorize::pattern`): `*` stands for any run of characters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pattern(String);

impl Pattern {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        authorize::pattern::matches(&self.0, name)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What one subject may do to one artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    pub subject: Subject,
    pub artifact: Pattern,
    /// The points this grant answers for: receive, process, send. Empty grants
    /// nothing, which is a grant worth writing when the artifact should be
    /// named and closed.
    pub actions: Vec<Action>,
}

impl Grant {
    #[must_use]
    pub fn new(subject: Subject, artifact: impl Into<String>) -> Self {
        Self {
            subject,
            artifact: Pattern::new(artifact),
            actions: Vec::new(),
        }
    }

    #[must_use]
    pub fn allowing(mut self, action: Action) -> Self {
        if !self.actions.contains(&action) {
            self.actions.push(action);
        }

        self
    }

    /// Whether this grant names the artifact at all, whoever is asking.
    #[must_use]
    pub fn names(&self, artifact: &str) -> bool {
        self.artifact.matches(artifact)
    }

    /// Whether this grant admits this identity for this action.
    #[must_use]
    pub fn admits(&self, identity: &AuthenticatedIdentity, action: Action) -> bool {
        self.subject.matches(identity) && self.actions.contains(&action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_pattern_names_everything_under_it_and_a_plain_one_only_itself() {
        assert!(Pattern::new("partner-*").matches("partner-x"));
        assert!(Pattern::new("partner-*").matches("partner-"));
        assert!(!Pattern::new("partner-*").matches("partnerx"));
        assert!(Pattern::new("Billing").matches("Billing"));
        assert!(!Pattern::new("Billing").matches("Billing2"));
        assert!(Pattern::new("*").matches("anything"));
    }

    #[test]
    fn allowing_an_action_twice_records_it_once() {
        let grant = Grant::new(Subject::Any, "Billing")
            .allowing(Action::Send)
            .allowing(Action::Send);

        assert_eq!(grant.actions, vec![Action::Send]);
    }
}
