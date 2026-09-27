//! A grant: one subject, one artifact or prefix, the actions it may take there.

use authorize::Action;
use authorize::subject::Subject;
use context::AuthenticatedIdentity;

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
        let grant = Grant::new(Subject::Anyone, "Billing")
            .allowing(Action::Send)
            .allowing(Action::Send);

        assert_eq!(grant.actions, vec![Action::Send]);
    }
}
