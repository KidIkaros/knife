//! Deterministic reachability observations, independent of research workflows.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reachability {
    ConfirmedDirect,
    ConfirmedIndirect,
    #[default]
    Unresolved,
    NotObserved,
}

impl Reachability {
    /// No observed edges is not proof that execution is impossible.
    pub const fn from_observations(direct_xrefs: usize, indirect_edges: usize) -> Self {
        if direct_xrefs > 0 {
            Self::ConfirmedDirect
        } else if indirect_edges > 0 {
            Self::ConfirmedIndirect
        } else {
            Self::Unresolved
        }
    }

    pub const fn is_confirmed(self) -> bool {
        matches!(self, Self::ConfirmedDirect | Self::ConfirmedIndirect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_direct_edges_do_not_prove_unreachability() {
        assert_eq!(
            Reachability::from_observations(0, 0),
            Reachability::Unresolved
        );
        assert_eq!(
            Reachability::from_observations(0, 1),
            Reachability::ConfirmedIndirect
        );
        assert_eq!(
            Reachability::from_observations(1, 0),
            Reachability::ConfirmedDirect
        );
        assert!(!Reachability::NotObserved.is_confirmed());
    }
}
