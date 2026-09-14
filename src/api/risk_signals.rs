//! Heuristic audit signals for front ends.
//!
//! These are leads for analyst review, not vulnerability findings. A missing
//! direct reachability proof remains unresolved rather than becoming evidence
//! that a call site is unreachable.

use crate::address::StaticVa;
use crate::analysis::audit;
use crate::analysis::reachability::Reachability;
use crate::workspace::Session;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSignal {
    pub address: StaticVa,
    pub function: Option<String>,
    pub api: String,
    pub pattern: String,
    pub severity: u8,
    pub detail: String,
    pub reachability: Reachability,
    pub source: String,
    pub trail: Vec<StaticVa>,
}

impl RiskSignal {
    pub fn reachable_compat(&self) -> bool {
        self.reachability.is_confirmed()
    }
}

pub fn query(session: &Session) -> Vec<RiskSignal> {
    let mut signals: Vec<_> = audit::run(&session.an, &session.bin, &session.bytes)
        .into_iter()
        .map(RiskSignal::from)
        .collect();
    signals.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(
                right
                    .reachability
                    .is_confirmed()
                    .cmp(&left.reachability.is_confirmed()),
            )
            .then(left.address.cmp(&right.address))
    });
    signals
}

impl From<audit::Finding> for RiskSignal {
    fn from(finding: audit::Finding) -> Self {
        Self {
            address: StaticVa(finding.addr),
            function: finding.func,
            api: finding.api,
            pattern: finding.pattern.to_string(),
            severity: finding.severity,
            detail: finding.detail.clone(),
            reachability: if finding.reachable {
                Reachability::ConfirmedDirect
            } else {
                Reachability::Unresolved
            },
            source: evidence_source(&finding.detail).to_string(),
            trail: finding.trail.into_iter().map(StaticVa).collect(),
        }
    }
}

fn evidence_source(detail: &str) -> &'static str {
    if detail.contains("external-input API") {
        "EXTERNAL INPUT"
    } else if detail.contains("function argument") {
        "ARGUMENT"
    } else if detail.contains("some incoming paths") {
        "CFG MERGE"
    } else if detail.contains("subtraction") {
        "SUBTRACTION"
    } else if detail.contains("multiplication") {
        "MULTIPLICATION"
    } else if detail.contains("stack buffer") {
        "STACK BUFFER"
    } else {
        "RUNTIME VALUE"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absence_of_legacy_direct_reachability_remains_unresolved() {
        let signal = RiskSignal::from(audit::Finding {
            addr: 0x2000,
            func: Some("dispatch_handler".into()),
            api: "indirect_dispatch".into(),
            pattern: "review-lead",
            severity: 2,
            detail: "no direct xrefs were recovered".into(),
            reachable: false,
            trail: Vec::new(),
        });
        assert_eq!(signal.reachability, Reachability::Unresolved);
        assert!(!signal.reachable_compat());
    }
}
