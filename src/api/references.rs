//! Reference sites, independent of listing rendering. Empty results do not prove
//! unreachability: unresolved indirect edges are outside the recovered graph.

use crate::address::StaticVa;
use crate::analysis::engine::{Analysis, XrefKind};
use crate::workspace::Session;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceView {
    Xrefs,
    Callers,
    Callees,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceSite {
    pub source: StaticVa,
    pub target: StaticVa,
    pub kind: XrefKind,
    pub source_label: String,
    pub target_label: String,
}

pub fn query(session: &Session, address: StaticVa, view: ReferenceView) -> Vec<ReferenceSite> {
    query_in(&session.an, address, view)
}

pub fn query_in(analysis: &Analysis, address: StaticVa, view: ReferenceView) -> Vec<ReferenceSite> {
    let row = |source, target, kind| ReferenceSite {
        source: StaticVa(source),
        target: StaticVa(target),
        kind,
        source_label: match analysis.function_at(source) {
            Some(function) if source != function.addr => {
                format!("{}+0x{:x}", function.name, source - function.addr)
            }
            Some(function) => function.name.clone(),
            None => analysis.label(source),
        },
        target_label: analysis.label(target),
    };
    let is_call = |source, target, kind| {
        kind == XrefKind::Call
            || (kind == XrefKind::Jump
                && analysis
                    .function_at(source)
                    .is_some_and(|function| function.calls.contains(&target)))
    };
    match view {
        ReferenceView::Xrefs | ReferenceView::Callers => {
            let target = if view == ReferenceView::Callers {
                analysis
                    .function_at(address.get())
                    .map_or(address.get(), |f| f.addr)
            } else {
                address.get()
            };
            analysis
                .xrefs_to
                .get(&target)
                .into_iter()
                .flatten()
                .filter(|reference| {
                    view == ReferenceView::Xrefs || is_call(reference.from, target, reference.kind)
                })
                .map(|reference| row(reference.from, target, reference.kind))
                .collect()
        }
        ReferenceView::Callees => {
            let Some(function) = analysis.function_at(address.get()) else {
                return Vec::new();
            };
            // Walk actual block instructions, not a guessed contiguous size range.
            let mut rows = Vec::new();
            for block in &function.blocks {
                for instruction in &block.insns {
                    if let Some(references) = analysis.xrefs_from.get(&instruction.addr) {
                        rows.extend(
                            references
                                .iter()
                                .filter(|reference| {
                                    is_call(instruction.addr, reference.to, reference.kind)
                                })
                                .map(|reference| {
                                    row(instruction.addr, reference.to, reference.kind)
                                }),
                        );
                    }
                }
            }
            rows.sort_by_key(|row| (row.source, row.target, row.kind as u8));
            rows.dedup();
            rows
        }
    }
}
