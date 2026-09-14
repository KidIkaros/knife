//! Presentation-neutral import and export queries for Knife front ends.

use crate::address::StaticVa;
use crate::analysis::{engine::Analysis, thunks};
use crate::model::Binary;
use crate::workspace::Session;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolQuery {
    pub text_contains: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolSummary {
    /// Owning module for an import; empty for an export.
    pub module: String,
    pub name: String,
    pub address: Option<StaticVa>,
    pub reference_count: usize,
}

pub fn imports(session: &Session, query: &SymbolQuery) -> Vec<SymbolSummary> {
    imports_in(&session.an, query)
}

pub fn imports_in(analysis: &Analysis, query: &SymbolQuery) -> Vec<SymbolSummary> {
    let needle = query
        .text_contains
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    let mut symbols: Vec<_> = analysis
        .imports
        .iter()
        .map(|(address, decorated)| {
            let module = decorated
                .rsplit_once('!')
                .map(|(module, _)| module.to_string())
                .unwrap_or_default();
            SymbolSummary {
                module,
                name: thunks::bare_name(decorated).to_string(),
                address: Some(StaticVa(*address)),
                reference_count: analysis.xrefs_to.get(address).map_or(0, Vec::len),
            }
        })
        .filter(|symbol| {
            needle.is_empty()
                || symbol.name.to_lowercase().contains(&needle)
                || symbol.module.to_lowercase().contains(&needle)
        })
        .collect();

    // One API can appear through both a slot and a stub. Keep the address with
    // the strongest observed reference support, then present modules together.
    symbols.sort_by(|left, right| {
        left.module
            .cmp(&right.module)
            .then(left.name.cmp(&right.name))
            .then(right.reference_count.cmp(&left.reference_count))
            .then(left.address.cmp(&right.address))
    });
    symbols.dedup_by(|left, right| left.module == right.module && left.name == right.name);
    symbols.sort_by(|left, right| {
        left.module
            .cmp(&right.module)
            .then(right.reference_count.cmp(&left.reference_count))
            .then(left.name.cmp(&right.name))
    });
    symbols.truncate(query.limit.unwrap_or(usize::MAX));
    symbols
}

pub fn exports(session: &Session, query: &SymbolQuery) -> Vec<SymbolSummary> {
    exports_in(&session.bin, &session.an, query)
}

pub fn exports_in(binary: &Binary, analysis: &Analysis, query: &SymbolQuery) -> Vec<SymbolSummary> {
    let needle = query
        .text_contains
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    binary
        .exports
        .iter()
        .filter(|name| needle.is_empty() || name.to_lowercase().contains(&needle))
        .map(|name| {
            let function = analysis.find_by_name(name);
            SymbolSummary {
                module: String::new(),
                name: name.clone(),
                address: function.map(|function| StaticVa(function.addr)),
                reference_count: function.map_or(0, |function| function.incoming),
            }
        })
        .take(query.limit.unwrap_or(usize::MAX))
        .collect()
}
