//! Typed function and cross-reference queries shared by Knife front ends.

use crate::address::StaticVa;
use crate::analysis::engine;
use crate::model::SymKind;
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionQuery {
    pub name_contains: Option<String>,
    pub named_only: bool,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub address: StaticVa,
    pub name: String,
    pub named: bool,
    pub size: u64,
    pub basic_blocks: usize,
    pub incoming_references: usize,
}

pub fn functions(session: &Session, query: &FunctionQuery) -> Vec<FunctionSummary> {
    let needle = query
        .name_contains
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    session
        .an
        .functions
        .iter()
        .filter(|function| !query.named_only || function.named)
        .filter(|function| needle.is_empty() || function.name.to_lowercase().contains(&needle))
        .take(query.limit.unwrap_or(usize::MAX))
        .map(|function| FunctionSummary {
            address: StaticVa(function.addr),
            name: function.name.clone(),
            named: function.named,
            size: function.size,
            basic_blocks: function.blocks.len(),
            incoming_references: function.incoming,
        })
        .collect()
}

pub fn resolve_function(session: &Session, selector: &str) -> Option<FunctionSummary> {
    resolve_engine_function(session, selector).map(|function| FunctionSummary {
        address: StaticVa(function.addr),
        name: function.name.clone(),
        named: function.named,
        size: function.size,
        basic_blocks: function.blocks.len(),
        incoming_references: function.incoming,
    })
}

pub fn resolve_address(session: &Session, selector: &str) -> Option<StaticVa> {
    resolve_address_in(&session.an, selector).ok()
}

/// Adjacent recovered entry in static-address order; never wraps at the ends.
pub fn adjacent_function(
    analysis: &engine::Analysis,
    address: StaticVa,
    forward: bool,
) -> Option<StaticVa> {
    let entry = analysis
        .function_at(address.get())
        .map_or(address.get(), |f| f.addr);
    let index = if forward {
        analysis.functions.partition_point(|f| f.addr <= entry)
    } else {
        analysis
            .functions
            .partition_point(|f| f.addr < entry)
            .checked_sub(1)?
    };
    analysis.functions.get(index).map(|f| StaticVa(f.addr))
}

/// Resolve exact symbols before hexadecimal static addresses. Ambiguous symbols
/// require an explicit address; an interior address is not rounded to an entry.
pub fn resolve_address_in(analysis: &engine::Analysis, selector: &str) -> Result<StaticVa> {
    let selector = selector.trim();
    let matches = analysis.resolve(selector, None);
    match matches.as_slice() {
        [address] => Ok(StaticVa(*address)),
        [] => parse_address(selector).map(StaticVa).map_err(|_| {
            anyhow!("no symbol or address matches {selector:?}; use a hexadecimal static VA")
        }),
        _ => Err(anyhow!("ambiguous symbol {selector:?}; use a static VA")),
    }
}

/// Borrowed query for terminal and CLI consumers that already own analysis state.
pub fn resolve_function_in<'a>(
    analysis: &'a engine::Analysis,
    selector: &str,
) -> Option<&'a engine::Function> {
    let address = resolve_address_in(analysis, selector).ok()?.get();
    analysis
        .find_function(address)
        .or_else(|| analysis.function_at(address))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefDirection {
    To,
    From,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefSummary {
    pub address: StaticVa,
    pub kind: String,
    pub site: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectPathQuery {
    pub selector: String,
    pub maximum_paths: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectPathHop {
    pub address: StaticVa,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectPathSummary {
    pub hops: Vec<DirectPathHop>,
}

/// Return recovered direct-call paths from known entry/export roots.
///
/// An empty result is deliberately not an unreachability verdict: indirect
/// dispatch, callbacks, and unresolved edges are outside this direct graph.
pub fn direct_paths(session: &Session, query: &DirectPathQuery) -> Result<Vec<DirectPathSummary>> {
    let maximum_paths = query.maximum_paths.clamp(1, 64);
    let target = resolve_engine_function(session, &query.selector)
        .map(|function| function.addr)
        .or_else(|| parse_address(&query.selector).ok())
        .ok_or_else(|| anyhow!("nothing matches {:?}", query.selector))?;
    let base = engine::display_base(&session.bin);
    let mut roots: Vec<_> = session
        .bin
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymKind::Export)
        .filter_map(|symbol| symbol.addr.checked_add(base))
        .collect();
    if let Some(entry) = session.bin.entry.checked_add(base) {
        roots.push(entry);
    }
    let mut paths = session.an.paths_to(target, &roots, maximum_paths, false);
    paths.sort_by_key(Vec::len);
    paths.truncate(maximum_paths);
    Ok(paths
        .into_iter()
        .map(|path| DirectPathSummary {
            hops: path
                .into_iter()
                .map(|address| DirectPathHop {
                    address: StaticVa(address),
                    name: session.an.label(address),
                })
                .collect(),
        })
        .collect())
}

pub fn xrefs(session: &Session, address: StaticVa, direction: XrefDirection) -> Vec<XrefSummary> {
    match direction {
        XrefDirection::From => session
            .an
            .find_function(address.0)
            .or_else(|| session.an.function_at(address.0))
            .map(|function| {
                function
                    .calls
                    .iter()
                    .map(|target| XrefSummary {
                        address: StaticVa(*target),
                        kind: "call".to_string(),
                        site: session.an.label(*target),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        XrefDirection::To => session
            .an
            .xrefs_to
            .get(&address.0)
            .map(|references| {
                references
                    .iter()
                    .map(|reference| XrefSummary {
                        address: StaticVa(reference.from),
                        kind: reference.kind.label().to_string(),
                        site: site_name(session, reference.from),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn site_name(session: &Session, address: u64) -> String {
    match session.an.function_at(address) {
        Some(function) => {
            let offset = address.saturating_sub(function.addr);
            if offset == 0 {
                function.name.clone()
            } else {
                format!("{}+0x{offset:x}", function.name)
            }
        }
        None => "-".to_string(),
    }
}

fn resolve_engine_function<'a>(
    session: &'a Session,
    selector: &str,
) -> Option<&'a crate::analysis::engine::Function> {
    resolve_function_in(&session.an, selector)
}

fn parse_address(value: &str) -> Result<u64> {
    let value = value.trim();
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(raw, 16).map_err(Into::into)
}
