//! Stable deterministic CFG and call-graph queries for front ends.

use crate::address::StaticVa;
use crate::analysis::engine::Function;
use crate::analysis::graphs;
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphKind {
    ControlFlow,
    CallClosure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphQuery {
    pub kind: GraphKind,
    pub selector: String,
    pub maximum_nodes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphResult {
    pub view: GraphView,
    /// DOT is generated from the same deterministic graph as `view`.
    pub dot: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphView {
    pub kind: GraphKind,
    pub title: String,
    pub root: StaticVa,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub address: StaticVa,
    pub label: String,
    pub kind: String,
    pub detail: Option<String>,
    pub instruction_addresses: Vec<StaticVa>,
    pub basic_blocks: usize,
    pub byte_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub back: bool,
}

pub fn query(session: &Session, request: &GraphQuery) -> Result<GraphResult> {
    let function = resolve_function(session, &request.selector)
        .ok_or_else(|| anyhow!("nothing matches {:?}", request.selector))?;
    let graph = match request.kind {
        GraphKind::ControlFlow => graphs::cfg(function),
        GraphKind::CallClosure => {
            let roots = BTreeSet::from([function.addr]);
            let graph =
                graphs::call_graph(&session.an.functions, &session.an.imports, Some(&roots));
            let maximum = request.maximum_nodes.unwrap_or(96).max(8);
            if graph.nodes.len() > maximum {
                return Err(anyhow!(
                    "the call closure from {} spans {} nodes; open a callee to go deeper",
                    function.name,
                    graph.nodes.len()
                ));
            }
            graph
        }
    };
    let dot = graphs::dot(&graph, &function.name);
    let functions: BTreeMap<u64, &Function> = session
        .an
        .functions
        .iter()
        .map(|candidate| (candidate.addr, candidate))
        .collect();
    let nodes = graph
        .nodes
        .iter()
        .map(|node| {
            let owner = functions.get(&node.address).copied();
            let block = (request.kind == GraphKind::ControlFlow)
                .then(|| {
                    function
                        .blocks
                        .iter()
                        .find(|block| block.start == node.address)
                })
                .flatten();
            GraphNode {
                id: node.id.clone(),
                address: StaticVa(node.address),
                label: node.label.clone(),
                kind: node.kind.to_string(),
                detail: node.detail.clone(),
                instruction_addresses: block
                    .map(|block| {
                        block
                            .insns
                            .iter()
                            .map(|instruction| StaticVa(instruction.addr))
                            .collect()
                    })
                    .unwrap_or_default(),
                basic_blocks: owner.map_or(0, |candidate| candidate.blocks.len()),
                byte_size: block
                    .map(|block| block.end.saturating_sub(block.start))
                    .or_else(|| owner.map(|candidate| candidate.size))
                    .unwrap_or(0),
            }
        })
        .collect();
    let edges = graph
        .edges
        .iter()
        .map(|edge| GraphEdge {
            from: edge.from.clone(),
            to: edge.to.clone(),
            kind: edge.kind.to_string(),
            back: edge.back,
        })
        .collect();
    Ok(GraphResult {
        view: GraphView {
            kind: request.kind,
            title: function.name.clone(),
            root: StaticVa(function.addr),
            nodes,
            edges,
        },
        dot,
    })
}

fn resolve_function<'a>(session: &'a Session, selector: &str) -> Option<&'a Function> {
    session.an.find_by_name(selector).or_else(|| {
        let raw = selector
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        u64::from_str_radix(raw, 16).ok().and_then(|address| {
            session
                .an
                .find_function(address)
                .or_else(|| session.an.function_at(address))
        })
    })
}
