//! Presentation-neutral access to analyst-confirmed facts.

use crate::address::StaticVa;
use crate::analysis::engine;
use crate::db;
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactKind {
    Prototype,
    Structure,
    Binding,
    Variable,
    Note,
}

impl FactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prototype => stringify!(prototype),
            Self::Structure => stringify!(structure),
            Self::Binding => stringify!(binding),
            Self::Variable => stringify!(variable),
            Self::Note => stringify!(note),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactRow {
    pub kind: FactKind,
    pub name: String,
    pub detail: String,
    pub address: Option<StaticVa>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactQuery {
    pub text_contains: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRef {
    pub base: String,
    pub offset: i64,
    pub type_name: Option<String>,
    pub member: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineActions {
    pub field: Option<FieldRef>,
    pub variable: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TypeLibraryOperation {
    ImportMerge,
    ImportReplace,
    Export,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeLibraryReceipt {
    pub operation: TypeLibraryOperation,
    pub types: usize,
    pub fields: usize,
}

pub fn analyst_facts(session: &Session, query: &FactQuery) -> Vec<FactRow> {
    let base = engine::display_base(&session.bin);
    let mut rows = Vec::new();
    for (function, prototype) in &session.db.prototypes {
        let address = checked_address(base, *function);
        rows.push(FactRow {
            kind: FactKind::Prototype,
            name: fact_label(session, address, *function),
            detail: format!("{} ({})", prototype.returns, prototype.params.join(", ")),
            address,
        });
    }
    for (type_name, fields) in &session.db.fields {
        for (offset, field) in fields {
            let sign = if *offset < 0 { "-" } else { "+" };
            rows.push(FactRow {
                kind: FactKind::Structure,
                name: type_name.clone(),
                detail: format!("{sign}0x{:x} {field}", offset.unsigned_abs()),
                address: None,
            });
        }
    }
    for ((function, base_id), type_name) in &session.db.bindings {
        let address = checked_address(base, *function);
        rows.push(FactRow {
            kind: FactKind::Binding,
            name: format!("{}:{base_id}", fact_label(session, address, *function)),
            detail: format!("{type_name} *"),
            address,
        });
    }
    for ((function, base_id), name) in &session.db.variables {
        let address = checked_address(base, *function);
        rows.push(FactRow {
            kind: FactKind::Variable,
            name: format!("{}:{base_id}", fact_label(session, address, *function)),
            detail: name.clone(),
            address,
        });
    }
    for (stored, text) in &session.db.notes {
        let address = checked_address(base, *stored);
        rows.push(FactRow {
            kind: FactKind::Note,
            name: fact_label(session, address, *stored),
            detail: text.clone(),
            address,
        });
    }
    let needle = query
        .text_contains
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    rows.retain(|row| {
        needle.is_empty()
            || row.name.to_lowercase().contains(&needle)
            || row.detail.to_lowercase().contains(&needle)
    });
    rows
}

pub fn line_actions(session: &Session, function: StaticVa, text: &str) -> Result<LineActions> {
    let stored = function
        .get()
        .checked_sub(engine::display_base(&session.bin))
        .ok_or_else(|| anyhow!("function address is below the image base"))?;
    let field = parse_field_ref(text, stored, &session.db);
    let variable = field.as_ref().map(|field| field.base.clone()).or_else(|| {
        session
            .db
            .variables
            .iter()
            .find(|((owner, _), alias)| *owner == stored && contains_identifier(text, alias))
            .map(|((_, base), _)| base.clone())
    });
    Ok(LineActions { field, variable })
}

pub fn import_type_library(
    session: &mut Session,
    path: &Path,
    replace: bool,
) -> Result<TypeLibraryReceipt> {
    let summary = session.db.import_type_library(path, replace)?;
    Ok(TypeLibraryReceipt {
        operation: if replace {
            TypeLibraryOperation::ImportReplace
        } else {
            TypeLibraryOperation::ImportMerge
        },
        types: summary.types,
        fields: summary.fields,
    })
}

pub fn export_type_library(session: &Session, path: &Path) -> Result<TypeLibraryReceipt> {
    let summary = session.db.export_type_library(path)?;
    Ok(TypeLibraryReceipt {
        operation: TypeLibraryOperation::Export,
        types: summary.types,
        fields: summary.fields,
    })
}

fn parse_field_ref(text: &str, function: u64, database: &db::Db) -> Option<FieldRef> {
    let arrow = text.find("->")?;
    let shown_base = ident_tail(&text[..arrow]);
    let base = database
        .variables
        .iter()
        .find_map(|((owner, recovered), alias)| {
            (*owner == function && alias == &shown_base).then_some(recovered.clone())
        })
        .unwrap_or(shown_base);
    if !db::valid_base(&base) {
        return None;
    }
    let member = ident_head(&text[arrow + 2..]);
    let type_name = database.bound_type(function, &base).map(str::to_string);
    let offset = if let Some(hex) = member.strip_prefix("field_m") {
        i64::from_str_radix(hex, 16).ok()?.checked_neg()?
    } else if let Some(hex) = member.strip_prefix("field_") {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        let type_name = type_name.as_ref()?;
        database
            .fields
            .get(type_name)?
            .iter()
            .find_map(|(&offset, field)| (field.name == member).then_some(offset))?
    };
    Some(FieldRef {
        base,
        offset,
        type_name,
        member,
    })
}

fn checked_address(base: u64, stored: u64) -> Option<StaticVa> {
    base.checked_add(stored).map(StaticVa)
}

fn fact_label(session: &Session, address: Option<StaticVa>, stored: u64) -> String {
    match address {
        Some(address) => session.an.label(address.get()),
        None => format!("stored_0x{stored:x}"),
    }
}

fn is_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn ident_tail(text: &str) -> String {
    text.chars()
        .rev()
        .take_while(|ch| is_ident_char(*ch))
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn ident_head(text: &str) -> String {
    text.chars().take_while(|ch| is_ident_char(*ch)).collect()
}

fn contains_identifier(text: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    text.match_indices(identifier).any(|(start, matched)| {
        let before = text[..start].chars().next_back();
        let after = text[start + matched.len()..].chars().next();
        !before.is_some_and(is_ident_char) && !after.is_some_and(is_ident_char)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_field_offsets_preserve_sign_and_hex_semantics() {
        let database = db::Db::default();
        let plus = parse_field_ref("rcx->field_28 = 0;", 0x1000, &database).unwrap();
        let minus = parse_field_ref("var_8->field_m18 = 0;", 0x1000, &database).unwrap();
        assert_eq!(plus.offset, 0x28);
        assert_eq!(minus.offset, -0x18);
    }

    #[test]
    fn displayed_aliases_resolve_to_stable_recovered_bases() {
        let mut database = db::Db::default();
        database.set_variable(0x1000, "rcx", "context").unwrap();
        let field = parse_field_ref("context->field_10;", 0x1000, &database).unwrap();
        assert_eq!(field.base, "rcx");
    }

    #[test]
    fn named_fields_resolve_through_the_bound_type() {
        let mut database = db::Db::default();
        database.bind_type(0x1000, "rcx", "HEADER").unwrap();
        database
            .set_typed_field("HEADER", 0x28, "length", None)
            .unwrap();
        let field = parse_field_ref("rcx->length;", 0x1000, &database).unwrap();
        assert_eq!(field.offset, 0x28);
        assert_eq!(field.type_name.as_deref(), Some("HEADER"));
    }

    #[test]
    fn identifier_matching_rejects_substrings() {
        assert!(contains_identifier("rax = rcx;", "rcx"));
        assert!(!contains_identifier("rcx_saved = 0;", "rcx"));
        assert!(!contains_identifier("", "rcx"));
    }
}
