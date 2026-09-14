//! Explicit analyst-approved annotation mutations.
//!
//! Model output is a proposal and must never call this API implicitly. Front
//! ends invoke it only after a user action or an audited non-model policy.

use crate::address::StaticVa;
use crate::analysis::engine;
use crate::db;
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnalystEdit {
    SetName {
        address: StaticVa,
        name: String,
    },
    ClearName {
        address: StaticVa,
    },
    SetNote {
        address: StaticVa,
        note: String,
    },
    ClearNote {
        address: StaticVa,
    },
    SetPrototype {
        function: StaticVa,
        returns: String,
        params: Vec<String>,
    },
    ClearPrototype {
        function: StaticVa,
    },
    BindType {
        function: StaticVa,
        base: String,
        type_name: String,
    },
    ClearTypeBinding {
        function: StaticVa,
        base: String,
    },
    SetField {
        type_name: String,
        offset: i64,
        name: String,
        data_type: Option<String>,
    },
    ClearField {
        type_name: String,
        offset: i64,
    },
    SetVariable {
        function: StaticVa,
        base: String,
        name: String,
    },
    ClearVariable {
        function: StaticVa,
        base: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalystEditKind {
    SetName,
    ClearName,
    SetNote,
    ClearNote,
    SetPrototype,
    ClearPrototype,
    BindType,
    ClearTypeBinding,
    SetField,
    ClearField,
    SetVariable,
    ClearVariable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditReceipt {
    pub kind: AnalystEditKind,
    pub address: Option<StaticVa>,
    pub previous: Option<String>,
    pub current: Option<String>,
}

pub fn apply_analyst_edit(session: &mut Session, edit: AnalystEdit) -> Result<EditReceipt> {
    match edit {
        AnalystEdit::SetName { address, name } => {
            let name = name.trim();
            if name.is_empty() || !db::valid_identifier(name) {
                return Err(anyhow!("{name:?} is not a valid identifier"));
            }
            let stored = stored_address(session, address)?;
            let previous = session.db.names.get(&stored).cloned();
            session.db.set_name(stored, name);
            Ok(EditReceipt {
                kind: AnalystEditKind::SetName,
                address: Some(address),
                previous,
                current: Some(name.to_string()),
            })
        }
        AnalystEdit::ClearName { address } => {
            let stored = stored_address(session, address)?;
            let previous = session.db.clear_name(stored);
            Ok(EditReceipt {
                kind: AnalystEditKind::ClearName,
                address: Some(address),
                previous,
                current: None,
            })
        }
        AnalystEdit::SetNote { address, note } => {
            let note = note.trim();
            if note.is_empty() {
                return apply_analyst_edit(session, AnalystEdit::ClearNote { address });
            }
            let stored = stored_address(session, address)?;
            let previous = session.db.notes.get(&stored).cloned();
            session.db.set_note(stored, note);
            Ok(EditReceipt {
                kind: AnalystEditKind::SetNote,
                address: Some(address),
                previous,
                current: Some(note.to_string()),
            })
        }
        AnalystEdit::ClearNote { address } => {
            let stored = stored_address(session, address)?;
            let previous = session.db.clear_note(stored);
            Ok(EditReceipt {
                kind: AnalystEditKind::ClearNote,
                address: Some(address),
                previous,
                current: None,
            })
        }
        AnalystEdit::SetPrototype {
            function,
            returns,
            params,
        } => {
            let stored = stored_address(session, function)?;
            let returns = returns.trim();
            let params: Vec<String> = params
                .into_iter()
                .map(|param| param.trim().to_string())
                .collect();
            let previous = session
                .db
                .prototype(stored)
                .map(|prototype| format_prototype(&prototype.returns, &prototype.params));
            session.db.set_prototype(stored, returns, &params)?;
            Ok(EditReceipt {
                kind: AnalystEditKind::SetPrototype,
                address: Some(function),
                previous,
                current: Some(format_prototype(returns, &params)),
            })
        }
        AnalystEdit::ClearPrototype { function } => {
            let stored = stored_address(session, function)?;
            let previous = session
                .db
                .clear_prototype(stored)
                .map(|prototype| format_prototype(&prototype.returns, &prototype.params));
            Ok(EditReceipt {
                kind: AnalystEditKind::ClearPrototype,
                address: Some(function),
                previous,
                current: None,
            })
        }
        AnalystEdit::BindType {
            function,
            base,
            type_name,
        } => {
            let stored = stored_address(session, function)?;
            let base = base.trim();
            let type_name = type_name.trim();
            let previous = session.db.bound_type(stored, base).map(str::to_string);
            session.db.bind_type(stored, base, type_name)?;
            Ok(EditReceipt {
                kind: AnalystEditKind::BindType,
                address: Some(function),
                previous,
                current: Some(type_name.to_string()),
            })
        }
        AnalystEdit::ClearTypeBinding { function, base } => {
            let stored = stored_address(session, function)?;
            let previous = session.db.clear_binding(stored, base.trim());
            Ok(EditReceipt {
                kind: AnalystEditKind::ClearTypeBinding,
                address: Some(function),
                previous,
                current: None,
            })
        }
        AnalystEdit::SetField {
            type_name,
            offset,
            name,
            data_type,
        } => {
            let type_name = type_name.trim();
            let name = name.trim();
            let data_type = data_type
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let previous = session
                .db
                .fields
                .get(type_name)
                .and_then(|fields| fields.get(&offset))
                .map(ToString::to_string);
            session
                .db
                .set_typed_field(type_name, offset, name, data_type)?;
            Ok(EditReceipt {
                kind: AnalystEditKind::SetField,
                address: None,
                previous,
                current: Some(match data_type {
                    Some(data_type) => format!("{name}: {data_type}"),
                    None => name.to_string(),
                }),
            })
        }
        AnalystEdit::ClearField { type_name, offset } => {
            let previous = session
                .db
                .clear_field(type_name.trim(), offset)
                .map(|field| field.to_string());
            Ok(EditReceipt {
                kind: AnalystEditKind::ClearField,
                address: None,
                previous,
                current: None,
            })
        }
        AnalystEdit::SetVariable {
            function,
            base,
            name,
        } => {
            let stored = stored_address(session, function)?;
            let base = base.trim();
            let name = name.trim();
            let previous = session.db.variable_name(stored, base).map(str::to_string);
            session.db.set_variable(stored, base, name)?;
            Ok(EditReceipt {
                kind: AnalystEditKind::SetVariable,
                address: Some(function),
                previous,
                current: Some(name.to_string()),
            })
        }
        AnalystEdit::ClearVariable { function, base } => {
            let stored = stored_address(session, function)?;
            let previous = session.db.clear_variable(stored, base.trim());
            Ok(EditReceipt {
                kind: AnalystEditKind::ClearVariable,
                address: Some(function),
                previous,
                current: None,
            })
        }
    }
}

fn format_prototype(returns: &str, params: &[String]) -> String {
    format!("{returns} ({})", params.join(", "))
}

fn stored_address(session: &Session, address: StaticVa) -> Result<u64> {
    if engine::va_to_off(
        &session.bin,
        engine::display_base(&session.bin),
        address.get(),
    )
    .is_none()
    {
        return Err(anyhow!(
            "address 0x{:x} is not mapped in this image",
            address.get()
        ));
    }
    address
        .get()
        .checked_sub(engine::display_base(&session.bin))
        .ok_or_else(|| anyhow!("address 0x{:x} is below the image base", address.get()))
}
