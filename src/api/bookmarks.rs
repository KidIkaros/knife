//! Local analyst bookmarks. They are annotations, not binary-derived facts.
use crate::address::StaticVa;
use crate::analysis::engine;
use crate::{db::Db, model::Binary};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    pub address: StaticVa,
    pub user_name: Option<String>,
    pub user_comment: Option<String>,
}

pub fn list(binary: &Binary, database: &Db) -> Result<Vec<Bookmark>> {
    let base = engine::display_base(binary);
    database
        .bookmarks
        .iter()
        .map(|offset| {
            Ok(Bookmark {
                address: StaticVa(
                    base.checked_add(*offset)
                        .context("bookmark address overflows static VA")?,
                ),
                user_name: database.names.get(offset).cloned(),
                user_comment: database.notes.get(offset).cloned(),
            })
        })
        .collect()
}

/// Explicit user mutation. A failed save must not leave an apparent success in memory.
pub fn set(binary: &Binary, database: &mut Db, address: StaticVa, enabled: bool) -> Result<()> {
    let offset = address
        .get()
        .checked_sub(engine::display_base(binary))
        .context("bookmark static VA is below the image base")?;
    let existed = database.bookmarks.contains(&offset);
    if enabled {
        database.bookmarks.insert(offset);
    } else {
        database.bookmarks.remove(&offset);
    }
    if let Err(error) = database.save() {
        if existed {
            database.bookmarks.insert(offset);
        } else {
            database.bookmarks.remove(&offset);
        }
        return Err(error);
    }
    Ok(())
}
