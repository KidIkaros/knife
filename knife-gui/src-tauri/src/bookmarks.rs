//! Bookmarks: named marks on addresses, persisted per binary.
//!
//! IDA's marks, for the same reason: an address that took work to reach — the
//! IOCTL handler, the size computation you proved wrong — should survive the
//! restart. Stored in a small JSON sidecar under the app-data directory,
//! keyed by the open target's path; bookmarks are window furniture, not
//! engine facts, so they stay out of reknife's annotation database.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[derive(Serialize)]
pub struct BookmarkRow {
    pub addr: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    addr: String,
    #[serde(default)]
    label: String,
}

type Store = BTreeMap<String, Vec<Entry>>;

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("bookmarks.json"))
}

fn load(app: &AppHandle) -> Store {
    let Ok(path) = store_path(app) else {
        return BTreeMap::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn save(app: &AppHandle, all: &Store) -> Result<(), String> {
    let path = store_path(app)?;
    let text = serde_json::to_string_pretty(all).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())
}

/// The bookmarks for one binary, in address order.
#[tauri::command]
pub fn bookmarks_list(app: AppHandle, path: String) -> Result<Vec<BookmarkRow>, String> {
    let all = load(&app);
    let mut rows: Vec<BookmarkRow> = all
        .get(&path)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|e| BookmarkRow {
            addr: e.addr,
            label: e.label,
        })
        .collect();
    rows.sort_by(|a, b| a.addr.cmp(&b.addr));
    Ok(rows)
}

/// Mark or unmark an address. Returns whether it is now marked.
///
/// `label` is applied when marking; an existing mark is removed regardless of
/// it, which keeps toggle a single keystroke.
#[tauri::command]
pub fn bookmark_toggle(
    app: AppHandle,
    path: String,
    addr: String,
    label: Option<String>,
) -> Result<bool, String> {
    let mut all = load(&app);
    let list = all.entry(path).or_default();
    // Addresses compare canonically: one spelling per mark.
    let at = addr.to_lowercase();
    if let Some(i) = list.iter().position(|e| e.addr == at) {
        list.remove(i);
        save(&app, &all)?;
        return Ok(false);
    }
    list.push(Entry {
        addr: at,
        label: label.unwrap_or_default(),
    });
    save(&app, &all)?;
    Ok(true)
}
