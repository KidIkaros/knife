//! Reversible analyst-approved binary patch staging.

use crate::address::{FileOffset, StaticVa};
use crate::analysis::engine;
use crate::workspace::Session;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchReceipt {
    pub address: StaticVa,
    pub file_offset: FileOffset,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearedPatchReceipt {
    pub file_offset: FileOffset,
    pub restored: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchSummary {
    pub file_offset: FileOffset,
    pub address: Option<StaticVa>,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReceipt {
    pub path: String,
    pub bytes_written: usize,
}

pub fn parse_replacement(value: &str) -> Result<Vec<u8>> {
    crate::db::parse_patch_bytes(value)
}

pub fn stage_patch(
    session: &mut Session,
    address: StaticVa,
    replacement: Vec<u8>,
) -> Result<PatchReceipt> {
    let base = engine::display_base(&session.bin);
    let offset = engine::va_to_off(&session.bin, base, address.get())
        .ok_or_else(|| anyhow!("address 0x{:x} is not backed by file bytes", address.get()))?;
    let offset_u64 = u64::try_from(offset).context("patch offset is too large")?;
    let start = offset;
    let end = start
        .checked_add(replacement.len())
        .context("patch range overflows")?;
    if replacement.is_empty() {
        return Err(anyhow!("patch bytes cannot be empty"));
    }
    if end > session.bytes.len() {
        return Err(anyhow!(
            "patch range 0x{offset:x}..0x{:x} exceeds the {}-byte file",
            offset_u64 + replacement.len() as u64,
            session.bytes.len()
        ));
    }
    let original: Vec<u8> = (0..replacement.len())
        .map(|index| {
            session
                .db
                .patches
                .get(&(offset_u64 + index as u64))
                .map_or(session.bytes[start + index], |patch| patch.original)
        })
        .collect();
    session
        .db
        .stage_patch(&session.bytes, offset_u64, &replacement)?;
    session.bytes[start..end].copy_from_slice(&replacement);
    Ok(PatchReceipt {
        address,
        file_offset: FileOffset(offset_u64),
        original,
        replacement,
    })
}

pub fn clear_patch(session: &mut Session, file_offset: FileOffset) -> Result<ClearedPatchReceipt> {
    let run = session
        .db
        .patch_runs()
        .into_iter()
        .find(|run| {
            file_offset.get() >= run.offset
                && file_offset.get() < run.offset + run.bytes.len() as u64
        })
        .ok_or_else(|| anyhow!("no staged patch contains offset 0x{:x}", file_offset.get()))?;
    let start = usize::try_from(run.offset).context("patch offset is too large")?;
    let end = start
        .checked_add(run.original.len())
        .context("patch range overflows")?;
    if end > session.bytes.len() {
        return Err(anyhow!("staged patch exceeds the current workspace image"));
    }
    let restored = run.original.clone();
    session.db.clear_patch_run_at(file_offset.get());
    session.bytes[start..end].copy_from_slice(&restored);
    Ok(ClearedPatchReceipt {
        file_offset: FileOffset(run.offset),
        restored,
    })
}

pub fn patches(session: &Session) -> Vec<PatchSummary> {
    let base = engine::display_base(&session.bin);
    session
        .db
        .patch_runs()
        .into_iter()
        .map(|run| PatchSummary {
            file_offset: FileOffset(run.offset),
            address: engine::off_to_va(&session.bin, base, run.offset).map(StaticVa),
            original: run.original,
            replacement: run.bytes,
        })
        .collect()
}

/// Export the current workspace image, including staged patches, without ever
/// overwriting the analyzed input.
pub fn export_workspace_image(session: &Session, output: &Path) -> Result<ExportReceipt> {
    let input = std::fs::canonicalize(&session.bin.path).ok();
    if output.exists() && std::fs::canonicalize(output).ok() == input && input.is_some() {
        return Err(anyhow!("refusing to overwrite the input binary"));
    }
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, &session.bytes)?;
    Ok(ExportReceipt {
        path: output.to_string_lossy().into_owned(),
        bytes_written: session.bytes.len(),
    })
}
