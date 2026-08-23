//! The loaded workspace and its derived caches, behind a panic barrier.
//!
//! Modeled on `reknife`'s MCP server (`src/mcp.rs`): one cached analysis session
//! behind a request dispatcher, with every engine call wrapped in
//! `catch_unwind`. knife parses hostile binaries — a malformed sample that
//! unwinds the engine must produce an error, never take the window down.
//!
//! Expensive, name-independent derivations (the string map) are built once at
//! load. Name-dependent derivations (driver hints, the audit findings, the
//! detail panel) are rebuilt after an edit that changes recovery.

use crate::dto;
use anyhow::{anyhow, Result};
use reknife::analysis::strings::Located;
use reknife::analysis::{audit, capabilities, driver, engine, hardening, hashes, signing, triage};
use reknife::listing;
use reknife::workspace::Session;
use reknife::ANALYSIS_BUDGET;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Run analysis on a thread with a large stack, and return its result the way
/// `catch_unwind` would.
///
/// This does double duty. Tauri runs commands on worker threads whose default
/// stack (~2 MB) is far smaller than the main thread's, and the decompiler is
/// deeply recursive — on a large stripped image it can want more than 2 MB and
/// overflow, which aborts the process (a stack overflow is not catchable). A
/// 256 MB stack removes that ceiling, and `join()` still turns a panic into an
/// `Err` rather than taking the window down.
fn on_big_stack<T, F>(f: F) -> Result<T>
where
    T: Send,
    F: FnOnce() -> Result<T> + Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn_scoped(scope, move || AssertUnwindSafe(f).0())
            .expect("spawn analysis thread")
            .join()
            .map_err(|_| anyhow!("the analysis panicked while handling this file"))?
    })
}

/// One open target: the analysis session plus everything the views read that is
/// too expensive to rebuild per request.
pub struct Loaded {
    pub path: PathBuf,
    pub session: Session,
    /// Display base: converts a shown virtual address into the space `Db` stores.
    pub base: u64,
    /// String literals keyed by address — built once (name-independent).
    pub strings: BTreeMap<u64, Located>,
    /// Driver listing hints, when the target is a plausible driver.
    pub hints: Option<BTreeMap<u64, String>>,
    /// The BYOVD report, when the target really is a driver. A full walk of the
    /// analysis plus the string map, and the pane re-reads it every time its
    /// severity or reachability filter is toggled — but both of those are
    /// post-filters on this value, so it is built once here with the rest of the
    /// derived state rather than recomputed per request.
    pub driver: Option<driver::DriverReport>,
    /// Ranked attack-surface findings, canonically sorted.
    pub findings: Vec<audit::Finding>,
    /// The last function decompiled, and its lines.
    ///
    /// Showing the pseudocode tab fetches the lines and the per-line actions
    /// together, and each call ran the decompiler itself — the most expensive
    /// operation in the app, run twice over the same function at the same moment,
    /// on two threads contending for this struct's own lock. Behind a mutex
    /// because the read path hands out `&Loaded`; cleared whenever recovery
    /// changes, since a rename rewrites the text.
    pub pseudo: Mutex<Option<(u64, Vec<reknife::analysis::ir::Line>)>>,
    /// The detail panel, pre-serialized (hashing a large image is not free).
    pub detail: serde_json::Value,
    /// YARA matches for this target, and the rules that produced them. The
    /// triage verdict is computed *with* these, so loading rules changes the
    /// score exactly as `knife info --rules` does.
    pub yara: Vec<reknife::analysis::yara::RuleMatch>,
    pub yara_rules: Option<String>,
}

impl Loaded {
    /// Pseudocode for a function, decompiled once. The lines and the per-line
    /// actions are two separate requests over the same function, so the second
    /// one gets the first one's work instead of repeating it.
    pub fn decompiled(
        &self,
        f: &reknife::analysis::engine::Function,
    ) -> Vec<reknife::analysis::ir::Line> {
        if let Some((at, lines)) = self.pseudo.lock().unwrap().as_ref() {
            if *at == f.addr {
                return lines.clone();
            }
        }
        let lines = reknife::analysis::ir::decompile(
            &self.session.an,
            &self.session.bin,
            f,
            &self.strings,
            &self.session.db,
        );
        *self.pseudo.lock().unwrap() = Some((f.addr, lines.clone()));
        lines
    }
}

/// Every target the window has open, and which one the views are showing.
///
/// Order is insertion order, which is the tab order. Each entry holds a whole
/// analysis — the image bytes included — so several large binaries at once cost
/// real memory; closing a tab is what frees it.
#[derive(Default)]
struct Inner {
    open: Vec<Loaded>,
    active: usize,
}

/// The shared backend state.
#[derive(Default)]
pub struct AppState {
    inner: Mutex<Inner>,
}

/// One row in the target tab bar.
#[derive(serde::Serialize)]
pub struct TargetRow {
    pub path: String,
    pub title: String,
    pub active: bool,
}

impl AppState {
    /// Load a target (or reuse it if the same path is already open). All of the
    /// analysis, including the derived caches, happens inside one panic barrier.
    ///
    /// `phase` is called as each stage begins. Recovering functions in a large
    /// image takes seconds, and a window that says nothing for that long looks
    /// hung; naming the stage costs nothing and tells the truth.
    pub fn open(&self, path: &str, phase: &dyn Fn(&str)) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        // Already open: switching to it is instant, and re-analysing a target
        // the window is already holding would be pure waste.
        if let Some(i) = guard.open.iter().position(|l| l.path == Path::new(path)) {
            guard.active = i;
            return Ok(());
        }
        let loaded = catch_unwind(AssertUnwindSafe(|| -> Result<Loaded> {
            phase("parsing and recovering functions");
            let session = Session::open(path, None, ANALYSIS_BUDGET, "the graphical view")?;
            let base = engine::display_base(&session.bin);
            phase("mapping string literals");
            let strings = listing::string_map(&session.bin, &session.bytes, base);
            let mut loaded = Loaded {
                path: PathBuf::from(path),
                session,
                base,
                strings,
                hints: None,
                driver: None,
                pseudo: Mutex::new(None),
                findings: Vec::new(),
                detail: serde_json::Value::Null,
                yara: Vec::new(),
                yara_rules: None,
            };
            recompute_derived_with(&mut loaded, phase);
            Ok(loaded)
        }))
        .map_err(|_| anyhow!("the analysis panicked while loading this file"))??;
        guard.open.push(loaded);
        guard.active = guard.open.len() - 1;
        Ok(())
    }

    /// Load YARA rules and rescan, then rebuild the verdict with the matches.
    ///
    /// Passing `None` clears them, which puts the score back to the rule-free
    /// one rather than leaving a stale verdict behind.
    pub fn set_yara(&self, rules: Option<&str>) -> Result<usize> {
        let mut guard = self.inner.lock().unwrap();
        let active = guard.active;
        let loaded = guard
            .open
            .get_mut(active)
            .ok_or_else(|| anyhow!("no target is open"))?;
        // As in `edit`: the rebuild that follows the scan runs the audit and the
        // detail panel over hostile bytes, so it goes inside the barrier rather
        // than after it, where a panic would poison the lock held here.
        on_big_stack(move || {
            let matched = match rules {
                Some(path) => {
                    let (compiled, _) = reknife::analysis::yara::compile(path)?;
                    let hits = reknife::analysis::yara::scan(&compiled, &loaded.session.bytes)?;
                    let n = hits.len();
                    loaded.yara = hits;
                    loaded.yara_rules = Some(path.to_string());
                    n
                }
                None => {
                    loaded.yara.clear();
                    loaded.yara_rules = None;
                    0
                }
            };
            recompute_derived(loaded);
            Ok(matched)
        })
    }

    /// Show an already-open target.
    pub fn select(&self, path: &str) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        let i = guard
            .open
            .iter()
            .position(|l| l.path == Path::new(path))
            .ok_or_else(|| anyhow!("{path} is not open"))?;
        guard.active = i;
        Ok(())
    }

    /// Close a target and free its analysis, keeping the selection sensible.
    pub fn close(&self, path: &str) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        let Some(i) = guard.open.iter().position(|l| l.path == Path::new(path)) else {
            return Ok(());
        };
        guard.open.remove(i);
        // Closing a tab before the active one shifts it left; closing the last
        // one steps back rather than off the end.
        let active = guard.active;
        guard.active = if guard.open.is_empty() {
            0
        } else if i < active {
            active - 1
        } else {
            active.min(guard.open.len() - 1)
        };
        Ok(())
    }

    /// The open targets, in tab order.
    pub fn targets(&self) -> Vec<TargetRow> {
        let guard = self.inner.lock().unwrap();
        guard
            .open
            .iter()
            .enumerate()
            .map(|(i, l)| TargetRow {
                path: l.path.to_string_lossy().into_owned(),
                title: l
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| l.path.to_string_lossy().into_owned()),
                active: i == guard.active,
            })
            .collect()
    }

    /// Read the loaded workspace, panic-contained. Errors if nothing is open.
    pub fn read<T: Send>(&self, f: impl FnOnce(&Loaded) -> Result<T> + Send) -> Result<T> {
        let guard = self.inner.lock().unwrap();
        let loaded = guard
            .open
            .get(guard.active)
            .ok_or_else(|| anyhow!("no target is open"))?;
        on_big_stack(move || f(loaded))
    }

    /// Persist an analyst fact that does not change recovery (a note). Saves the
    /// database; no re-analysis, so a comment on a huge image is instant.
    pub fn annotate<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        let mut guard = self.inner.lock().unwrap();
        let active = guard.active;
        let loaded = guard
            .open
            .get_mut(active)
            .ok_or_else(|| anyhow!("no target is open"))?;
        catch_unwind(AssertUnwindSafe(|| {
            let out = f(&mut loaded.session)?;
            loaded.session.db.save()?;
            Ok::<T, anyhow::Error>(out)
        }))
        .map_err(|_| anyhow!("the edit panicked"))?
    }

    /// Persist an analyst fact that changes recovery (a name), then rebuild the
    /// analysis and the name-dependent caches — the GUI equivalent of the TUI's
    /// `refresh_analysis`. Uses `ANALYSIS_BUDGET` so the on-disk cache stays valid.
    pub fn edit<T: Send>(&self, f: impl FnOnce(&mut Session) -> Result<T> + Send) -> Result<T> {
        let mut guard = self.inner.lock().unwrap();
        let active = guard.active;
        let loaded = guard
            .open
            .get_mut(active)
            .ok_or_else(|| anyhow!("no target is open"))?;
        // The re-analysis belongs inside the barrier, not after it. It runs the
        // same hostile-input engine as `open`, and it used to run bare: a panic
        // in `engine::analyze` or `audit::run` unwound through the `MutexGuard`
        // this function is holding, poisoning it, and every later `lock().unwrap()`
        // in this file panicked — one bad rename killed the window for the rest of
        // the session. Running it on the analysis thread keeps the unwind over
        // there, so a panic comes back as an `Err` and the lock survives; the
        // large stack is the same insurance the read path already takes.
        on_big_stack(move || {
            let out = f(&mut loaded.session)?;
            loaded.session.db.save()?;
            let an = engine::analyze(
                &loaded.session.bin,
                &loaded.session.bytes,
                ANALYSIS_BUDGET,
                &loaded.session.db,
            );
            loaded.session.an = an;
            recompute_derived(loaded);
            Ok(out)
        })
    }
}

/// Rebuild the name-dependent caches from the current analysis.
fn recompute_derived(loaded: &mut Loaded) {
    recompute_derived_with(loaded, &|_| {});
}

/// As `recompute_derived`, reporting each stage as it starts.
fn recompute_derived_with(loaded: &mut Loaded, phase: &dyn Fn(&str)) {
    let session = &loaded.session;
    phase("auditing call sites");
    let plausible = driver::plausibly_a_driver(&session.bin);
    let hints = plausible.then(|| driver::listing_hints(&session.bin, &session.bytes, &session.an));
    let report = plausible
        .then(|| driver::report(&session.bin, &session.bytes, &session.an, &loaded.strings))
        .filter(|r| r.is_driver);
    let mut findings = audit::run(&session.an, &session.bin, &session.bytes);
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.reachable.cmp(&a.reachable))
            .then(a.addr.cmp(&b.addr))
    });
    phase("hashing and reading mitigations");
    let yara_names: Vec<String> = loaded.yara.iter().map(|m| m.rule.clone()).collect();
    let detail = build_detail(&loaded.session, &yara_names);
    loaded.hints = hints;
    loaded.driver = report;
    // A rename or a retype rewrites the pseudocode, so the cached copy is no
    // longer what the analyst would see.
    *loaded.pseudo.lock().unwrap() = None;
    loaded.findings = findings;
    loaded.detail = detail;
}

/// Assemble the right-hand detail panel: identity, sections, hashes, exploit
/// mitigations, the triage verdict, and signing.
fn build_detail(s: &Session, yara_names: &[String]) -> serde_json::Value {
    let file_hashes = hashes::file_hashes(&s.bytes);
    let imphash = hashes::imphash(&s.bin);
    let hardening = hardening::run(&s.bin);
    let caps = capabilities::matches(
        s.bin
            .all_imported_functions()
            .chain(s.bin.exports.iter().map(String::as_str)),
    );
    let verdict = triage::run(&s.bin, &caps, yara_names);

    // Group the capability matches by category, most-populated first: the
    // categories are the summary, the APIs are the evidence.
    let mut by_category: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for m in &caps {
        by_category
            .entry(m.category)
            .or_default()
            .push(m.api.clone());
    }
    let mut capabilities: Vec<dto::CapabilityDto> = by_category
        .into_iter()
        .map(|(category, mut apis)| {
            apis.sort();
            apis.dedup();
            dto::CapabilityDto { category, apis }
        })
        .collect();
    capabilities.sort_by(|a, b| {
        b.apis
            .len()
            .cmp(&a.apis.len())
            .then(a.category.cmp(b.category))
    });
    let signing = signing::summarize(&s.bin, &s.bytes);
    let named = s.an.functions.iter().filter(|f| f.named).count();

    let detail = dto::BinaryDetail {
        path: s.bin.path.clone(),
        format: s.bin.format.label().to_string(),
        arch: s.bin.arch.label().to_string(),
        bits: s.bin.bits,
        size: s.bin.size,
        image_base: dto::hex(s.bin.image_base),
        entry: dto::hex(s.bin.entry),
        subsystem: s.bin.subsystem.clone(),
        is_lib: s.bin.is_lib,
        is_stripped: s.bin.is_stripped,
        functions: s.an.functions.len(),
        named,
        sections: dto::sections(&s.bin),
        hashes: dto::HashesDto {
            md5: file_hashes.md5,
            sha1: file_hashes.sha1,
            sha256: file_hashes.sha256,
            imphash,
        },
        mitigations: dto::mitigations(&hardening),
        triage: dto::triage(&verdict),
        capabilities,
        signing: dto::SigningDto {
            signed: signing.signed,
            entries: signing.entries,
            subjects: signing.subjects,
            thumbprints: signing.thumbprints,
            region_off: s.bin.sig_region.map(|(off, _)| dto::hex(off)),
            region_size: s.bin.sig_region.map(|(_, size)| size),
            header_claims_signed: s.bin.has_signature,
        },
    };
    serde_json::to_value(detail).unwrap_or(serde_json::Value::Null)
}
