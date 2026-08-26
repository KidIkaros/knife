//! Serde payloads the frontend consumes.
//!
//! These mirror the front-end-agnostic types the `reknife` engine already
//! produces (`listing::Line`, `ir::Line`, `audit::Finding`, the model structs)
//! and add nothing but a stable JSON shape. Addresses cross the IPC boundary as
//! hex strings, never numbers: a u64 virtual address can exceed JavaScript's
//! safe-integer range, and the frontend treats an address as an opaque id it
//! displays and echoes back, so a string is both safer and more natural.

use reknife::analysis::{audit, hardening, ir, triage};
use reknife::listing::{Annot, Line};
use reknife::model::Binary;
use serde::Serialize;

/// Format a virtual address the way the whole UI addresses things.
pub fn hex(addr: u64) -> String {
    format!("0x{addr:x}")
}

/// One row in the function list.
#[derive(Serialize)]
pub struct FnRow {
    pub addr: String,
    pub name: String,
    pub named: bool,
    pub size: u64,
    pub blocks: usize,
    pub incoming: usize,
}

/// The summary returned right after a target is opened.
#[derive(Serialize)]
pub struct OpenResult {
    pub path: String,
    pub title: String,
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub functions: usize,
    pub named: usize,
    pub high_risk: usize,
    pub is_driver: bool,
}

/// The trailing comment on an instruction, with its source so the UI can colour
/// each kind distinctly (a user note is not a derived hint).
#[derive(Serialize)]
pub struct AnnotDto {
    pub kind: &'static str,
    pub text: String,
}

impl From<&Annot> for AnnotDto {
    fn from(a: &Annot) -> Self {
        match a {
            Annot::Note(t) => AnnotDto {
                kind: "note",
                text: t.clone(),
            },
            Annot::Symbol(t) => AnnotDto {
                kind: "symbol",
                text: t.clone(),
            },
            Annot::Local(t) => AnnotDto {
                kind: "local",
                text: t.clone(),
            },
            Annot::Text(t) => AnnotDto {
                kind: "text",
                text: t.clone(),
            },
            Annot::Hint(t) => AnnotDto {
                kind: "hint",
                text: t.clone(),
            },
        }
    }
}

/// One rendered disassembly line.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum LineDto {
    Label {
        addr: String,
        text: String,
    },
    /// A section header band in the linear view: segment name, whether it holds
    /// code or data, its permissions (absent for the container's own headers and
    /// for padding), its address range, and its size.
    Section {
        addr: String,
        name: String,
        /// "code" or "data" — named `code` because the enum's own tag is `kind`.
        code: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        perms: Option<String>,
        range: String,
        size: String,
    },
    /// A function header band in the linear view, so one routine is told from
    /// the next instead of running together into a wall.
    Sub {
        addr: String,
        name: String,
        meta: String,
    },
    Insn {
        addr: String,
        mnemonic: String,
        operands: String,
        annot: Option<AnnotDto>,
        target: Option<String>,
        /// The segment this row falls in, for the `.text:…`-style gutter. Only
        /// the linear sweep sets it; a per-function listing leaves it `None` and
        /// its gutter is unchanged.
        #[serde(skip_serializing_if = "Option::is_none")]
        seg: Option<String>,
    },
    Data {
        addr: String,
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        seg: Option<String>,
    },
}

impl From<&Line> for LineDto {
    fn from(line: &Line) -> Self {
        match line {
            Line::Label { addr, text } => LineDto::Label {
                addr: hex(*addr),
                text: text.clone(),
            },
            Line::Insn {
                addr,
                mnemonic,
                operands,
                annot,
                target,
            } => LineDto::Insn {
                addr: hex(*addr),
                mnemonic: mnemonic.clone(),
                operands: operands.clone(),
                annot: annot.as_ref().map(AnnotDto::from),
                target: target.map(hex),
                // A per-function listing has no segment gutter; only the linear
                // sweep sets this, and it builds its rows directly.
                seg: None,
            },
            Line::Data { addr, text } => LineDto::Data {
                addr: hex(*addr),
                text: text.clone(),
                seg: None,
            },
        }
    }
}

/// One line of decompiled pseudocode.
#[derive(Serialize)]
pub struct IrLineDto {
    pub label: bool,
    pub text: String,
}

impl From<&ir::Line> for IrLineDto {
    fn from(l: &ir::Line) -> Self {
        IrLineDto {
            label: l.label,
            text: l.text.clone(),
        }
    }
}

/// One cross-reference row (a caller of the current function, or one of its
/// callees).
#[derive(Serialize)]
pub struct XrefRow {
    /// The referencing (or referenced) address, as a jump target.
    pub addr: String,
    pub kind: &'static str,
    /// A human label: `func+0x1c` for a caller, the callee name for a callee.
    pub site: String,
}

/// One ranked attack-surface finding.
#[derive(Serialize)]
pub struct FindingDto {
    pub addr: String,
    pub func: Option<String>,
    pub api: String,
    pub pattern: &'static str,
    pub severity: u8,
    pub detail: String,
    pub reachable: bool,
    /// Where the dangerous value came from, named from the audit's own
    /// explanation: `SUBTRACTION`, `EXTERNAL INPUT`, `ARGUMENT`, and so on.
    pub source: &'static str,
    /// The instructions the argument came through, so the listing can highlight
    /// the flow rather than only marking its destination. Ascending; a step can
    /// sit after the call when a loop's back edge feeds it.
    pub trail: Vec<String>,
}

/// Name the provenance the audit found, from the sentence it wrote about it.
///
/// The audit already decided this when it built the explanation; recovering the
/// label from the text keeps the two from disagreeing, which is what a second
/// independent classification here would eventually do.
fn evidence_source(detail: &str) -> &'static str {
    if detail.contains("external-input API") {
        "EXTERNAL INPUT"
    } else if detail.contains("function argument") {
        "ARGUMENT"
    } else if detail.contains("some incoming paths") {
        "CFG MERGE"
    } else if detail.contains("subtraction") {
        "SUBTRACTION"
    } else if detail.contains("multiplication") {
        "MULTIPLICATION"
    } else if detail.contains("stack buffer") {
        "STACK BUFFER"
    } else {
        "RUNTIME VALUE"
    }
}

impl From<&audit::Finding> for FindingDto {
    fn from(f: &audit::Finding) -> Self {
        FindingDto {
            addr: hex(f.addr),
            func: f.func.clone(),
            api: f.api.clone(),
            pattern: f.pattern,
            severity: f.severity,
            detail: f.detail.clone(),
            reachable: f.reachable,
            source: evidence_source(&f.detail),
            trail: f.trail.iter().copied().map(hex).collect(),
        }
    }
}

// ── binary detail (the right-hand panel) ────────────────────────────────────

#[derive(Serialize)]
pub struct SectionDto {
    pub name: String,
    pub vaddr: String,
    pub vsize: u64,
    pub flags: String,
    pub entropy: f64,
}

#[derive(Serialize)]
pub struct HashesDto {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub imphash: Option<String>,
}

#[derive(Serialize)]
pub struct MitigationDto {
    pub name: &'static str,
    /// Human wording: "enabled" / "partial" / "disabled" / "n/a".
    pub state: &'static str,
    /// The shared marker vocabulary — info / warn / bad / na — which is what
    /// drives the colour and the `[+]` `[=]` `[-]` mark. Sent alongside the
    /// label because the two are not interchangeable.
    pub kind: &'static str,
    pub detail: String,
    pub impact: &'static str,
}

#[derive(Serialize)]
pub struct MitigationsDto {
    pub exposure: &'static str,
    pub score: u32,
    pub missing: usize,
    pub applicable: usize,
    pub findings: Vec<MitigationDto>,
}

#[derive(Serialize)]
pub struct SignalDto {
    pub text: String,
    pub weight: i32,
    pub kind: &'static str,
}

#[derive(Serialize)]
pub struct TriageDto {
    pub score: i32,
    pub verdict: &'static str,
    pub signals: Vec<SignalDto>,
}

#[derive(Serialize)]
pub struct SigningDto {
    pub signed: bool,
    /// WIN_CERTIFICATE entries in the table.
    pub entries: usize,
    /// Certificate subjects (Common Names), deduped, signer first.
    pub subjects: Vec<String>,
    /// SHA-1 thumbprints of the certificate blobs, which is what a revocation
    /// list or a threat-intel lookup is keyed by.
    pub thumbprints: Vec<String>,
    /// Where the certificate table lives, so it can be inspected as bytes.
    pub region_off: Option<String>,
    pub region_size: Option<u64>,
    /// The header claims a signature. A claim without a parsable table is worth
    /// seeing: it is what a stripped or malformed signature looks like.
    pub header_claims_signed: bool,
}

#[derive(Serialize)]
pub struct CapabilityDto {
    pub category: &'static str,
    pub apis: Vec<String>,
}

#[derive(Serialize)]
pub struct BinaryDetail {
    pub path: String,
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub size: u64,
    pub image_base: String,
    pub entry: String,
    pub subsystem: Option<String>,
    pub is_lib: bool,
    pub is_stripped: bool,
    pub functions: usize,
    pub named: usize,
    pub sections: Vec<SectionDto>,
    pub hashes: HashesDto,
    pub mitigations: MitigationsDto,
    pub triage: TriageDto,
    pub signing: SigningDto,
    /// What the imports say the binary can do, grouped by category.
    pub capabilities: Vec<CapabilityDto>,
}

/// Build the mitigations block from a hardening report.
pub fn mitigations(report: &hardening::Report) -> MitigationsDto {
    MitigationsDto {
        exposure: report.exposure.label(),
        score: report.score,
        missing: report.missing,
        applicable: report.applicable,
        findings: report
            .findings
            .iter()
            .map(|f| MitigationDto {
                name: f.name,
                state: f.state.label(),
                kind: f.state.kind(),
                detail: f.detail.clone(),
                impact: f.impact,
            })
            .collect(),
    }
}

/// Build the triage block from a triage result.
pub fn triage(result: &triage::TriageResult) -> TriageDto {
    TriageDto {
        score: result.score,
        verdict: result.verdict.label(),
        signals: result
            .signals
            .iter()
            .map(|s| SignalDto {
                text: s.text.clone(),
                weight: s.weight,
                kind: s.kind,
            })
            .collect(),
    }
}

/// The section table, front-end shaped.
pub fn sections(bin: &Binary) -> Vec<SectionDto> {
    bin.sections
        .iter()
        .map(|s| SectionDto {
            name: s.name.clone(),
            vaddr: hex(s.vaddr),
            vsize: s.vsize,
            flags: s.flags(),
            entropy: s.entropy,
        })
        .collect()
}

/// One window of the linear sweep.
///
/// `next` is the file offset to continue from. It has to come back with the
/// lines rather than be worked out from them: only the decoder knows how long
/// the last instruction was, and a caller guessing at that boundary would resume
/// inside an instruction and decode rubbish from there on. `None` means the end
/// of the file.
#[derive(Serialize)]
pub struct SweepDto {
    pub lines: Vec<LineDto>,
    pub start: u64,
    pub next: Option<u64>,
}

// ── navigator overview band ─────────────────────────────────────────────────

/// One bucket of the whole-file navigator band: a slice of the image summarised
/// by its entropy, the section it falls in, and the audit findings that land in
/// it. Laid out in file-offset space (the natural domain of entropy); `va` is a
/// representative virtual address so the frontend can seek without knowing the
/// section map.
#[derive(Serialize)]
pub struct OverviewBucket {
    /// File offset of the bucket start. A file offset is bounded by the file
    /// size, so it stays a JSON number rather than a hex string.
    pub off: u64,
    /// Representative virtual address (`off_to_va`), or `None` for a bucket that
    /// is not mapped into the address space (headers, padding, overlay).
    pub va: Option<String>,
    /// Mean Shannon entropy of the slice, 0..8.
    pub entropy: f64,
    /// Name of the section this bucket falls in, if any.
    pub section: Option<String>,
    /// The owning section is executable (code) rather than data.
    pub code: bool,
    /// Audit findings whose call site lands in this bucket.
    pub findings: u32,
    /// Highest severity among those findings (0 when there are none).
    pub max_sev: u8,
}

/// The navigator band model for the open target.
#[derive(Serialize)]
pub struct OverviewDto {
    pub size: u64,
    /// Bytes per bucket (the sampling step), so the frontend can label ranges.
    pub bucket_bytes: u64,
    pub buckets: Vec<OverviewBucket>,
    /// Index of the bucket containing the entry point, for a caret anchor.
    pub entry: Option<usize>,
}

// ── control-flow graph ──────────────────────────────────────────────────────

/// One basic block, with enough of its body to render a readable card.
#[derive(Serialize)]
pub struct CfgNode {
    pub id: String,
    pub addr: String,
    /// "entry" or "block".
    pub kind: &'static str,
    /// The block's instructions as the listing renders them — mnemonic and
    /// operands apart, the resolved callee or string literal alongside, and the
    /// target to follow. A card shows the same code the disassembly does, rather
    /// than a flattened line of text.
    pub insns: Vec<LineDto>,
    pub count: usize,
    pub bytes: u64,
}

/// One control-flow edge. `kind` is "true" / "false" / "flow"; `back` marks a
/// loop edge, which the layout draws differently because it points upward.
#[derive(Serialize)]
pub struct CfgEdge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    pub back: bool,
}

#[derive(Serialize)]
pub struct CfgDto {
    pub function: String,
    pub entry: String,
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

/// One string literal, with the address code refers to it by.
#[derive(Serialize)]
pub struct StringRow {
    pub addr: String,
    pub text: String,
    pub wide: bool,
    pub len: u64,
    /// How many instructions reference it — the reason to care about it.
    pub refs: usize,
}

/// One line of console output. `kind` drives its colour: the echoed command,
/// ordinary output, an error, or a dimmed hint.
#[derive(Serialize)]
pub struct ConsoleLine {
    pub kind: &'static str,
    pub text: String,
}

impl ConsoleLine {
    pub fn out(text: impl Into<String>) -> ConsoleLine {
        ConsoleLine {
            kind: "out",
            text: text.into(),
        }
    }
    pub fn err(text: impl Into<String>) -> ConsoleLine {
        ConsoleLine {
            kind: "err",
            text: text.into(),
        }
    }
    pub fn hint(text: impl Into<String>) -> ConsoleLine {
        ConsoleLine {
            kind: "hint",
            text: text.into(),
        }
    }
}
