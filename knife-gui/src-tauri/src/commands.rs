//! Tauri commands: the IPC surface the frontend calls. Each one is a thin
//! mapping onto a `reknife` engine call, exactly like the MCP server's tools —
//! the analysis lives in the library, this file only shapes the request and the
//! reply and turns `anyhow` errors into strings the frontend can show.

use crate::dto::{
    hex, AnnotDto, CfgDto, CfgEdge, CfgNode, FindingDto, FnRow, IrLineDto, LineDto, OpenResult,
    OverviewBucket, OverviewDto, StringRow, SweepDto, XrefRow,
};
use crate::state::{AppState, TargetRow};
use anyhow::{anyhow, Result};
use reknife::analysis::engine::{self, Analysis, Function};
use reknife::analysis::{disasm, graphs};
use reknife::db;
use reknife::listing;
use reknife::model::SymKind;
use serde::Serialize;
use tauri::{Emitter, State};

/// Resolve a selector — a symbol name, or a hex address — to a function.
/// Name first (so a symbol that looks like a number still wins), then the entry
/// address, then the function whose body contains the address. Mirrors
/// `mcp.rs::resolve`.
pub(crate) fn resolve<'a>(an: &'a Analysis, sel: &str) -> Option<&'a Function> {
    if let Some(f) = an.find_by_name(sel) {
        return Some(f);
    }
    let raw = sel.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(raw, 16)
        .ok()
        .and_then(|a| an.find_function(a).or_else(|| an.function_at(a)))
}

/// Parse a `0x…` (or bare hex) address.
pub(crate) fn parse_addr(s: &str) -> Result<u64> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(raw, 16).map_err(|_| anyhow!("not an address: {s:?}"))
}

/// `func+0x1c` for the site of a cross-reference.
pub(crate) fn site_name(an: &Analysis, addr: u64) -> String {
    match an.function_at(addr) {
        Some(f) => {
            let off = addr.saturating_sub(f.addr);
            if off == 0 {
                f.name.clone()
            } else {
                format!("{}+0x{off:x}", f.name)
            }
        }
        None => "-".to_string(),
    }
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

#[tauri::command]
pub fn open_target(
    app: tauri::AppHandle,
    state: State<AppState>,
    path: String,
) -> Result<OpenResult, String> {
    state
        .open(&path, &|p| {
            let _ = app.emit("knife://phase", p);
        })
        .map_err(|e| e.to_string())?;
    state
        .read(|l| {
            let an = &l.session.an;
            let named = an.functions.iter().filter(|f| f.named).count();
            Ok(OpenResult {
                path: l.session.bin.path.clone(),
                title: basename(&path),
                format: l.session.bin.format.label().to_string(),
                arch: l.session.bin.arch.label().to_string(),
                bits: l.session.bin.bits,
                functions: an.functions.len(),
                named,
                high_risk: l.findings.iter().filter(|f| f.severity >= 3).count(),
                is_driver: l.hints.is_some(),
            })
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_functions(
    state: State<AppState>,
    filter: Option<String>,
    named_only: Option<bool>,
    limit: Option<usize>,
) -> Result<Vec<FnRow>, String> {
    let needle = filter.unwrap_or_default().to_lowercase();
    let named_only = named_only.unwrap_or(false);
    let limit = limit.unwrap_or(usize::MAX);
    state
        .read(|l| {
            let rows = l
                .session
                .an
                .functions
                .iter()
                .filter(|f| !named_only || f.named)
                .filter(|f| needle.is_empty() || f.name.to_lowercase().contains(&needle))
                .take(limit)
                .map(|f| FnRow {
                    addr: hex(f.addr),
                    name: f.name.clone(),
                    named: f.named,
                    size: f.size,
                    blocks: f.blocks.len(),
                    incoming: f.incoming,
                })
                .collect();
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

/// Disassembly for a function, or a hex dump for anything else.
///
/// A string literal and an import slot are both addresses worth navigating to,
/// and neither is inside a recovered function. Falling back to the data view —
/// as the terminal interface does — is what makes every address in the window
/// clickable rather than only the ones that happen to be code.
#[tauri::command]
pub fn disassemble(state: State<AppState>, selector: String) -> Result<Vec<LineDto>, String> {
    state
        .read(|l| {
            if let Some(f) = resolve(&l.session.an, &selector) {
                let lines = listing::function(
                    &l.session.an,
                    f,
                    &l.session.db,
                    l.base,
                    &l.strings,
                    l.hints.as_ref(),
                );
                return Ok(lines.iter().map(LineDto::from).collect());
            }
            let addr =
                parse_addr(&selector).map_err(|_| anyhow!("nothing matches {selector:?}"))?;
            if engine::va_to_off(&l.session.bin, l.base, addr).is_none() {
                return Err(anyhow!("{selector} is not mapped in this image"));
            }
            let lines = listing::data_view(&l.session.bin, l.base, &l.session.bytes, addr);
            Ok(lines.iter().map(LineDto::from).collect())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn decompile(state: State<AppState>, selector: String) -> Result<Vec<IrLineDto>, String> {
    state
        .read(|l| {
            let Some(f) = resolve(&l.session.an, &selector) else {
                // Not a function: there is nothing to decompile, which is a
                // blank tab rather than a failure.
                return Ok(Vec::new());
            };
            Ok(l.decompiled(f).iter().map(IrLineDto::from).collect())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn xrefs(
    state: State<AppState>,
    addr: String,
    direction: String,
) -> Result<Vec<XrefRow>, String> {
    let target = parse_addr(&addr).map_err(|e| e.to_string())?;
    state
        .read(|l| {
            let an = &l.session.an;
            let rows = if direction == "from" {
                // Callees: the calls the function at `addr` makes.
                let Some(f) = an.find_function(target).or_else(|| an.function_at(target)) else {
                    // A data address makes no calls; the callers direction is
                    // still meaningful and is what the pane shows by default.
                    return Ok(Vec::new());
                };
                f.calls
                    .iter()
                    .map(|&t| XrefRow {
                        addr: hex(t),
                        kind: "call",
                        site: an.label(t),
                    })
                    .collect()
            } else {
                // Callers: who references `addr`.
                an.xrefs_to
                    .get(&target)
                    .map(|refs| {
                        refs.iter()
                            .map(|x| XrefRow {
                                addr: hex(x.from),
                                kind: x.kind.label(),
                                site: site_name(an, x.from),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn attack_surface(state: State<AppState>) -> Result<Vec<FindingDto>, String> {
    state
        .read(|l| Ok(l.findings.iter().map(FindingDto::from).collect()))
        .map_err(|e| e.to_string())
}

/// One 16-byte row of a hex dump: address label, hex pairs, ascii gutter.
#[derive(Serialize)]
pub struct HexRow {
    pub label: String,
    pub hex: String,
    pub ascii: String,
}

/// The bytes at an address.
///
/// The inspector's whole backend: map the vaddr through the sections, read
/// from the in-memory image, format rows. Static bytes only — the file on
/// disk, never a run of the target.
#[tauri::command]
pub fn hex_dump(
    state: State<AppState>,
    addr: String,
    len: Option<usize>,
) -> Result<Vec<HexRow>, String> {
    state
        .read(|l| {
            let at = parse_addr(&addr)?;
            // Same correction as the linear sweep: the address on screen is
            // absolute, and only `va_to_off` takes the image base off first. With
            // `disasm::vaddr_to_off` here the inspector could never open on a PE.
            let off = engine::va_to_off(&l.session.bin, l.base, at)
                .ok_or_else(|| anyhow!("{addr} is not in any section"))?;
            let want = len.unwrap_or(128).clamp(16, 1024);
            let start = (off as usize).min(l.session.bytes.len());
            let end = (start + want).min(l.session.bytes.len());
            let data = &l.session.bytes[start..end];
            let mut rows = Vec::new();
            for (i, chunk) in data.chunks(16).enumerate() {
                let hexs: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if (0x20..=0x7e).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                rows.push(HexRow {
                    label: hex(at + (i * 16) as u64),
                    hex: hexs.join(" "),
                    ascii,
                });
            }
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

/// One stretch of the file that reads the same way all through it.
///
/// The file is not uniformly code. Sweeping it as if it were means decoding the
/// DOS stub, the import tables and the resources as x86-64, which produces pages
/// of instructions that never existed. Splitting it into stretches first is what
/// lets each be shown as what it is.
struct Region {
    start: u64,
    end: u64,
    name: String,
    /// Short segment tag for the gutter (`.text`, `HEADER`, `overlay`).
    seg: String,
    /// `R-X` / `RW-` etc. for a real section; `None` for the container's own
    /// headers, alignment padding, and a trailing overlay, none of which are
    /// mapped with permissions.
    perms: Option<String>,
    /// Whether the bytes here are meant to be executed.
    code: bool,
}

/// A section's permissions as the three-slot `rwx` string a disassembler shows.
fn perms(sec: &reknife::model::Section) -> String {
    let bit = |on: bool, c: char| if on { c } else { '-' };
    format!(
        "{}{}{}",
        bit(sec.read, 'R'),
        bit(sec.write, 'W'),
        bit(sec.exec, 'X')
    )
}

/// Cut the file into regions, in file order and covering all of it.
///
/// Everything before the first section is the container's own header — for a PE
/// the DOS header, the stub, and the PE headers. Gaps between sections are
/// alignment padding, and anything after the last one is an overlay: appended
/// data that is not part of the image at all, which is where an installer keeps
/// its payload and where a signature lives.
fn regions(bin: &reknife::model::Binary) -> Vec<Region> {
    let mut secs: Vec<&reknife::model::Section> =
        bin.sections.iter().filter(|s| s.file_size > 0).collect();
    secs.sort_by_key(|s| s.file_off);

    let mut out: Vec<Region> = Vec::new();
    let mut at = 0u64;
    for s in &secs {
        if s.file_off > at {
            let headers = at == 0;
            out.push(Region {
                start: at,
                end: s.file_off,
                name: if headers {
                    match bin.format {
                        reknife::model::Format::Pe => "DOS header, stub, and PE headers".into(),
                        _ => "container headers".into(),
                    }
                } else {
                    "alignment padding".into()
                },
                seg: if headers {
                    "HEADER".into()
                } else {
                    "align".into()
                },
                perms: None,
                code: false,
            });
        }
        let end = (s.file_off + s.file_size).min(bin.size);
        if end > s.file_off {
            out.push(Region {
                start: s.file_off,
                end,
                name: s.name.clone(),
                seg: s.name.clone(),
                perms: Some(perms(s)),
                code: s.exec,
            });
        }
        at = at.max(end);
    }
    if bin.size > at {
        out.push(Region {
            start: at,
            end: bin.size,
            name: "overlay".into(),
            seg: "overlay".into(),
            perms: None,
            code: false,
        });
    }
    if out.is_empty() {
        out.push(Region {
            start: 0,
            end: bin.size,
            name: "file".into(),
            seg: "file".into(),
            perms: None,
            code: false,
        });
    }
    out
}

/// A window of the file read straight through, from `off` towards the end.
///
/// The function views answer "what does this routine do". They cannot answer
/// "what is in this file", because recovery only reaches code it can prove is
/// reachable — anything it missed, every byte between functions, and everything
/// that is not code at all is simply absent from the window.
///
/// Addressed by file offset rather than by virtual address, which is what makes
/// it whole: the DOS header and stub sit before the first section and the
/// overlay sits after the last, so neither has an address in the image and
/// neither could be reached by a sweep that thought in addresses. Regions that
/// hold code are disassembled; everything else is shown as bytes.
///
/// Windowed and forward only: instruction lengths vary and the decoder does not
/// resynchronise, so a sweep is only honest from a boundary it was given. The
/// reply carries the offset to continue from, which is the only place that
/// boundary is known.
#[tauri::command]
pub fn disassemble_linear(
    state: State<AppState>,
    off: Option<u64>,
    at: Option<String>,
    count: Option<usize>,
) -> Result<SweepDto, String> {
    let want = count.unwrap_or(1500).clamp(1, 20000);
    state
        .read(|l| {
            let bin = &l.session.bin;
            let an = &l.session.an;
            let bytes = &l.session.bytes;

            // An address, when the caller has one — "sweep from the function I am
            // reading" — otherwise a plain offset, defaulting to the top of the
            // file so the sweep genuinely starts at the start.
            let mut cursor = match (off, at.as_deref()) {
                (Some(o), _) => o,
                (None, Some(s)) => {
                    let va = parse_addr(s)?;
                    engine::va_to_off(bin, l.base, va)
                        .ok_or_else(|| anyhow!("{s} is not in any section"))?
                        as u64
                }
                (None, None) => 0,
            };
            let start = cursor;
            if cursor >= bin.size {
                return Ok(SweepDto {
                    lines: Vec::new(),
                    start,
                    next: None,
                });
            }

            let regions = regions(bin);
            let mut out: Vec<LineDto> = Vec::new();
            let entry_off = disasm::entry_location(bin, bytes).map(|(o, _)| o);

            while out.len() < want && cursor < bin.size {
                let Some(r) = regions.iter().find(|r| cursor >= r.start && cursor < r.end) else {
                    break;
                };
                let before = cursor;

                // Name the stretch as it is entered, so a reader always knows
                // whether they are looking at code, at a table, or at bytes
                // appended after the image.
                if cursor == r.start || out.is_empty() {
                    out.push(LineDto::Section {
                        addr: hex(cursor),
                        name: r.name.clone(),
                        code: if r.code { "code" } else { "data" },
                        perms: r.perms.clone(),
                        range: format!("0x{:x}–0x{:x}", r.start, r.end),
                        size: reknife::output::human(r.end - r.start),
                    });
                }

                if r.code && disasm::supported(bin.arch) {
                    let va = engine::off_to_va(bin, l.base, cursor).unwrap_or(cursor);
                    let room = want.saturating_sub(out.len()).max(1);
                    let insns = disasm::disassemble(bytes, cursor, va, bin.bits, bin.arch, room);
                    if insns.is_empty() {
                        cursor = r.end;
                        continue;
                    }
                    for i in &insns {
                        let ilen = i.bytes.len() as u64;
                        // Stop at the region edge rather than running the decoder
                        // on into whatever follows it.
                        if cursor + ilen > r.end {
                            break;
                        }
                        if Some(cursor) == entry_off {
                            out.push(LineDto::Label {
                                addr: hex(i.addr),
                                text: "entry point:".into(),
                            });
                        }
                        // A function start is where a reader gets their bearings.
                        // Without them a sweep is an undifferentiated wall and one
                        // routine cannot be told from the next.
                        if let Some(f) = an.find_function(i.addr) {
                            if f.addr == i.addr && Some(cursor) != entry_off {
                                let blocks = f.blocks.len();
                                out.push(LineDto::Sub {
                                    addr: hex(i.addr),
                                    name: f.name.clone(),
                                    meta: format!(
                                        "{blocks} block{} · {}",
                                        if blocks == 1 { "" } else { "s" },
                                        reknife::output::human(f.size),
                                    ),
                                });
                            }
                        }
                        let (mnemonic, operands) = match i.text.split_once(char::is_whitespace) {
                            Some((m, rest)) => (m.to_string(), rest.trim_start().to_string()),
                            None => (i.text.clone(), String::new()),
                        };
                        // Name what a branch or call points at, and make it
                        // followable, by reading the target back out of the
                        // operand text.
                        let target = trailing_addr(&operands).filter(|t| {
                            an.find_function(*t).is_some() || an.imports.contains_key(t)
                        });
                        let annot = target.map(|t| AnnotDto {
                            kind: "symbol",
                            text: an.label(t),
                        });
                        out.push(LineDto::Insn {
                            addr: hex(i.addr),
                            mnemonic,
                            operands,
                            annot,
                            target: target.map(hex),
                            seg: Some(r.seg.clone()),
                        });
                        cursor += ilen;
                    }
                } else {
                    // Bytes, sixteen to a line, with the printable ones beside
                    // them — the DOS stub's message is readable this way, and a
                    // table looks like a table instead of like broken code.
                    while out.len() < want && cursor < r.end {
                        let end = (cursor + 16).min(r.end).min(bin.size);
                        let chunk = &bytes[cursor as usize..end as usize];
                        let hexs: String = chunk
                            .iter()
                            .map(|b| format!("{b:02x} "))
                            .collect::<String>();
                        let ascii: String = chunk
                            .iter()
                            .map(|&b| {
                                if (0x20..=0x7e).contains(&b) {
                                    b as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        out.push(LineDto::Data {
                            addr: hex(engine::off_to_va(bin, l.base, cursor).unwrap_or(cursor)),
                            text: format!("{hexs:<48} {ascii}"),
                            seg: Some(r.seg.clone()),
                        });
                        cursor = end;
                    }
                }

                // Whatever happened above, the cursor has to have moved. An
                // instruction straddling the end of its region consumes nothing
                // and would otherwise be reconsidered forever; the rest of that
                // region is not decodable from here, so step over it.
                if cursor == before {
                    if out.len() >= want {
                        break;
                    }
                    cursor = r.end;
                }
            }

            Ok(SweepDto {
                lines: out,
                start,
                next: (cursor < bin.size).then_some(cursor),
            })
        })
        .map_err(|e| e.to_string())
}

/// The last `0x…` in an operand list, which for a direct call or jump is what it
/// targets. Returns nothing when the operands hold no plain address — a register
/// or memory form has no single destination to name.
fn trailing_addr(operands: &str) -> Option<u64> {
    let at = operands.rfind("0x")?;
    let digits: String = operands[at + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    // A memory operand keeps its address inside brackets; that is a location the
    // instruction reads, not somewhere control goes.
    if operands[at..].contains(']') {
        return None;
    }
    u64::from_str_radix(&digits, 16).ok()
}

/// The navigator band: a whole-file overview sampled into buckets, each carrying
/// its entropy, the section it falls in, and the audit findings that land in it.
///
/// Laid out in file-offset space — the natural domain of entropy and a linear
/// read of the image. Findings (virtual addresses) and the entry point are
/// mapped into that space here, so the frontend paints a ready model; each
/// bucket also carries a representative virtual address for click-to-seek. One
/// linear entropy pass over the image, so it is fetched once per target, not per
/// edit.
#[tauri::command]
pub fn overview(state: State<AppState>, buckets: usize) -> Result<OverviewDto, String> {
    state
        .read(|l| {
            let bin = &l.session.bin;
            let bytes = &l.session.bytes;
            let base = l.base;
            let size = bytes.len();
            if size == 0 {
                return Ok(OverviewDto {
                    size: 0,
                    bucket_bytes: 0,
                    buckets: Vec::new(),
                    entry: None,
                });
            }
            let n = buckets.clamp(64, 2048);
            let step = size.div_ceil(n).max(1);

            // One bucket per slice: entropy, the owning section, and a
            // representative virtual address for seeking.
            let mut out: Vec<OverviewBucket> = bytes
                .chunks(step)
                .enumerate()
                .map(|(i, chunk)| {
                    let off = (i * step) as u64;
                    let section = bin.sections.iter().find(|s| {
                        s.file_size > 0 && off >= s.file_off && off < s.file_off + s.file_size
                    });
                    OverviewBucket {
                        off,
                        va: engine::off_to_va(bin, base, off).map(hex),
                        entropy: reknife::analysis::entropy::entropy(chunk),
                        section: section.map(|s| s.name.clone()),
                        code: section.map(|s| s.exec).unwrap_or(false),
                        findings: 0,
                        max_sev: 0,
                    }
                })
                .collect();

            // Fold each finding into its bucket by mapping the call site's
            // virtual address back to a file offset.
            let last = out.len().saturating_sub(1);
            for f in &l.findings {
                if let Some(off) = engine::va_to_off(bin, base, f.addr) {
                    let b = &mut out[(off / step).min(last)];
                    b.findings += 1;
                    b.max_sev = b.max_sev.max(f.severity);
                }
            }

            let entry = engine::va_to_off(bin, base, bin.entry).map(|off| (off / step).min(last));

            Ok(OverviewDto {
                size: size as u64,
                bucket_bytes: step as u64,
                buckets: out,
                entry,
            })
        })
        .map_err(|e| e.to_string())
}

/// Export the open function's CFG, or its call closure, as a Graphviz file.
///
/// Reports and advisories want a picture that outlives the window; .dot is the
/// one format every graph tool reads. Returns (kind, nodes, edges) for the
/// confirmation toast.
#[tauri::command]
pub fn export_dot(
    state: State<AppState>,
    kind: String,
    selector: String,
    dest: String,
) -> Result<(String, usize, usize), String> {
    state
        .read(|l| {
            let an = &l.session.an;
            let f =
                resolve(an, &selector).ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;
            let graph = match kind.as_str() {
                "cfg" => graphs::cfg(f),
                "calls" => {
                    let mut roots = std::collections::BTreeSet::new();
                    roots.insert(f.addr);
                    let g = graphs::call_graph(&an.functions, &an.imports, Some(&roots));
                    if g.nodes.len() > 96 {
                        return Err(anyhow!(
                            "the call closure from {} spans {} nodes; open a callee to trim it",
                            f.name,
                            g.nodes.len()
                        ));
                    }
                    g
                }
                _ => return Err(anyhow!("unknown graph kind {kind:?}")),
            };
            let counts = (graph.nodes.len(), graph.edges.len());
            let text = graphs::dot(&graph, &f.name);
            std::fs::write(&dest, text).map_err(|e| anyhow!(e))?;
            Ok((kind, counts.0, counts.1))
        })
        .map_err(|e| e.to_string())
}

/// Write the ranked findings to a markdown report.///
/// The same ranked list the attack-surface pane shows, in the order it shows
/// them (severity, then reachability), with each finding's own explanation —
/// what IDA/Ghidra never write down. Returns how many findings were written.
#[tauri::command]
pub fn export_findings(state: State<AppState>, dest: String) -> Result<usize, String> {
    state
        .read(|l| {
            let name = l
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| l.path.to_string_lossy().into_owned());
            let mut out = String::new();
            out.push_str(&format!("# knife findings — {name}\n\n"));
            if l.findings.is_empty() {
                out.push_str("No findings.\n");
            } else {
                out.push_str(&format!(
                    "{} finding{}, ranked by severity then reachability.\n\n",
                    l.findings.len(),
                    if l.findings.len() == 1 { "" } else { "s" }
                ));
            }
            for f in &l.findings {
                let grade = match f.severity {
                    3.. => "HIGH",
                    2 => "MED",
                    _ => "LOW",
                };
                let f = FindingDto::from(f);
                out.push_str(&format!(
                    "## [{}] {} — {} @ {}\n\n",
                    grade,
                    f.pattern,
                    f.api,
                    f.func.as_deref().unwrap_or("unknown function"),
                ));
                out.push_str(&format!("- address: `{}`\n", f.addr));
                out.push_str(&format!(
                    "- reachable from user input: {}\n",
                    if f.reachable { "yes" } else { "no" }
                ));
                if !f.source.is_empty() && f.source != "ARGUMENT" {
                    out.push_str(&format!("- argument source: {}\n", f.source));
                }
                out.push_str(&format!("\n{}\n\n", f.detail));
            }
            std::fs::write(&dest, out).map_err(|e| anyhow!(e))?;
            Ok(l.findings.len())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn binary_detail(state: State<AppState>) -> Result<serde_json::Value, String> {
    state
        .read(|l| Ok(l.detail.clone()))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_name(state: State<AppState>, addr: String, name: String) -> Result<(), String> {
    let at = parse_addr(&addr).map_err(|e| e.to_string())?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("a name cannot be empty".to_string());
    }
    if !db::valid_identifier(&name) {
        return Err(format!("{name:?} is not a valid identifier"));
    }
    state
        .edit(|s| {
            let base = engine::display_base(&s.bin);
            s.db.set_name(at.wrapping_sub(base), &name);
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_note(state: State<AppState>, addr: String, note: String) -> Result<(), String> {
    let at = parse_addr(&addr).map_err(|e| e.to_string())?;
    let note = note.trim().to_string();
    state
        .annotate(|s| {
            let base = engine::display_base(&s.bin);
            let at = at.wrapping_sub(base);
            // Saving an empty note is how you delete one. This used to be
            // refused, for want of a way to drop the note without dropping the
            // name beside it — `Db::clear_note` does exactly that.
            if note.is_empty() {
                s.db.clear_note(at);
            } else {
                s.db.set_note(at, &note);
            }
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn cfg(state: State<AppState>, selector: String) -> Result<CfgDto, String> {
    state
        .read(|l| {
            let an = &l.session.an;
            let f =
                resolve(an, &selector).ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;
            // The engine classifies the edges (true / false / flow, and which
            // ones point backwards into a loop); the block bodies come straight
            // off the function so a card can show real instructions.
            let graph = graphs::cfg(f);

            // The same lines the disassembly view shows, keyed by address. The
            // cards used to be filled with `i.text(..)`, which is the bare
            // instruction and nothing else — no resolved callee, no string
            // behind a pointer, no note of yours, and no target to click. All of
            // that is what makes a block readable, and `listing::function`
            // already works it out; there was no reason for the graph to be
            // shown less than the listing is.
            let mut body: std::collections::BTreeMap<u64, LineDto> =
                std::collections::BTreeMap::new();
            for line in
                listing::function(an, f, &l.session.db, l.base, &l.strings, l.hints.as_ref())
            {
                // `loc_` labels are dropped: the card's own header already says
                // where the block starts.
                if matches!(line, reknife::listing::Line::Insn { .. }) {
                    body.insert(line.addr(), LineDto::from(&line));
                }
            }

            let nodes = f
                .blocks
                .iter()
                .map(|b| CfgNode {
                    id: hex(b.start),
                    addr: hex(b.start),
                    kind: if b.start == f.addr { "entry" } else { "block" },
                    insns: b
                        .insns
                        .iter()
                        .map(|i| {
                            // A block is never left empty: if the listing had
                            // nothing for an address, the plain text still says
                            // what the instruction is.
                            body.remove(&i.addr).unwrap_or_else(|| {
                                let text = i.text(an.bits, an.arch);
                                let (mnemonic, operands) = match text.split_once(' ') {
                                    Some((m, r)) => (m.to_string(), r.to_string()),
                                    None => (text.clone(), String::new()),
                                };
                                LineDto::Insn {
                                    addr: hex(i.addr),
                                    mnemonic,
                                    operands,
                                    annot: None,
                                    target: None,
                                    seg: None,
                                }
                            })
                        })
                        .collect(),
                    count: b.insns.len(),
                    bytes: b.end.saturating_sub(b.start),
                })
                .collect();
            // `graphs` ids blocks its own way; re-key on the address so the
            // frontend has one id space.
            let index: std::collections::BTreeMap<&str, String> = graph
                .nodes
                .iter()
                .map(|n| (n.id.as_str(), hex(n.address)))
                .collect();
            let edges = graph
                .edges
                .iter()
                .filter_map(|e| {
                    Some(CfgEdge {
                        from: index.get(e.from.as_str())?.clone(),
                        to: index.get(e.to.as_str())?.clone(),
                        kind: e.kind,
                        back: e.back,
                    })
                })
                .collect();
            Ok(CfgDto {
                function: f.name.clone(),
                entry: hex(f.addr),
                nodes,
                edges,
            })
        })
        .map_err(|e| e.to_string())
}

/// The call closure of one function: everything it reaches, transitively.
///
/// Rooted at the resolved function, so the question "what can this IOCTL
/// handler actually call" gets one navigable picture. Imports appear as leaf
/// cards, internal functions open on double-click. A closure that would not
/// fit a readable picture is refused rather than drawn unreadable — open a
/// callee instead and its own closure is one click away.
#[tauri::command]
pub fn call_graph(
    state: State<AppState>,
    selector: String,
    max_nodes: Option<usize>,
) -> Result<CfgDto, String> {
    state
        .read(|l| {
            let an = &l.session.an;
            let f =
                resolve(an, &selector).ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;
            let cap = max_nodes.unwrap_or(96).max(8);
            let mut roots = std::collections::BTreeSet::new();
            roots.insert(f.addr);
            let graph = graphs::call_graph(&an.functions, &an.imports, Some(&roots));
            if graph.nodes.len() > cap {
                return Err(anyhow!(
                    "the call closure from {} spans {} nodes; open a callee to go deeper",
                    f.name,
                    graph.nodes.len()
                ));
            }
            // The frontend has one card model for both graphs: a function card
            // shows its name where a block showed instructions, and its size
            // where a block showed an instruction count.
            let by_addr: std::collections::BTreeMap<u64, &Function> =
                an.functions.iter().map(|x| (x.addr, x)).collect();
            // `graphs` ids nodes its own way; re-key on the address so the
            // frontend has one id space.
            let index: std::collections::BTreeMap<&str, String> = graph
                .nodes
                .iter()
                .map(|n| (n.id.as_str(), hex(n.address)))
                .collect();
            let nodes = graph
                .nodes
                .iter()
                .map(|n| CfgNode {
                    id: hex(n.address),
                    addr: hex(n.address),
                    kind: if n.address == f.addr { "entry" } else { n.kind },
                    // A call-graph card is a whole function, so its one line is
                    // the name rather than an instruction.
                    insns: vec![LineDto::Data {
                        addr: hex(n.address),
                        text: n.label.clone(),
                        seg: None,
                    }],
                    count: by_addr.get(&n.address).map(|x| x.blocks.len()).unwrap_or(0),
                    bytes: by_addr.get(&n.address).map(|x| x.size).unwrap_or(0),
                })
                .collect();
            let edges = graph
                .edges
                .iter()
                .filter_map(|e| {
                    Some(CfgEdge {
                        from: index.get(e.from.as_str())?.clone(),
                        to: index.get(e.to.as_str())?.clone(),
                        kind: "call",
                        back: e.back,
                    })
                })
                .collect();
            Ok(CfgDto {
                function: f.name.clone(),
                entry: hex(f.addr),
                nodes,
                edges,
            })
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn strings_list(
    state: State<AppState>,
    filter: Option<String>,
    referenced_only: Option<bool>,
    limit: Option<usize>,
) -> Result<Vec<StringRow>, String> {
    let needle = filter.unwrap_or_default().to_lowercase();
    let referenced_only = referenced_only.unwrap_or(false);
    let limit = limit.unwrap_or(5000);
    state
        .read(|l| {
            // `strings` is the literal map the listing already built, keyed by
            // the address code refers to the literal by.
            let rows = l
                .strings
                .iter()
                .filter(|(_, s)| needle.is_empty() || s.text.to_lowercase().contains(&needle))
                .map(|(addr, s)| {
                    let refs = l.session.an.xrefs_to.get(addr).map_or(0, Vec::len);
                    StringRow {
                        addr: hex(*addr),
                        text: s.text.clone(),
                        wide: s.wide,
                        len: s.len,
                        refs,
                    }
                })
                .filter(|r| !referenced_only || r.refs > 0)
                .take(limit)
                .collect();
            Ok(rows)
        })
        .map_err(|e| e.to_string())
}

/// The open targets, in tab order.
#[tauri::command]
pub fn list_targets(state: State<AppState>) -> Vec<TargetRow> {
    state.targets()
}

/// Show an already-open target.
#[tauri::command]
pub fn select_target(state: State<AppState>, path: String) -> Result<(), String> {
    state.select(&path).map_err(|e| e.to_string())
}

/// Close a target and free its analysis.
#[tauri::command]
pub fn close_target(state: State<AppState>, path: String) -> Result<(), String> {
    state.close(&path).map_err(|e| e.to_string())
}

/// One call chain that reaches a target.
#[derive(serde::Serialize)]
pub struct PathRow {
    /// Each hop, entry-most first.
    pub hops: Vec<PathHop>,
}

#[derive(serde::Serialize)]
pub struct PathHop {
    pub addr: String,
    pub name: String,
}

/// How control can reach a function from outside.
///
/// The roots are the places control enters the image: the entry point and every
/// export. This is the question a vulnerability is judged by — a dangerous call
/// nothing can reach is a curiosity, and one three hops from an export is a
/// finding — and it is why `reachable` appears on every audit finding.
#[tauri::command]
pub fn paths_to(
    state: State<AppState>,
    selector: String,
    max: Option<usize>,
) -> Result<Vec<PathRow>, String> {
    let max = max.unwrap_or(12).clamp(1, 64);
    state
        .read(|l| {
            let an = &l.session.an;
            let bin = &l.session.bin;
            let target = resolve(an, &selector)
                .map(|f| f.addr)
                .or_else(|| parse_addr(&selector).ok())
                .ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;

            let base = engine::display_base(bin);
            let mut roots: Vec<u64> = bin
                .symbols
                .iter()
                .filter(|s| s.kind == SymKind::Export)
                .map(|s| s.addr + base)
                .collect();
            roots.push(bin.entry + base);

            let mut chains = an.paths_to(target, &roots, max, false);
            chains.sort_by_key(|c| c.len());
            chains.truncate(max);

            Ok(chains
                .into_iter()
                .map(|c| PathRow {
                    hops: c
                        .into_iter()
                        .map(|a| PathHop {
                            addr: hex(a),
                            name: an.label(a),
                        })
                        .collect(),
                })
                .collect())
        })
        .map_err(|e| e.to_string())
}

/// One YARA rule that matched.
#[derive(serde::Serialize)]
pub struct YaraHit {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
    /// Pattern identifier and how many times it hit.
    pub patterns: Vec<(String, usize)>,
}

/// Load rules (a file or a directory) and rescan the open target.
///
/// The verdict is recomputed with the matches folded in, which is what
/// `knife info --rules` does; passing no path clears them and puts the score
/// back to the rule-free one.
#[tauri::command]
pub fn set_yara_rules(state: State<AppState>, path: Option<String>) -> Result<usize, String> {
    state
        .set_yara(path.as_deref())
        .map_err(|e| format!("{e:#}"))
}

/// The rules that matched, and what is currently loaded.
#[tauri::command]
pub fn yara_matches(state: State<AppState>) -> Result<(Option<String>, Vec<YaraHit>), String> {
    state
        .read(|l| {
            Ok((
                l.yara_rules.clone(),
                l.yara
                    .iter()
                    .map(|m| YaraHit {
                        rule: m.rule.clone(),
                        namespace: m.namespace.clone(),
                        tags: m.tags.clone(),
                        meta: m.meta.clone(),
                        patterns: m.patterns.clone(),
                    })
                    .collect(),
            ))
        })
        .map_err(|e| e.to_string())
}
