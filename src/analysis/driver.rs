//! Kernel-driver analysis (`knife drv`): the BYOVD pass.
//!
//! This turns the generic pipeline's output into the questions a driver audit
//! actually asks:
//!   - is this a native-subsystem kernel module at all, and what does it import?
//!   - what devices / symbolic links does it expose (and to whom)?
//!   - which IRP major functions does it dispatch, and where are the handlers?
//!   - what IOCTL codes can a user land in those handlers, and how are they
//!     buffered (METHOD_BUFFERED / DIRECT / NEITHER)?
//!   - which kernel primitives (physical-memory maps, arbitrary R/W, driver
//!     loaders, callbacks) are real, with call sites?
//!
//! The symbolic parts reuse `sinks` so the two halves of an audit agree; the
//! IRP/IOCTL recovery is a linear scan of the entry/handler functions because
//! those are store/cmp patterns, not control flow.

use crate::analysis::engine::{Analysis, Function};
use crate::analysis::sinks::{self, Site};
use crate::model::Binary;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A matching vulnerable/malicious-driver snapshot entry, as reported.
#[derive(Debug, Clone, Serialize)]
pub struct LolHit {
    pub file: String,
    pub vendor: String,
    pub product: String,
    pub category: String,
    pub signer: String,
    pub malicious: bool,
}

// CTL_CODE(DeviceType, Function, Method, Access):
//   31..16 DeviceType, 15..14 Access, 13..2 Function, 1..0 Method
fn decode_ctl(code: u32) -> (u32, u32, u32, u32) {
    let decoded = crate::windows::decode_ctl_code(code);
    (
        decoded.device_type,
        decoded.function,
        decoded.method.code(),
        decoded.access,
    )
}

fn method_name(m: u32) -> &'static str {
    match m {
        0 => "METHOD_BUFFERED",
        1 => "METHOD_IN_DIRECT",
        2 => "METHOD_OUT_DIRECT",
        _ => "METHOD_NEITHER",
    }
}

fn irp_name(major: u8) -> &'static str {
    crate::analysis::ktypes::irp(major as u64)
}

/// Transport-protocol display name for a dispatch handler.
fn dispatch_name(major: u8) -> &'static str {
    match major {
        0 => "DispatchCreate",
        2 => "DispatchClose",
        3 => "DispatchRead",
        4 => "DispatchWrite",
        14 => "DispatchDeviceControl",
        15 => "DispatchInternalDeviceControl",
        18 => "DispatchCleanup",
        16 => "DispatchShutdown",
        _ => "Dispatch",
    }
}

/// A `; MajorFunction[...] /* IRP_MJ_* */` listing hint, base-correct.
fn slot_hint(major: u8) -> String {
    format!("MajorFunction[{major}] /* {} */", irp_name(major))
}

/// Annotation for IOCTL parameter loads inside a device-control handler: the
/// `_IO_STACK_LOCATION.Parameters.DeviceIoControl` fields a handler actually
/// reads (`IoControlCode` at +0x10, `Type3InputBuffer` at +0x18, ...).
fn ioctl_param_hints(insns: &[(u64, iced_x86::Instruction)], out: &mut BTreeMap<u64, String>) {
    use iced_x86::OpKind;
    let fields = crate::analysis::ktypes::IO_STACK_LOCATION;
    for (ip, i) in insns.iter() {
        let (op, disp) = if i.op0_kind() == OpKind::Memory {
            (i.op1_kind(), i.memory_displacement64())
        } else if i.op1_kind() == OpKind::Memory {
            (i.op0_kind(), i.memory_displacement64())
        } else {
            continue;
        };
        if op == OpKind::Register && !matches!(i.mnemonic(), iced_x86::Mnemonic::Lea) {
            if let Some(fl) = crate::analysis::ktypes::field(fields, disp) {
                out.insert(*ip, fl.name.to_string());
            }
        }
    }
}

/// The functions reachable from `roots` through `call` edges (bounded by the
/// visited set, so huge drivers stay linear in reachable functions).
fn reachable_fns(an: &Analysis, roots: &[u64]) -> BTreeSet<u64> {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut stack: Vec<u64> = Vec::new();
    for r in roots {
        if seen.insert(*r) {
            stack.push(*r);
        }
    }
    while let Some(f) = stack.pop() {
        let calls: Vec<u64> = an
            .function_at(f)
            .map(|f| f.calls.clone())
            .unwrap_or_default();
        for c in calls {
            if seen.insert(c) {
                stack.push(c);
            }
        }
    }
    seen
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub name: String,
    pub addr: u64,
    pub wide: bool,
    pub xrefs: usize,
    /// True when a function that references this string also calls a
    /// device-creating API (IoCreateDevice / IoCreateSymbolicLink / ...).
    #[serde(default)]
    pub created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IrpHandler {
    pub major: u8,
    pub name: String,
    /// Transport-protocol display name: `DispatchDeviceControl` & friends.
    #[serde(default)]
    pub derived: String,
    pub addr: u64,
    /// Instruction that stores the handler pointer into `MajorFunction`.
    pub loader_addr: u64,
    /// Raw byte offset of the dispatch slot from the recovered DriverObject base.
    pub table_offset: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FastIoHandler {
    pub name: String,
    pub table_addr: u64,
    pub table_offset: u64,
    pub pointer_value: u64,
    pub target: Option<u64>,
    pub loader_addr: u64,
    pub reachability: crate::analysis::reachability::Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FastIoTableAssignment {
    pub table_addr: u64,
    pub loader_addr: u64,
    pub declared_size: Option<u32>,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ioctl {
    pub code: u32,
    pub device_type: u32,
    pub function: u32,
    pub method_code: u32,
    pub method: String,
    pub access: u32,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Primitive {
    pub api: String,
    pub class: String,
    pub severity: u8,
    pub sites: Vec<Site>,
    /// True when at least one call site sits in a function reachable from the
    /// entry point or an IRP dispatch handler, i.e. user mode can plausibly
    /// drive it.
    #[serde(default)]
    pub reachable: bool,
    /// Evidence-honest state for new clients. A false legacy boolean means
    /// unresolved here, not proof that indirect execution is impossible.
    #[serde(default)]
    pub reachability: crate::analysis::reachability::Reachability,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallbackRegistration {
    pub api: String,
    pub category: String,
    pub registration_site: u64,
    pub owner_function: Option<String>,
    pub callback_argument: Option<u8>,
    pub context_object: Option<u64>,
    pub target: Option<u64>,
    pub activations: Vec<CallbackActivation>,
    pub cancellations: Vec<CallbackCancellation>,
    pub registration_reachability: crate::analysis::reachability::Reachability,
    pub target_reachability: crate::analysis::reachability::Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallbackActivation {
    pub api: String,
    pub site: u64,
    pub owner_function: Option<String>,
    pub context_object: Option<u64>,
    pub owner_object: Option<u64>,
    pub ordering_confirmed: bool,
    pub reachability: crate::analysis::reachability::Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallbackCancellation {
    pub api: String,
    pub site: u64,
    pub owner_function: Option<String>,
    pub context_object: Option<u64>,
    pub owner_object: Option<u64>,
    /// True only when this call is in the same basic block after a matched
    /// activation. It does not prove cancellation succeeded or won a race.
    pub after_activation_confirmed: bool,
    pub reachability: crate::analysis::reachability::Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DriverReport {
    pub is_driver: bool,
    pub why: Vec<String>,
    pub module: String,
    pub entry: u64,
    pub entry_label: String,
    /// `DriverEntry` when this is a native driver, else the engine label.
    #[serde(default)]
    pub entry_name: String,
    pub bits: u32,
    pub subsystem: Option<String>,
    /// system kernel modules -> import count (ntoskrnl, hal, ndis, ...)
    pub kernel_imports: BTreeMap<String, usize>,
    /// every other imported module (application-layer names)
    pub app_imports: Vec<String>,
    pub devices: Vec<Device>,
    pub irp: Vec<IrpHandler>,
    #[serde(default)]
    pub fast_io: Vec<FastIoHandler>,
    #[serde(default)]
    pub fast_io_tables: Vec<FastIoTableAssignment>,
    pub ioctls: Vec<Ioctl>,
    pub primitives: Vec<Primitive>,
    #[serde(default)]
    pub callback_registrations: Vec<CallbackRegistration>,
    #[serde(default)]
    pub callback_activations: Vec<CallbackActivation>,
    #[serde(default)]
    pub callback_cancellations: Vec<CallbackCancellation>,
    /// Authenticode signing facts (subjects + thumbprints).
    pub signing: crate::analysis::signing::SigningSummary,
    /// Bundled known-vulnerable-driver matches (loldrivers snapshot).
    pub known_bad: Vec<LolHit>,
    /// Instruction-address -> `; field-name` annotations for the listing
    /// (dispatch-table stores, IOCTL parameter loads). Keyed by engine (VA).
    #[serde(default)]
    pub listing_hints: BTreeMap<u64, String>,
}

/// The kernel catalog, as a name set, so report primitives only from the
/// native-API half of the sink catalogue (user-mode sinks stay out of a
/// driver report).
fn kernel_api_set() -> BTreeSet<&'static str> {
    crate::analysis::ntapi::KERNEL_CATALOG
        .iter()
        .map(|d| d.api)
        .collect()
}

/// Whether the image links against the kernel executive.
///
/// This is the line between a driver and the kernel itself. A driver calls the
/// DDK routines — `IoCreateDevice`, `ObReferenceObject`, the rest — which live
/// in `ntoskrnl` and `hal`, so it imports them. The kernel image *exports* those
/// and imports only the layers beneath it (`bootvid`, `ci`, `kdcom`), so it
/// imports neither. `is_system_module` is too wide to tell them apart, because
/// it counts `ci` and `cng`, which the kernel does import.
fn imports_kernel(bin: &Binary) -> bool {
    bin.imports.iter().any(|lib| {
        let base = lib
            .name
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(&lib.name)
            .to_ascii_lowercase();
        matches!(
            base.as_str(),
            "ntoskrnl" | "ntkrnlmp" | "ntkrnlpa" | "ntkrnlpaex" | "hal"
        )
    })
}

/// Whether this looks like a kernel driver rather than some other native image.
///
/// A `.sys`/`.drv` is one on its name alone. Otherwise it takes both a native
/// subsystem and an actual link to the kernel — subsystem alone was flagging
/// the kernel itself (`ntoskrnl.exe`), the HAL, and native boot programs like
/// `smss.exe`, none of which are drivers and none of which have an IOCTL surface
/// to show.
pub fn plausibly_a_driver(bin: &Binary) -> bool {
    let ext_is_driver = std::path::Path::new(&bin.path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("sys") || e.eq_ignore_ascii_case("drv"));
    ext_is_driver || (bin.subsystem.as_deref() == Some("native") && imports_kernel(bin))
}

/// The `; field-name` listing hints for a driver: dispatch-slot stores and
/// IOCTL parameter-field loads. Lightweight (no sink walk, no reachability) so
/// plain `knife dis --func` and the MCP server can show the same type names
/// the interactive driver pane does without a whole driver audit.
pub fn listing_hints(bin: &Binary, bytes: &[u8], an: &Analysis) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    if bin.bits != 64 {
        return out;
    }
    let base = crate::analysis::engine::display_base(bin);
    let entry_va = bin.entry + base;
    let mut handlers: Vec<(u8, u64)> = Vec::new();
    if let Some(entry_fn) = an.function_at(entry_va) {
        let insns = decode_range(bin, bytes, entry_fn);
        for (store_ip, _, major, addr) in dispatch_table_stores(&insns) {
            out.insert(store_ip, slot_hint(major));
            handlers.push((major, addr));
        }
        // IOCTL parameter-field hints from each device-control handler.
        for (major, addr) in handlers {
            if major == 14 {
                if let Some(h) = an.function_at(addr) {
                    ioctl_param_hints(&decode_range(bin, bytes, h), &mut out);
                }
            }
        }
    }
    out
}

pub fn report(
    bin: &Binary,
    bytes: &[u8],
    an: &Analysis,
    strings: &BTreeMap<u64, crate::analysis::strings::Located>,
) -> DriverReport {
    let base = crate::analysis::engine::display_base(bin);
    let kernel = kernel_api_set();
    let all: BTreeSet<&str> = crate::analysis::sinks::CATALOG
        .iter()
        .chain(crate::analysis::ntapi::KERNEL_CATALOG.iter())
        .map(|d| d.api)
        .collect();

    // Keep the reasons in step with `plausibly_a_driver`: native subsystem is
    // only a reason when the image also links the kernel, or the kernel itself
    // reads as a driver here.
    let mut why = Vec::new();
    let ext = std::path::Path::new(&bin.path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if ext.eq_ignore_ascii_case("sys") || ext.eq_ignore_ascii_case("drv") {
        why.push(format!(".{ext} extension"));
    }
    if bin.subsystem.as_deref() == Some("native") && imports_kernel(bin) {
        why.push("native subsystem, imports the kernel".into());
    }
    let is_driver = !why.is_empty();
    // Still a driver, but the surface below cannot be read on this machine, and
    // an empty dispatch table should not be mistaken for a driver that has none.
    if is_driver && !crate::analysis::disasm::lifting_supported(bin.arch) {
        why.push(format!(
            "kernel surface not read: the dispatch and IOCTL decode is x86/x64 only, this is {}",
            bin.arch.label()
        ));
    }
    let module = std::path::Path::new(&bin.path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("?")
        .to_string();
    // All report addresses live in the engine's space (VA), matching `an`
    // lookups: the entry point and every string/key are based so they line up
    // with function headers and xref targets even when image_base is non-zero.
    let entry_va = bin.entry + base;
    let entry_label = an.label(entry_va);

    // Import surface: split system DLLs from app-layer names.
    let mut kernel_imports: BTreeMap<String, usize> = BTreeMap::new();
    let mut app_imports: Vec<String> = Vec::new();
    for lib in &bin.imports {
        let base = lib
            .name
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(&lib.name);
        if crate::analysis::ntapi::is_system_module(base) {
            *kernel_imports.entry(lib.name.clone()).or_default() += lib.functions.len();
        } else {
            app_imports.push(lib.name.clone());
        }
    }
    app_imports.sort();

    // Devices and symbolic links: the strings that name a surface, plus whether
    // anything in the image references them. The string map comes from the
    // caller (already built for the TUI / cmd_drv). Re-extracting it here was
    // a whole extra scan of the file for nothing.
    // A device is "created" when a function that references its name (or the
    // UNICODE_STRING struct that points at it, a few bytes below the payload)
    // also calls a device-creation API, so we can tell the exposed surface
    // from a string that merely happens to match.
    let create_slots: BTreeSet<u64> = an
        .imports
        .iter()
        .filter(|(_, full)| {
            let bare = crate::analysis::thunks::bare_name(full);
            matches!(
                bare,
                "IoCreateDevice"
                    | "IoCreateDeviceSecure"
                    | "IoCreateSymbolicLink"
                    | "IoRegisterDeviceInterface"
            )
        })
        .map(|(slot, _)| *slot)
        .collect();
    let create_callers: BTreeSet<u64> = create_slots
        .iter()
        .flat_map(|slot| {
            an.xrefs_to
                .get(slot)
                .map(|xs| {
                    xs.iter()
                        .filter(|x| x.kind == crate::analysis::engine::XrefKind::Call)
                        .filter_map(|x| an.function_at(x.from))
                        .map(|f| f.addr)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect();
    // A device is "created" when a function that references its name (or the
    // UNICODE_STRING struct that points at it, a few bytes below the payload)
    // also calls a device-creation API. Precompute the sorted target addresses
    // of those create calls once, and answer each device with a binary search,
    // so a file that embeds thousands of `\Device\` strings stays linear instead
    // of rescanning every call site per string.
    let create_calls: Vec<u64> = an
        .xrefs_from
        .iter()
        .filter(|(from, _)| {
            an.function_at(**from)
                .is_some_and(|f| create_callers.contains(&f.addr))
        })
        .flat_map(|(_, refs)| refs.iter().map(|r| r.to))
        .collect();
    let mut create_calls = create_calls;
    create_calls.sort_unstable();
    create_calls.dedup();
    let created_near = |va: u64| {
        let lo = va.saturating_sub(0x20);
        let hi = va.saturating_add(0x20);
        let first = create_calls.partition_point(|&t| t < lo);
        create_calls.get(first).is_some_and(|&t| t <= hi)
    };
    let mut devices: Vec<Device> = Vec::new();
    for (va, s) in strings {
        let trimmed = s.text.trim_end_matches('\0');
        if trimmed.starts_with("\\Device\\")
            || trimmed.starts_with("\\DosDevices\\")
            || trimmed.starts_with("\\??\\")
            || trimmed.starts_with("\\\\.\\")
        {
            let refs = an.xrefs_to.get(va).map(Vec::len).unwrap_or(0);
            devices.push(Device {
                name: trimmed.to_string(),
                addr: *va,
                wide: s.wide,
                xrefs: refs,
                created: created_near(*va),
            });
        }
    }
    devices.sort_by(|a, b| b.xrefs.cmp(&a.xrefs).then(a.addr.cmp(&b.addr)));

    // IRP dispatch + IOCTL recovery (linear scans of the relevant functions).
    // Only meaningful for native drivers, and 64-bit: the MajorFunction
    // offsets below are the x64 layouts.
    let mut irp: Vec<IrpHandler> = Vec::new();
    let mut fast_io: Vec<FastIoHandler> = Vec::new();
    let mut fast_io_tables: Vec<FastIoTableAssignment> = Vec::new();
    let mut ioctls: Vec<Ioctl> = Vec::new();
    let mut listing_hints: BTreeMap<u64, String> = BTreeMap::new();
    if is_driver && bin.bits == 64 {
        if let Some(entry_fn) = an.function_at(entry_va) {
            let insns = decode_range(bin, bytes, entry_fn);
            for (store_ip, table_offset, major, addr) in dispatch_table_stores(&insns) {
                irp.push(IrpHandler {
                    major,
                    name: irp_name(major).to_string(),
                    derived: dispatch_name(major).to_string(),
                    addr,
                    loader_addr: store_ip,
                    table_offset,
                });
                // `mov [obj+slot], handler` -> what the slot is (base-correct:
                // `major` was resolved against whichever x64 layout the stores
                // agreed on, so name the slot from the major directly).
                listing_hints.insert(store_ip, slot_hint(major));
            }
            let known_functions = an
                .functions
                .iter()
                .map(|function| function.addr)
                .collect::<BTreeSet<_>>();
            for (loader_addr, table_addr) in fast_io_table_assignments(&insns) {
                let declared_size = read_static_u32(bin, bytes, table_addr);
                fast_io_tables.push(FastIoTableAssignment {
                    table_addr,
                    loader_addr,
                    declared_size,
                    provenance: if declared_size.is_some() {
                        "STATIC_DRIVER_OBJECT_FAST_IO_TABLE_STORE"
                    } else {
                        "STATIC_FAST_IO_TABLE_BYTES_UNAVAILABLE"
                    }
                    .into(),
                });
                fast_io.extend(parse_fast_io_table(
                    bin,
                    bytes,
                    table_addr,
                    loader_addr,
                    &known_functions,
                ));
                listing_hints.insert(loader_addr, "FastIoDispatch".into());
            }
        }
        // ioctl codes + parameter-field hints from each device-control handler
        for h in &irp {
            if h.major == 14 {
                if let Some(f) = function_containing(an, h.addr) {
                    let insns = decode_range(bin, bytes, f);
                    for (addr, code) in ioctl_compares(&insns) {
                        let (device, function, method, access) = decode_ctl(code);
                        ioctls.push(Ioctl {
                            code,
                            device_type: device,
                            function,
                            method_code: method,
                            method: method_name(method).to_string(),
                            access,
                            addr,
                        });
                    }
                    ioctl_param_hints(&insns, &mut listing_hints);
                }
            }
        }
        irp.sort_by_key(|h| h.major);
        fast_io.sort_by_key(|handler| (handler.table_addr, handler.table_offset));
        fast_io_tables.sort_by_key(|table| (table.table_addr, table.loader_addr));
        ioctls.sort_by_key(|i| i.code);
    }

    // Primitives: kernel-catalog sinks, with call sites and reachability. The
    // sink walk + reachability BFS is the expensive part of a driver audit; a
    // non-driver (or a 32-bit one, where our dispatch recovery does not apply)
    // has no kernel surface worth walking.
    let primitives: Vec<Primitive> = if is_driver && bin.bits == 64 {
        let roots = std::iter::once(entry_va)
            .chain(irp.iter().map(|h| h.addr))
            .collect::<Vec<_>>();
        let reachable = reachable_fns(an, &roots);
        let mut primitives: Vec<Primitive> = sinks::find(an)
            .into_iter()
            .filter(|h| kernel.contains(h.api.as_str()))
            .map(|h| {
                let directly_reachable = h.sites.iter().any(|s| {
                    an.function_at(s.from)
                        .map(|f| reachable.contains(&f.addr))
                        .unwrap_or(false)
                });
                Primitive {
                    reachable: directly_reachable,
                    reachability: if directly_reachable {
                        crate::analysis::reachability::Reachability::ConfirmedDirect
                    } else {
                        crate::analysis::reachability::Reachability::Unresolved
                    },
                    api: h.api,
                    class: h.class.to_string(),
                    severity: h.severity,
                    sites: h.sites,
                }
            })
            .collect();
        primitives.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.api.cmp(&b.api)));
        primitives
    } else {
        Vec::new()
    };
    let CallbackRecovery {
        registrations: callback_registrations,
        activations: callback_activations,
        cancellations: callback_cancellations,
    } = recover_callback_registrations(an, &primitives);
    let _ = all;

    let signing = crate::analysis::signing::summarize(bin, bytes);
    let known_bad: Vec<LolHit> =
        crate::analysis::loldrivers::lookup(&crate::analysis::hashes::sha256_hex(bytes))
            .into_iter()
            .map(|e| LolHit {
                file: e.file.clone(),
                vendor: e.vendor.clone(),
                product: e.product.clone(),
                category: e.category.clone(),
                signer: e.signer.clone(),
                malicious: e.is_malicious(),
            })
            .collect();

    let entry_name = if is_driver {
        "DriverEntry".to_string()
    } else {
        entry_label.clone()
    };

    DriverReport {
        is_driver,
        why,
        module,
        entry: entry_va,
        entry_label,
        entry_name,
        bits: bin.bits,
        subsystem: bin.subsystem.clone(),
        kernel_imports,
        app_imports,
        devices,
        irp,
        fast_io,
        fast_io_tables,
        ioctls,
        primitives,
        callback_registrations,
        callback_activations,
        callback_cancellations,
        signing,
        known_bad,
        listing_hints,
    }
}

#[derive(Clone, Copy)]
struct CallbackSpec {
    argument: Option<u8>,
    category: &'static str,
    establishes_dispatch: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DpcActivationSpec {
    context_argument: u8,
    owner_argument: Option<u8>,
    provenance: &'static str,
}

fn dpc_activation_spec(api: &str) -> Option<DpcActivationSpec> {
    let (context_argument, owner_argument) = match api {
        "KeInsertQueueDpc" => (0, None),
        "KeSetTimer" => (2, Some(0)),
        "KeSetTimerEx" => (3, Some(0)),
        _ => return None,
    };
    Some(DpcActivationSpec {
        context_argument,
        owner_argument,
        provenance: "STATIC_DPC_ACTIVATION_ARGUMENT",
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DpcCancellationSpec {
    context_argument: Option<u8>,
    owner_argument: Option<u8>,
}

fn dpc_cancellation_spec(api: &str) -> Option<DpcCancellationSpec> {
    match api {
        "KeRemoveQueueDpc" => Some(DpcCancellationSpec {
            context_argument: Some(0),
            owner_argument: None,
        }),
        "KeCancelTimer" => Some(DpcCancellationSpec {
            context_argument: None,
            owner_argument: Some(0),
        }),
        _ => None,
    }
}

fn callback_spec(api: &str) -> CallbackSpec {
    let argument = match api {
        "PsSetCreateProcessNotifyRoutine"
        | "PsSetCreateProcessNotifyRoutineEx"
        | "PsSetCreateThreadNotifyRoutine"
        | "PsSetLoadImageNotifyRoutine"
        | "CmRegisterCallback"
        | "CmRegisterCallbackEx" => Some(0),
        "IoRegisterBootDriverReinitialization"
        | "IoRegisterDriverReinitialization"
        | "IoQueueWorkItem"
        | "KeInitializeDpc" => Some(1),
        "IoSetCompletionRoutineEx" => Some(2),
        _ => Option::None,
    };
    let category = match api {
        "IoSetCompletionRoutineEx" => "IRP_COMPLETION",
        "IoQueueWorkItem" => "WORK_ITEM",
        "KeInitializeDpc" => "DPC",
        "ObRegisterCallbacks" => "OBJECT_CALLBACK_STRUCTURE",
        _ => "KERNEL_CALLBACK_REGISTRATION",
    };
    // KeInitializeDpc only stores the routine. Execution additionally needs a
    // activation such as queueing the DPC or arming its timer, which this edge has not proven.
    let establishes_dispatch = argument.is_some() && api != "KeInitializeDpc";
    CallbackSpec {
        argument,
        category,
        establishes_dispatch,
    }
}

fn abi_register(argument: u8) -> Option<iced_x86::Register> {
    use iced_x86::Register;
    [Register::RCX, Register::RDX, Register::R8, Register::R9]
        .get(argument as usize)
        .copied()
}

fn canonical_argument_register(register: iced_x86::Register) -> Option<iced_x86::Register> {
    use iced_x86::Register::*;
    match register {
        RCX | ECX | CX | CL | CH => Some(RCX),
        RDX | EDX | DX | DL | DH => Some(RDX),
        R8 | R8D | R8W | R8L => Some(R8),
        R9 | R9D | R9W | R9L => Some(R9),
        _ => Option::None,
    }
}

fn immediate_value(instruction: &iced_x86::Instruction) -> Option<u64> {
    use iced_x86::OpKind;
    match instruction.op1_kind() {
        OpKind::Immediate64 => Some(instruction.immediate64()),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(instruction.immediate32() as u64),
        _ => None,
    }
}

fn recover_literal_argument(function: &Function, call_site: u64, argument: u8) -> Option<u64> {
    use iced_x86::{
        Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
        Register,
    };
    let wanted = abi_register(argument)?;
    let block = function
        .blocks
        .iter()
        .find(|block| block.insns.iter().any(|insn| insn.addr == call_site))?;
    let mut values: BTreeMap<Register, u64> = BTreeMap::new();
    let mut info_factory = InstructionInfoFactory::new();
    for raw in &block.insns {
        if raw.addr == call_site {
            return values.get(&wanted).copied();
        }
        let mut decoder = Decoder::with_ip(64, raw.bytes(), raw.addr, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            values.clear();
            continue;
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            values.clear();
            continue;
        }
        let destination = (instruction.op0_kind() == OpKind::Register)
            .then(|| canonical_argument_register(instruction.op0_register()))
            .flatten();
        let replacement = destination.and_then(|destination| {
            let value = match instruction.mnemonic() {
                Mnemonic::Lea
                    if instruction.op1_kind() == OpKind::Memory
                        && instruction.memory_base() == Register::RIP
                        && instruction.is_ip_rel_memory_operand() =>
                {
                    Some(instruction.memory_displacement64())
                }
                Mnemonic::Mov if instruction.op1_kind() == OpKind::Register => {
                    canonical_argument_register(instruction.op1_register())
                        .and_then(|source| values.get(&source).copied())
                }
                Mnemonic::Mov => immediate_value(&instruction),
                _ => Option::None,
            };
            value.map(|value| (destination, value))
        });
        for used in info_factory.info(&instruction).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                if let Some(register) = canonical_argument_register(used.register()) {
                    values.remove(&register);
                }
            }
        }
        if let Some((destination, value)) = replacement {
            values.insert(destination, value);
        }
    }
    None
}

fn recover_callback_target(
    function: &Function,
    registration_site: u64,
    argument: u8,
    known_functions: &BTreeSet<u64>,
) -> Option<u64> {
    recover_literal_argument(function, registration_site, argument)
        .filter(|target| known_functions.contains(target))
}

fn matching_dpc_activations(
    context_object: Option<u64>,
    candidates: &[CallbackActivation],
) -> Vec<CallbackActivation> {
    let Some(context_object) = context_object else {
        return Vec::new();
    };
    candidates
        .iter()
        .filter(|activation| activation.context_object == Some(context_object))
        .cloned()
        .collect()
}

fn matching_dpc_cancellations(
    context_object: Option<u64>,
    activations: &[CallbackActivation],
    candidates: &[CallbackCancellation],
) -> Vec<CallbackCancellation> {
    let Some(context_object) = context_object else {
        return Vec::new();
    };
    candidates
        .iter()
        .filter(|cancellation| {
            cancellation.context_object == Some(context_object)
                || cancellation.owner_object.is_some_and(|owner_object| {
                    activations
                        .iter()
                        .any(|activation| activation.owner_object == Some(owner_object))
                })
        })
        .cloned()
        .collect()
}

fn function_has_basic_block_order(function: &Function, before: u64, after: u64) -> bool {
    function.blocks.iter().any(|block| {
        let before_index = block
            .insns
            .iter()
            .position(|instruction| instruction.addr == before);
        let after_index = block
            .insns
            .iter()
            .position(|instruction| instruction.addr == after);
        matches!((before_index, after_index), (Some(before), Some(after)) if before < after)
    })
}

fn same_basic_block_order(analysis: &Analysis, before: u64, after: u64) -> bool {
    let Some(function) = analysis.function_at(before) else {
        return false;
    };
    analysis.function_at(after).map(|candidate| candidate.addr) == Some(function.addr)
        && function_has_basic_block_order(function, before, after)
}

fn callback_target_reachability(
    target: Option<u64>,
    spec: CallbackSpec,
    registration_reachability: crate::analysis::reachability::Reachability,
    activations: &[CallbackActivation],
) -> crate::analysis::reachability::Reachability {
    let activated = activations
        .iter()
        .any(|activation| activation.reachability.is_confirmed() && activation.ordering_confirmed);
    if target.is_some()
        && registration_reachability.is_confirmed()
        && (spec.establishes_dispatch || activated)
    {
        crate::analysis::reachability::Reachability::ConfirmedIndirect
    } else {
        crate::analysis::reachability::Reachability::Unresolved
    }
}

fn downgrade_ambiguous_dpc_reinitializations(registrations: &mut [CallbackRegistration]) {
    let mut counts = BTreeMap::<u64, usize>::new();
    for registration in registrations.iter() {
        if registration.api == "KeInitializeDpc" {
            if let Some(context_object) = registration.context_object {
                *counts.entry(context_object).or_default() += 1;
            }
        }
    }
    for registration in registrations.iter_mut() {
        let ambiguous = registration
            .context_object
            .and_then(|context_object| counts.get(&context_object))
            .is_some_and(|count| *count > 1);
        if registration.api == "KeInitializeDpc" && ambiguous {
            registration.target_reachability =
                crate::analysis::reachability::Reachability::Unresolved;
            registration.provenance = "DPC_OBJECT_REINITIALIZATION_AMBIGUOUS".into();
        }
    }
}

struct CallbackRecovery {
    registrations: Vec<CallbackRegistration>,
    activations: Vec<CallbackActivation>,
    cancellations: Vec<CallbackCancellation>,
}

fn recover_callback_registrations(
    analysis: &Analysis,
    primitives: &[Primitive],
) -> CallbackRecovery {
    let known_functions = analysis
        .functions
        .iter()
        .map(|function| function.addr)
        .collect::<BTreeSet<_>>();
    let dpc_activation_candidates = primitives
        .iter()
        .filter_map(|primitive| dpc_activation_spec(&primitive.api).map(|spec| (primitive, spec)))
        .flat_map(|(primitive, activation_spec)| {
            primitive.sites.iter().map(move |site| CallbackActivation {
                api: primitive.api.clone(),
                site: site.from,
                owner_function: site.in_func.clone(),
                context_object: analysis.function_at(site.from).and_then(|function| {
                    recover_literal_argument(function, site.from, activation_spec.context_argument)
                }),
                owner_object: activation_spec.owner_argument.and_then(|argument| {
                    analysis.function_at(site.from).and_then(|function| {
                        recover_literal_argument(function, site.from, argument)
                    })
                }),
                ordering_confirmed: false,
                reachability: primitive.reachability,
                provenance: activation_spec.provenance.into(),
            })
        })
        .collect::<Vec<_>>();
    let dpc_cancellation_candidates = primitives
        .iter()
        .filter_map(|primitive| dpc_cancellation_spec(&primitive.api).map(|spec| (primitive, spec)))
        .flat_map(|(primitive, cancellation_spec)| {
            primitive
                .sites
                .iter()
                .map(move |site| CallbackCancellation {
                    api: primitive.api.clone(),
                    site: site.from,
                    owner_function: site.in_func.clone(),
                    context_object: cancellation_spec.context_argument.and_then(|argument| {
                        analysis.function_at(site.from).and_then(|function| {
                            recover_literal_argument(function, site.from, argument)
                        })
                    }),
                    owner_object: cancellation_spec.owner_argument.and_then(|argument| {
                        analysis.function_at(site.from).and_then(|function| {
                            recover_literal_argument(function, site.from, argument)
                        })
                    }),
                    after_activation_confirmed: false,
                    reachability: primitive.reachability,
                    provenance: "STATIC_DPC_CANCELLATION_ARGUMENT_RESULT_UNKNOWN".into(),
                })
        })
        .collect::<Vec<_>>();
    let mut registrations = primitives
        .iter()
        .filter(|primitive| primitive.class == "callback")
        .flat_map(|primitive| {
            let spec = callback_spec(&primitive.api);
            let known_functions = &known_functions;
            let dpc_activation_candidates = &dpc_activation_candidates;
            let dpc_cancellation_candidates = &dpc_cancellation_candidates;
            primitive.sites.iter().map(move |site| {
                let target = spec.argument.and_then(|argument| {
                    analysis.function_at(site.from).and_then(|function| {
                        recover_callback_target(function, site.from, argument, known_functions)
                    })
                });
                let context_object = (primitive.api == "KeInitializeDpc")
                    .then(|| {
                        analysis
                            .function_at(site.from)
                            .and_then(|function| recover_literal_argument(function, site.from, 0))
                    })
                    .flatten();
                let activations = if primitive.api == "KeInitializeDpc" {
                    matching_dpc_activations(context_object, dpc_activation_candidates)
                        .into_iter()
                        .map(|mut activation| {
                            activation.ordering_confirmed =
                                same_basic_block_order(analysis, site.from, activation.site);
                            if activation.ordering_confirmed {
                                activation.provenance =
                                    "STATIC_DPC_ACTIVATION_ARGUMENT_SAME_BLOCK_AFTER_INITIALIZATION"
                                        .into();
                            }
                            activation
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let matched_reachable_activation = activations.iter().any(|activation| {
                    activation.reachability.is_confirmed() && activation.ordering_confirmed
                });
                let cancellations = if primitive.api == "KeInitializeDpc" {
                    matching_dpc_cancellations(
                        context_object,
                        &activations,
                        dpc_cancellation_candidates,
                    )
                        .into_iter()
                        .map(|mut cancellation| {
                            let owner_linked = cancellation.owner_object.is_some_and(
                                |owner_object| {
                                    activations.iter().any(|activation| {
                                        activation.owner_object == Some(owner_object)
                                    })
                                },
                            );
                            cancellation.after_activation_confirmed = activations.iter().any(|activation| {
                                let same_lifecycle = cancellation.context_object == context_object
                                    || cancellation.owner_object.is_some_and(|owner_object| {
                                        activation.owner_object == Some(owner_object)
                                    });
                                same_lifecycle
                                    &&
                                    same_basic_block_order(
                                        analysis,
                                        activation.site,
                                        cancellation.site,
                                    )
                            });
                            if cancellation.after_activation_confirmed {
                                cancellation.provenance = if owner_linked {
                                    "STATIC_TIMER_OWNER_LINK_SAME_BLOCK_AFTER_ACTIVATION_RESULT_UNKNOWN"
                                } else {
                                    "STATIC_DPC_CANCELLATION_ARGUMENT_SAME_BLOCK_AFTER_ACTIVATION_RESULT_UNKNOWN"
                                }
                                .into();
                            } else if owner_linked {
                                cancellation.provenance =
                                    "STATIC_TIMER_OWNER_LINK_RESULT_UNKNOWN".into();
                            }
                            cancellation
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let target_reachability = callback_target_reachability(
                    target,
                    spec,
                    primitive.reachability,
                    &activations,
                );
                CallbackRegistration {
                    api: primitive.api.clone(),
                    category: spec.category.into(),
                    registration_site: site.from,
                    owner_function: site.in_func.clone(),
                    callback_argument: spec.argument,
                    context_object,
                    target,
                    activations,
                    cancellations,
                    registration_reachability: primitive.reachability,
                    target_reachability,
                    provenance: if target.is_some() && matched_reachable_activation {
                        "DIRECT_ARGUMENT_STATIC_FUNCTION_AND_MATCHED_DPC_ACTIVATION_OBJECT"
                    } else if target.is_some() {
                        "DIRECT_ARGUMENT_STATIC_FUNCTION"
                    } else if spec.argument.is_none() {
                        "STRUCTURE_BACKED_TARGET_UNRESOLVED"
                    } else {
                        "STATIC_REGISTRATION_CALL_TARGET_UNRESOLVED"
                    }
                    .into(),
                }
            })
        })
        .collect::<Vec<_>>();
    downgrade_ambiguous_dpc_reinitializations(&mut registrations);
    CallbackRecovery {
        registrations,
        activations: dpc_activation_candidates,
        cancellations: dpc_cancellation_candidates,
    }
}

fn function_containing(an: &Analysis, addr: u64) -> Option<&Function> {
    an.function_at(addr)
}

/// Decode a function's whole byte range into (ip, instruction) pairs.
fn decode_range(bin: &Binary, bytes: &[u8], f: &Function) -> Vec<(u64, iced_x86::Instruction)> {
    let start = f.addr;
    let end = f
        .blocks
        .iter()
        .map(|b| b.end)
        .max()
        .unwrap_or(start + f.size);
    // Every read below this point is an x86 decode. On another architecture it
    // would not fail, it would succeed on the wrong instruction set and report a
    // dispatch table and IOCTL codes that were never there. Nothing is the
    // truthful answer; the report says why.
    if !crate::analysis::disasm::lifting_supported(bin.arch) {
        return Vec::new();
    }
    let base = crate::analysis::engine::display_base(bin);
    let Some(off) = crate::analysis::engine::va_to_off(bin, base, start) else {
        return Vec::new();
    };
    let len = end.saturating_sub(start) as usize;
    let code = &bytes[off..off.saturating_add(len).min(bytes.len())];
    let mut dec = iced_x86::Decoder::with_ip(64, code, start, iced_x86::DecoderOptions::NONE);
    let mut out = Vec::new();
    while dec.can_decode() {
        let insn = dec.decode();
        out.push((insn.ip(), insn));
    }
    out
}

/// Find `DriverObject->MajorFunction[i] = handler` stores in DriverEntry.
///
/// Pattern: the entry function does `lea rN, [rip+handler]` then
/// `mov [rX + 0x70 + 8*i], rN` where rX holds DriverObject (rcx on entry, or a
/// register it was copied into). Returns (major, handler-address) pairs. This
/// is a heuristic: it only fires on the store shape, never invents handlers.
/// Returns one `(store_ip, table_offset, major, handler-addr)` per recovered slot store.
fn driver_object_pointer_stores(insns: &[(u64, iced_x86::Instruction)]) -> Vec<(u64, u64, u64)> {
    use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
    let mut cands: Vec<(u64, u64, u64)> = Vec::new();
    let mut reg_value: BTreeMap<Register, u64> = BTreeMap::new();
    let mut obj_regs: BTreeSet<Register> = BTreeSet::from([Register::RCX]);
    let mut info_factory = InstructionInfoFactory::new();
    for (ip, i) in insns.iter() {
        // Consume the pre-instruction state for a pointer store. The store does
        // not change its source/base registers, so invalidation happens below.
        if i.mnemonic() == Mnemonic::Mov
            && i.op0_kind() == OpKind::Memory
            && i.op1_kind() == OpKind::Register
        {
            let base = i.memory_base().full_register();
            let source = i.op1_register().full_register();
            if base != Register::None && obj_regs.contains(&base) {
                if let Some(value) = reg_value.get(&source).copied() {
                    cands.push((*ip, i.memory_displacement64(), value));
                }
            }
        }

        // Compute replacement facts from the old state before removing every
        // register the instruction writes (including implicit/secondary writes).
        let destination =
            (i.op0_kind() == OpKind::Register).then(|| i.op0_register().full_register());
        let new_value = destination.and_then(|destination| {
            let value = if i.mnemonic() == Mnemonic::Lea
                && i.op1_kind() == OpKind::Memory
                && i.memory_base() == Register::RIP
                && i.is_ip_rel_memory_operand()
            {
                Some(i.memory_displacement64())
            } else if i.mnemonic() == Mnemonic::Mov && i.op1_kind() == OpKind::Register {
                reg_value.get(&i.op1_register().full_register()).copied()
            } else {
                immediate_value(i).filter(|_| i.mnemonic() == Mnemonic::Mov)
            };
            value.map(|value| (destination, value))
        });
        let new_object = destination.filter(|_| {
            i.mnemonic() == Mnemonic::Mov
                && i.op1_kind() == OpKind::Register
                && obj_regs.contains(&i.op1_register().full_register())
        });

        for used in info_factory.info(i).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                let register = used.register().full_register();
                reg_value.remove(&register);
                obj_regs.remove(&register);
            }
        }
        if matches!(
            i.flow_control(),
            iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall
        ) {
            for register in [
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ] {
                reg_value.remove(&register);
                obj_regs.remove(&register);
            }
        } else if matches!(
            i.flow_control(),
            iced_x86::FlowControl::UnconditionalBranch
                | iced_x86::FlowControl::IndirectBranch
                | iced_x86::FlowControl::ConditionalBranch
                | iced_x86::FlowControl::Return
        ) {
            reg_value.clear();
            obj_regs.clear();
        }
        if let Some((register, value)) = new_value {
            reg_value.insert(register, value);
        }
        if let Some(register) = new_object {
            obj_regs.insert(register);
        }
    }
    cands
}

fn dispatch_table_stores(insns: &[(u64, iced_x86::Instruction)]) -> Vec<(u64, u64, u8, u64)> {
    let bases = crate::analysis::ktypes::MAJOR_BASES;
    let cands = driver_object_pointer_stores(insns);
    // Pick the table base the stores actually agree on; ties go to the newer
    // layout so modern drivers win.
    let best = *bases
        .iter()
        .max_by_key(|&&b| {
            cands
                .iter()
                .filter(|(_, d, _)| (b..b + 8 * 28).contains(d))
                .count()
        })
        .unwrap_or(&bases[0]);
    let mut out: Vec<(u64, u64, u8, u64)> = Vec::new();
    for (ip, disp, value) in cands {
        if (best..best + 8 * 28).contains(&disp) {
            let major = ((disp - best) / 8) as u8;
            if major < 28 {
                out.push((ip, disp, major, value));
            }
        }
    }
    out
}

fn fast_io_table_assignments(insns: &[(u64, iced_x86::Instruction)]) -> Vec<(u64, u64)> {
    driver_object_pointer_stores(insns)
        .into_iter()
        .filter(|(_, offset, _)| *offset == crate::analysis::ktypes::FAST_IO_DISPATCH_OFFSET)
        .map(|(loader, _, table)| (loader, table))
        .collect()
}

const FAST_IO_SLOTS: &[(u64, &str)] = &[
    (0x08, "FastIoCheckIfPossible"),
    (0x10, "FastIoRead"),
    (0x18, "FastIoWrite"),
    (0x20, "FastIoQueryBasicInfo"),
    (0x28, "FastIoQueryStandardInfo"),
    (0x30, "FastIoLock"),
    (0x38, "FastIoUnlockSingle"),
    (0x40, "FastIoUnlockAll"),
    (0x48, "FastIoUnlockAllByKey"),
    (0x50, "FastIoDeviceControl"),
    (0x58, "AcquireFileForNtCreateSection"),
    (0x60, "ReleaseFileForNtCreateSection"),
    (0x68, "FastIoDetachDevice"),
    (0x70, "FastIoQueryNetworkOpenInfo"),
    (0x78, "AcquireForModWrite"),
    (0x80, "MdlRead"),
    (0x88, "MdlReadComplete"),
    (0x90, "PrepareMdlWrite"),
    (0x98, "MdlWriteComplete"),
    (0xa0, "FastIoReadCompressed"),
    (0xa8, "FastIoWriteCompressed"),
    (0xb0, "MdlReadCompleteCompressed"),
    (0xb8, "MdlWriteCompleteCompressed"),
    (0xc0, "FastIoQueryOpen"),
    (0xc8, "ReleaseForModWrite"),
    (0xd0, "AcquireForCcFlush"),
    (0xd8, "ReleaseForCcFlush"),
];

fn read_static_u64(bin: &Binary, bytes: &[u8], address: u64) -> Option<u64> {
    let base = crate::analysis::engine::display_base(bin);
    let offset = crate::analysis::engine::va_to_off(bin, base, address)?;
    let raw: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

fn read_static_u32(bin: &Binary, bytes: &[u8], address: u64) -> Option<u32> {
    let base = crate::analysis::engine::display_base(bin);
    let offset = crate::analysis::engine::va_to_off(bin, base, address)?;
    let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn parse_fast_io_table(
    bin: &Binary,
    bytes: &[u8],
    table_addr: u64,
    loader_addr: u64,
    known_functions: &BTreeSet<u64>,
) -> Vec<FastIoHandler> {
    let Some(declared_size) = read_static_u32(bin, bytes, table_addr).map(u64::from) else {
        return Vec::new();
    };
    if !(8..=0x1000).contains(&declared_size) {
        return Vec::new();
    }
    FAST_IO_SLOTS
        .iter()
        .filter(|(offset, _)| offset.saturating_add(8) <= declared_size)
        .filter_map(|(offset, name)| {
            let pointer_value = read_static_u64(bin, bytes, table_addr.checked_add(*offset)?)?;
            if pointer_value == 0 {
                return None;
            }
            let target = known_functions
                .contains(&pointer_value)
                .then_some(pointer_value);
            Some(FastIoHandler {
                name: (*name).into(),
                table_addr,
                table_offset: *offset,
                pointer_value,
                target,
                loader_addr,
                reachability: if target.is_some() {
                    crate::analysis::reachability::Reachability::ConfirmedIndirect
                } else {
                    crate::analysis::reachability::Reachability::Unresolved
                },
                provenance: if target.is_some() {
                    "STATIC_FAST_IO_TABLE_POINTER"
                } else {
                    "STATIC_FAST_IO_POINTER_TARGET_UNRESOLVED"
                }
                .into(),
            })
        })
        .collect()
}

/// Recover literal IOCTL constant compares inside a handler
/// (`cmp reg, imm32` / `cmp [mem], imm32`), decoded via CTL_CODE.
fn ioctl_compares(insns: &[(u64, iced_x86::Instruction)]) -> Vec<(u64, u32)> {
    use iced_x86::{Mnemonic, OpKind};
    let mut out = Vec::new();
    for (ip, i) in insns.iter() {
        if i.mnemonic() == Mnemonic::Cmp {
            let code = match (i.op0_kind(), i.op1_kind()) {
                (OpKind::Register, OpKind::Immediate32) | (OpKind::Memory, OpKind::Immediate32) => {
                    i.immediate32()
                }
                _ => continue,
            };
            if code >= 0x10000 {
                out.push((*ip, code));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::engine;
    use crate::db::Db;
    use crate::formats::fixture;

    fn drive(bin_bytes: Vec<u8>) -> (Binary, Vec<u8>, Analysis) {
        let bin = crate::formats::analyze("fixture.sys", &bin_bytes).unwrap();
        let an = engine::analyze(&bin, &bin_bytes, 200_000, &Db::default());
        (bin, bin_bytes, an)
    }

    fn string_map_for(
        bin: &Binary,
        bytes: &[u8],
    ) -> BTreeMap<u64, crate::analysis::strings::Located> {
        crate::listing::string_map(bin, bytes, crate::analysis::engine::display_base(bin))
    }

    fn native(path: &str, imports: &[&str]) -> Binary {
        let mut bin = Binary::stub(crate::model::Format::Pe, crate::model::Arch::X86_64);
        bin.path = path.into();
        bin.subsystem = Some("native".into());
        bin.imports = imports
            .iter()
            .map(|name| crate::model::ImportedLib {
                name: (*name).into(),
                functions: vec!["Fn".into()],
                ordinals: vec![None],
            })
            .collect();
        bin
    }

    #[test]
    fn decode_range_maps_based_pe_static_addresses() {
        use crate::analysis::engine::{BasicBlock, EngineInsn};
        use crate::model::Section;
        use iced_x86::FlowControl;
        let mut bin = Binary::stub(crate::model::Format::Pe, crate::model::Arch::X86_64);
        bin.image_base = 0x140000000;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr: 0x1000,
            vsize: 1,
            file_off: 0,
            file_size: 1,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let function = Function {
            addr: 0x140001000,
            name: "DriverEntry".into(),
            blocks: vec![BasicBlock {
                start: 0x140001000,
                end: 0x140001001,
                insns: vec![EngineInsn::new(
                    0x140001000,
                    &[0xc3],
                    FlowControl::Return,
                    None,
                    None,
                )],
                succ: Vec::new(),
            }],
            size: 1,
            incoming: 0,
            calls: Vec::new(),
            named: true,
            tables: Vec::new(),
        };
        let decoded = decode_range(&bin, &[0xc3], &function);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, 0x140001000);
        assert_eq!(decoded[0].1.mnemonic(), iced_x86::Mnemonic::Ret);
    }

    #[test]
    fn fast_io_assignment_is_not_misclassified_as_major_function_zero() {
        let code = [
            0x48, 0x8d, 0x05, 0xf9, 0x0f, 0, 0, // lea rax,[rip+0xff9] -> 0x2000
            0x48, 0x89, 0x41, 0x50, // mov [rcx+0x50],rax
        ];
        let mut decoder =
            iced_x86::Decoder::with_ip(64, &code, 0x1000, iced_x86::DecoderOptions::NONE);
        let insns = [decoder.decode(), decoder.decode()]
            .into_iter()
            .map(|instruction| (instruction.ip(), instruction))
            .collect::<Vec<_>>();
        assert_eq!(fast_io_table_assignments(&insns), vec![(0x1007, 0x2000)]);
        assert!(dispatch_table_stores(&insns).is_empty());
    }

    #[test]
    fn overwritten_table_or_driver_object_register_does_not_invent_fast_io_edge() {
        fn decode(code: &[u8]) -> Vec<(u64, iced_x86::Instruction)> {
            let mut decoder =
                iced_x86::Decoder::with_ip(64, code, 0x1000, iced_x86::DecoderOptions::NONE);
            let mut out = Vec::new();
            while decoder.can_decode() {
                let instruction = decoder.decode();
                out.push((instruction.ip(), instruction));
            }
            out
        }
        let stale_table = decode(&[
            0x48, 0x8d, 0x05, 0xf9, 0x0f, 0, 0, // lea rax,[0x2000]
            0x31, 0xc0, // xor eax,eax
            0x48, 0x89, 0x41, 0x50, // mov [rcx+0x50],rax
        ]);
        assert!(fast_io_table_assignments(&stale_table).is_empty());

        let stale_object = decode(&[
            0x48, 0x89, 0xcb, // mov rbx,rcx
            0x31, 0xdb, // xor ebx,ebx
            0x48, 0x8d, 0x05, 0xf4, 0x0f, 0, 0, // lea rax,[0x2000]
            0x48, 0x89, 0x43, 0x50, // mov [rbx+0x50],rax
        ]);
        assert!(fast_io_table_assignments(&stale_object).is_empty());

        let stale_across_call = decode(&[
            0x48, 0x89, 0xcb, // mov rbx,rcx (nonvolatile DriverObject)
            0x48, 0x8d, 0x05, 0xf6, 0x0f, 0, 0, // lea rax,[0x2000]
            0xff, 0x15, 0, 0, 0, 0, // call [rip] clobbers volatile rax
            0x48, 0x89, 0x43, 0x50, // mov [rbx+0x50],rax
        ]);
        assert!(fast_io_table_assignments(&stale_across_call).is_empty());
    }

    #[test]
    fn fast_io_slots_preserve_unknown_nonzero_pointer_values() {
        use crate::model::Section;
        let mut bin = Binary::stub(crate::model::Format::Pe, crate::model::Arch::X86_64);
        bin.image_base = 0x140000000;
        bin.sections = vec![Section {
            name: ".rdata".into(),
            vaddr: 0x2000,
            vsize: 0xe0,
            file_off: 0,
            file_size: 0xe0,
            entropy: 0.0,
            read: true,
            write: false,
            exec: false,
        }];
        let mut bytes = vec![0u8; 0xe0];
        bytes[0..4].copy_from_slice(&0xe0u32.to_le_bytes());
        bytes[0x10..0x18].copy_from_slice(&0x140003000u64.to_le_bytes());
        bytes[0x18..0x20].copy_from_slice(&0xfffff80012345678u64.to_le_bytes());
        let handlers = parse_fast_io_table(
            &bin,
            &bytes,
            0x140002000,
            0x140001020,
            &BTreeSet::from([0x140003000]),
        );
        assert_eq!(handlers.len(), 2, "zero FastIoCheckIfPossible is absent");
        assert_eq!(handlers[0].name, "FastIoRead");
        assert_eq!(handlers[0].target, Some(0x140003000));
        assert_eq!(
            handlers[0].reachability,
            crate::analysis::reachability::Reachability::ConfirmedIndirect
        );
        assert_eq!(handlers[1].name, "FastIoWrite");
        assert_eq!(handlers[1].pointer_value, 0xfffff80012345678);
        assert_eq!(handlers[1].target, None);
        assert_eq!(
            handlers[1].reachability,
            crate::analysis::reachability::Reachability::Unresolved
        );
    }

    fn callback_setup(intervening_call: bool) -> Function {
        use crate::analysis::engine::{BasicBlock, EngineInsn};
        use iced_x86::FlowControl;
        let mut insns = vec![EngineInsn::new(
            0x1000,
            &[0x48, 0x8d, 0x15, 0xf9, 0, 0, 0], // lea rdx,[rip+0xf9] -> 0x1100
            FlowControl::Next,
            Some(0x1100),
            None,
        )];
        if intervening_call {
            insns.push(EngineInsn::new(
                0x1007,
                &[0xff, 0x15, 0, 0, 0, 0],
                FlowControl::IndirectCall,
                None,
                Some("OtherApi".into()),
            ));
        }
        let site = if intervening_call { 0x100d } else { 0x1007 };
        insns.push(EngineInsn::new(
            site,
            &[0xff, 0x15, 0, 0, 0, 0],
            FlowControl::IndirectCall,
            None,
            Some("IoQueueWorkItem".into()),
        ));
        Function {
            addr: 0x1000,
            name: "DriverEntry".into(),
            blocks: vec![BasicBlock {
                start: 0x1000,
                end: site + 6,
                insns,
                succ: Vec::new(),
            }],
            size: site + 6 - 0x1000,
            incoming: 0,
            calls: Vec::new(),
            named: true,
            tables: Vec::new(),
        }
    }

    #[test]
    fn direct_callback_argument_recovers_only_known_function_entries() {
        let function = callback_setup(false);
        assert_eq!(
            recover_callback_target(&function, 0x1007, 1, &BTreeSet::from([0x1100])),
            Some(0x1100)
        );
        assert_eq!(
            recover_callback_target(&function, 0x1007, 1, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn dpc_initialization_does_not_claim_the_callback_will_execute() {
        let spec = callback_spec("KeInitializeDpc");
        assert_eq!(spec.argument, Some(1));
        assert!(!spec.establishes_dispatch);
        assert!(callback_spec("IoQueueWorkItem").establishes_dispatch);
    }

    #[test]
    fn dpc_activation_apis_use_their_documented_abi_arguments() {
        assert_eq!(
            dpc_activation_spec("KeInsertQueueDpc")
                .unwrap()
                .context_argument,
            0
        );
        assert_eq!(
            dpc_activation_spec("KeSetTimer").unwrap().context_argument,
            2
        );
        assert_eq!(
            dpc_activation_spec("KeSetTimer").unwrap().owner_argument,
            Some(0)
        );
        assert_eq!(
            dpc_activation_spec("KeSetTimerEx")
                .unwrap()
                .context_argument,
            3
        );
        assert!(dpc_activation_spec("KeCancelTimer").is_none());
        assert_eq!(
            dpc_cancellation_spec("KeCancelTimer").unwrap(),
            DpcCancellationSpec {
                context_argument: None,
                owner_argument: Some(0),
            }
        );
    }

    #[test]
    fn dpc_activation_correlation_requires_exact_object_and_confirmed_path() {
        use crate::analysis::reachability::Reachability;
        let candidates = vec![
            CallbackActivation {
                api: "KeSetTimer".into(),
                site: 0x1200,
                owner_function: Some("QueueDpc".into()),
                context_object: Some(0x3000),
                owner_object: Some(0x5000),
                ordering_confirmed: true,
                reachability: Reachability::ConfirmedDirect,
                provenance: "STATIC_DPC_ACTIVATION_ARGUMENT".into(),
            },
            CallbackActivation {
                api: "KeInsertQueueDpc".into(),
                site: 0x1300,
                owner_function: Some("OrphanQueue".into()),
                context_object: Some(0x4000),
                owner_object: None,
                ordering_confirmed: false,
                reachability: Reachability::Unresolved,
                provenance: "STATIC_DPC_ACTIVATION_ARGUMENT".into(),
            },
        ];
        let matched = matching_dpc_activations(Some(0x3000), &candidates);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].site, 0x1200);
        assert_eq!(
            callback_target_reachability(
                Some(0x2000),
                callback_spec("KeInitializeDpc"),
                Reachability::ConfirmedDirect,
                &matched,
            ),
            Reachability::ConfirmedIndirect
        );
        let wrong_object = matching_dpc_activations(Some(0x5000), &candidates);
        assert!(wrong_object.is_empty());
        assert_eq!(
            callback_target_reachability(
                Some(0x2000),
                callback_spec("KeInitializeDpc"),
                Reachability::ConfirmedDirect,
                &wrong_object,
            ),
            Reachability::Unresolved
        );
        let reachable_but_unordered = vec![CallbackActivation {
            api: "KeInsertQueueDpc".into(),
            site: 0x1400,
            owner_function: Some("OtherFunction".into()),
            context_object: Some(0x6000),
            owner_object: None,
            ordering_confirmed: false,
            reachability: Reachability::ConfirmedDirect,
            provenance: "STATIC_DPC_ACTIVATION_ARGUMENT".into(),
        }];
        assert_eq!(
            callback_target_reachability(
                Some(0x2000),
                callback_spec("KeInitializeDpc"),
                Reachability::ConfirmedDirect,
                &reachable_but_unordered,
            ),
            Reachability::Unresolved
        );
        let unresolved = matching_dpc_activations(Some(0x4000), &candidates);
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            callback_target_reachability(
                Some(0x2000),
                callback_spec("KeInitializeDpc"),
                Reachability::ConfirmedDirect,
                &unresolved,
            ),
            Reachability::Unresolved
        );
    }

    #[test]
    fn dpc_cancellation_is_counter_evidence_not_proof_of_non_execution() {
        use crate::analysis::reachability::Reachability;
        let candidates = vec![CallbackCancellation {
            api: "KeRemoveQueueDpc".into(),
            site: 0x1300,
            owner_function: Some("ScheduleDpc".into()),
            context_object: Some(0x3000),
            owner_object: None,
            after_activation_confirmed: true,
            reachability: Reachability::ConfirmedDirect,
            provenance:
                "STATIC_DPC_CANCELLATION_ARGUMENT_SAME_BLOCK_AFTER_ACTIVATION_RESULT_UNKNOWN".into(),
        }];
        assert_eq!(
            matching_dpc_cancellations(Some(0x3000), &[], &candidates).len(),
            1
        );
        assert!(matching_dpc_cancellations(Some(0x4000), &[], &candidates).is_empty());

        let activation = CallbackActivation {
            api: "KeInsertQueueDpc".into(),
            site: 0x1200,
            owner_function: Some("ScheduleDpc".into()),
            context_object: Some(0x3000),
            owner_object: None,
            ordering_confirmed: true,
            reachability: Reachability::ConfirmedDirect,
            provenance: "STATIC_DPC_ACTIVATION_ARGUMENT".into(),
        };
        assert_eq!(
            callback_target_reachability(
                Some(0x2000),
                callback_spec("KeInitializeDpc"),
                Reachability::ConfirmedDirect,
                &[activation],
            ),
            Reachability::ConfirmedIndirect
        );
    }

    #[test]
    fn timer_cancellation_requires_exact_timer_owner_linkage() {
        use crate::analysis::reachability::Reachability;
        let activation = CallbackActivation {
            api: "KeSetTimer".into(),
            site: 0x1200,
            owner_function: Some("ArmTimer".into()),
            context_object: Some(0x3000),
            owner_object: Some(0x5000),
            ordering_confirmed: true,
            reachability: Reachability::ConfirmedDirect,
            provenance: "STATIC_DPC_ACTIVATION_ARGUMENT".into(),
        };
        let cancellation = CallbackCancellation {
            api: "KeCancelTimer".into(),
            site: 0x1300,
            owner_function: Some("ArmTimer".into()),
            context_object: None,
            owner_object: Some(0x5000),
            after_activation_confirmed: true,
            reachability: Reachability::ConfirmedDirect,
            provenance: "STATIC_DPC_CANCELLATION_ARGUMENT_RESULT_UNKNOWN".into(),
        };
        assert_eq!(
            matching_dpc_cancellations(
                Some(0x3000),
                std::slice::from_ref(&activation),
                std::slice::from_ref(&cancellation),
            )
            .len(),
            1
        );
        let wrong_timer = CallbackCancellation {
            owner_object: Some(0x6000),
            ..cancellation
        };
        assert!(matching_dpc_cancellations(
            Some(0x3000),
            std::slice::from_ref(&activation),
            &[wrong_timer],
        )
        .is_empty());
        assert_eq!(
            callback_target_reachability(
                Some(0x2000),
                callback_spec("KeInitializeDpc"),
                Reachability::ConfirmedDirect,
                &[activation],
            ),
            Reachability::ConfirmedIndirect
        );
    }

    #[test]
    fn dpc_object_and_same_block_order_are_deterministic_facts() {
        use crate::analysis::engine::{BasicBlock, EngineInsn};
        use iced_x86::FlowControl;
        let function = Function {
            addr: 0x1000,
            name: "ScheduleDpc".into(),
            blocks: vec![BasicBlock {
                start: 0x1000,
                end: 0x1013,
                insns: vec![
                    EngineInsn::new(
                        0x1000,
                        &[0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0, 0],
                        FlowControl::Next,
                        Some(0x2000),
                        None,
                    ),
                    EngineInsn::new(
                        0x1007,
                        &[0xff, 0x15, 0, 0, 0, 0],
                        FlowControl::IndirectCall,
                        None,
                        Some("KeInitializeDpc".into()),
                    ),
                    EngineInsn::new(
                        0x100d,
                        &[0xff, 0x15, 0, 0, 0, 0],
                        FlowControl::IndirectCall,
                        None,
                        Some("KeInsertQueueDpc".into()),
                    ),
                ],
                succ: Vec::new(),
            }],
            size: 0x13,
            incoming: 0,
            calls: Vec::new(),
            named: true,
            tables: Vec::new(),
        };
        assert_eq!(recover_literal_argument(&function, 0x1007, 0), Some(0x2000));
        assert!(function_has_basic_block_order(&function, 0x1007, 0x100d));
        assert!(!function_has_basic_block_order(&function, 0x100d, 0x1007));
    }

    #[test]
    fn timer_dpc_arguments_are_recovered_from_r8_and_r9() {
        use crate::analysis::engine::{BasicBlock, EngineInsn};
        use iced_x86::FlowControl;
        let function = Function {
            addr: 0x1000,
            name: "ArmTimers".into(),
            blocks: vec![BasicBlock {
                start: 0x1000,
                end: 0x101a,
                insns: vec![
                    EngineInsn::new(
                        0x1000,
                        &[0x4c, 0x8d, 0x05, 0xf9, 0x0f, 0, 0],
                        FlowControl::Next,
                        Some(0x2000),
                        None,
                    ),
                    EngineInsn::new(
                        0x1007,
                        &[0xff, 0x15, 0, 0, 0, 0],
                        FlowControl::IndirectCall,
                        None,
                        Some("KeSetTimer".into()),
                    ),
                    EngineInsn::new(
                        0x100d,
                        &[0x4c, 0x8d, 0x0d, 0xec, 0x1f, 0, 0],
                        FlowControl::Next,
                        Some(0x3000),
                        None,
                    ),
                    EngineInsn::new(
                        0x1014,
                        &[0xff, 0x15, 0, 0, 0, 0],
                        FlowControl::IndirectCall,
                        None,
                        Some("KeSetTimerEx".into()),
                    ),
                ],
                succ: Vec::new(),
            }],
            size: 0x1a,
            incoming: 0,
            calls: Vec::new(),
            named: true,
            tables: Vec::new(),
        };
        assert_eq!(recover_literal_argument(&function, 0x1007, 2), Some(0x2000));
        assert_eq!(recover_literal_argument(&function, 0x1014, 3), Some(0x3000));
    }

    #[test]
    fn repeated_initialization_of_one_dpc_object_downgrades_all_targets() {
        use crate::analysis::reachability::Reachability;
        let make = |site, target| CallbackRegistration {
            api: "KeInitializeDpc".into(),
            category: "DPC".into(),
            registration_site: site,
            owner_function: Some("ScheduleDpc".into()),
            callback_argument: Some(1),
            context_object: Some(0x4000),
            target: Some(target),
            activations: Vec::new(),
            cancellations: Vec::new(),
            registration_reachability: Reachability::ConfirmedDirect,
            target_reachability: Reachability::ConfirmedIndirect,
            provenance: "DIRECT_ARGUMENT_STATIC_FUNCTION_AND_MATCHED_DPC_QUEUE_OBJECT".into(),
        };
        let mut registrations = vec![make(0x1000, 0x2000), make(0x1100, 0x3000)];
        downgrade_ambiguous_dpc_reinitializations(&mut registrations);
        assert!(registrations.iter().all(|registration| {
            registration.target_reachability == Reachability::Unresolved
                && registration.provenance == "DPC_OBJECT_REINITIALIZATION_AMBIGUOUS"
        }));
        assert_eq!(registrations[0].target, Some(0x2000));
        assert_eq!(registrations[1].target, Some(0x3000));
    }

    #[test]
    fn intervening_call_invalidates_callback_argument_fact() {
        let function = callback_setup(true);
        assert_eq!(
            recover_callback_target(&function, 0x100d, 1, &BTreeSet::from([0x1100])),
            None
        );
    }

    #[test]
    fn non_destination_register_write_invalidates_callback_argument_fact() {
        use crate::analysis::engine::{BasicBlock, EngineInsn};
        use iced_x86::FlowControl;
        let function = Function {
            addr: 0x1000,
            name: "DriverEntry".into(),
            blocks: vec![BasicBlock {
                start: 0x1000,
                end: 0x100f,
                insns: vec![
                    EngineInsn::new(
                        0x1000,
                        &[0x48, 0x8d, 0x15, 0xf9, 0, 0, 0],
                        FlowControl::Next,
                        Some(0x1100),
                        None,
                    ),
                    // xchg rax,rdx writes RDX even though RDX is not operand 0.
                    EngineInsn::new(0x1007, &[0x48, 0x92], FlowControl::Next, None, None),
                    EngineInsn::new(
                        0x1009,
                        &[0xff, 0x15, 0, 0, 0, 0],
                        FlowControl::IndirectCall,
                        None,
                        Some("IoQueueWorkItem".into()),
                    ),
                ],
                succ: Vec::new(),
            }],
            size: 0xf,
            incoming: 0,
            calls: Vec::new(),
            named: true,
            tables: Vec::new(),
        };
        assert_eq!(
            recover_callback_target(&function, 0x1009, 1, &BTreeSet::from([0x1100])),
            None
        );
    }

    #[test]
    fn the_kernel_itself_is_not_a_driver() {
        // ntoskrnl is native, but it is the kernel: it exports the DDK routines
        // and imports only the layers beneath it, so it must not read as a
        // driver just for being native.
        let kernel = native("ntoskrnl.exe", &["BOOTVID.DLL", "CI.DLL", "KDCOM.DLL"]);
        assert!(!plausibly_a_driver(&kernel));

        // A real driver is native and links the kernel executive.
        let driver = native("mystery", &["NTOSKRNL.EXE", "HAL.DLL"]);
        assert!(plausibly_a_driver(&driver));

        // And a .sys is one on its name, whatever it imports.
        let mut by_name = Binary::stub(crate::model::Format::Pe, crate::model::Arch::X86_64);
        by_name.path = "foo.sys".into();
        assert!(plausibly_a_driver(&by_name));
    }

    #[test]
    fn the_driver_fixture_reports_a_full_driver() {
        let (bin, bytes, an) = drive(fixture::pe_with_driver());
        let rep = report(&bin, &bytes, &an, &string_map_for(&bin, &bytes));
        assert!(rep.is_driver);
        assert!(
            rep.why.iter().any(|w| w.contains("native")),
            "{:?}",
            rep.why
        );
        assert_eq!(rep.entry, 0x1000);
        // device + symlink surfaced, referenced by DriverEntry code
        assert!(rep
            .devices
            .iter()
            .any(|d| d.name == "\\Device\\Knifelab" && d.xrefs >= 1));
        assert!(rep
            .devices
            .iter()
            .any(|d| d.name == "\\DosDevices\\Knifelab"));
        // Both names are consumed by device-creating APIs in DriverEntry.
        assert!(
            rep.devices.iter().all(|d| d.created),
            "fixture devices are created via IoCreateDevice/IoCreateSymbolicLink"
        );
        // IRP_MJ_DEVICE_CONTROL (14) -> 0x1100
        let dc = rep
            .irp
            .iter()
            .find(|h| h.major == 14)
            .expect("device-control dispatch recovered");
        assert_eq!(dc.addr, 0x1100);
        assert_eq!(dc.derived, "DispatchDeviceControl");
        // Entry is named for a driver, and the store got a type hint.
        assert_eq!(rep.entry_name, "DriverEntry");
        assert!(
            rep.listing_hints
                .values()
                .any(|h| h.contains("MajorFunction[14]")),
            "dispatch store carries a MajorFunction hint: {:?}",
            rep.listing_hints
        );
        // one IOCTL constant in the handler, decoded as device 0x22
        assert!(
            rep.ioctls.iter().any(|i| i.device_type == 0x22),
            "{:?}",
            rep.ioctls
        );
        // primitives from the kernel catalog
        let phys = rep
            .primitives
            .iter()
            .find(|p| p.api == "MmMapIoSpace")
            .expect("physical-mem primitive");
        assert_eq!(phys.class, "physical-mem");
        assert!(!phys.sites.is_empty());
        // The physical-memory map sits inside DispatchDeviceControl, which is
        // a dispatch root, so it must be user-mode reachable.
        assert!(
            phys.reachable,
            "MmMapIoSpace is reached from the IRP handler"
        );
        assert!(rep.primitives.iter().any(|p| p.api == "IoCreateDevice"));
        // The helper at 0x1200 calls KeInitializeMutex but no direct path reaches
        // it, so the compatibility flag is false while reachability stays unresolved.
        let hidden = rep
            .primitives
            .iter()
            .find(|p| p.api == "KeInitializeMutex")
            .expect("sync primitive from the unreferenced helper");
        assert!(
            !hidden.reachable,
            "KeInitializeMutex has no confirmed direct path"
        );
        assert!(rep.kernel_imports.contains_key("ntoskrnl.dll"));
    }

    #[test]
    fn ctl_code_round_trips() {
        // CTL_CODE(0x22, 0x10, METHOD_BUFFERED(0), FILE_ANY_ACCESS(3))
        let code = (0x22u32 << 16) | (3u32 << 14) | (0x10u32 << 2);
        assert_eq!(decode_ctl(code), (0x22, 0x10, 0, 3));
    }

    #[test]
    fn irp_major_names_readables() {
        assert_eq!(irp_name(14), "IRP_MJ_DEVICE_CONTROL");
        assert_eq!(irp_name(0), "IRP_MJ_CREATE");
    }

    #[test]
    fn a_console_exe_is_not_a_driver() {
        let buf = fixture::pe_with_iat_call();
        let bin = crate::formats::analyze("fixture.exe", &buf).unwrap();
        let an = engine::analyze(&bin, &buf, 200_000, &Db::default());
        let rep = report(&bin, &buf, &an, &string_map_for(&bin, &buf));
        assert!(!rep.is_driver);
    }
}
