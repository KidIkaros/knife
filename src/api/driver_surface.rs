//! Evidence-honest Windows driver surface queries for front ends.

use crate::address::{PointerValue, StaticVa};
use crate::analysis::driver::DriverReport;
use crate::analysis::reachability::Reachability;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverSurfaceQuery {
    pub minimum_severity: u8,
    pub confirmed_reachable_only: bool,
}

impl Default for DriverSurfaceQuery {
    fn default() -> Self {
        Self {
            minimum_severity: 1,
            confirmed_reachable_only: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverSurface {
    pub is_driver: bool,
    pub why: Vec<String>,
    pub module: String,
    pub entry: StaticVa,
    pub entry_name: String,
    pub subsystem: Option<String>,
    pub kernel_imports: Vec<(String, usize)>,
    pub app_imports: Vec<String>,
    pub devices: Vec<DeviceSurface>,
    pub irp_handlers: Vec<IrpHandlerSurface>,
    pub indirect_dispatch: Vec<IndirectDispatchEdge>,
    /// Callback registration sites remain first-class even when the callback
    /// target cannot yet be recovered. An unresolved target is evidence of an
    /// indirect path, not evidence that the path is unreachable.
    pub callback_registrations: Vec<CallbackRegistration>,
    /// All observed lifecycle calls, including events not linked to a recovered
    /// registration. Linked events also remain nested on their registration.
    #[serde(default)]
    pub callback_activations: Vec<CallbackActivation>,
    #[serde(default)]
    pub callback_cancellations: Vec<CallbackCancellation>,
    pub ioctls: Vec<IoctlSurface>,
    pub primitives: Vec<PrimitiveSurface>,
    pub known_bad: Vec<KnownBadDriver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSurface {
    pub name: String,
    pub address: StaticVa,
    pub wide: bool,
    pub xrefs: usize,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrpHandlerSurface {
    pub major: u8,
    pub name: String,
    pub derived_name: String,
    pub address: StaticVa,
}

/// A deterministically recovered function-pointer edge. Optional locations are
/// explicit because static analysis does not know a runtime DriverObject
/// address or a guarded-call wrapper merely from a table store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectDispatchEdge {
    pub kind: String,
    pub table: String,
    pub entry_name: Option<String>,
    pub table_address: Option<StaticVa>,
    pub declared_table_size: Option<u32>,
    pub table_offset: u64,
    pub pointer_value: Option<PointerValue>,
    pub target: Option<StaticVa>,
    pub loader: StaticVa,
    pub caller: Option<StaticVa>,
    pub guarded_call_wrapper: Option<StaticVa>,
    pub reachability: Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackRegistration {
    pub api: String,
    pub category: String,
    pub registration_site: StaticVa,
    pub owner_function: Option<String>,
    /// Zero-based Windows x64 ABI argument containing the callback when the
    /// API passes it directly. `None` means the callback is structure-backed.
    pub callback_argument: Option<u8>,
    pub context_object: Option<StaticVa>,
    pub target: Option<StaticVa>,
    pub activations: Vec<CallbackActivation>,
    pub cancellations: Vec<CallbackCancellation>,
    pub registration_reachability: Reachability,
    pub target_reachability: Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackActivation {
    pub api: String,
    pub site: StaticVa,
    pub owner_function: Option<String>,
    pub context_object: Option<StaticVa>,
    pub owner_object: Option<StaticVa>,
    pub ordering_confirmed: bool,
    pub reachability: Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackCancellation {
    pub api: String,
    pub site: StaticVa,
    pub owner_function: Option<String>,
    pub context_object: Option<StaticVa>,
    pub owner_object: Option<StaticVa>,
    pub after_activation_confirmed: bool,
    pub reachability: Reachability,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoctlSurface {
    pub code: u32,
    pub device_type: u32,
    pub function: u32,
    pub method_code: u32,
    pub method: String,
    pub access: u32,
    pub address: StaticVa,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimitiveSite {
    pub address: StaticVa,
    pub function: Option<String>,
    pub function_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimitiveSurface {
    pub api: String,
    pub class: String,
    pub severity: u8,
    /// Compatibility projection for existing clients. `false` means unproven,
    /// never confirmed unreachable; use `reachability` for the actual state.
    pub reachable: bool,
    pub reachability: Reachability,
    pub sites: Vec<PrimitiveSite>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownBadDriver {
    pub file: String,
    pub vendor: String,
    pub product: String,
    pub category: String,
    pub signer: String,
    pub malicious: bool,
}

impl DriverSurface {
    pub(crate) fn from_report(report: &DriverReport, query: DriverSurfaceQuery) -> Self {
        let confirmed = |state| {
            matches!(
                state,
                Reachability::ConfirmedDirect | Reachability::ConfirmedIndirect
            )
        };
        Self {
            is_driver: report.is_driver,
            why: report.why.clone(),
            module: report.module.clone(),
            entry: StaticVa(report.entry),
            entry_name: report.entry_name.clone(),
            subsystem: report.subsystem.clone(),
            kernel_imports: report
                .kernel_imports
                .iter()
                .map(|(module, count)| (module.clone(), *count))
                .collect(),
            app_imports: report.app_imports.clone(),
            devices: report
                .devices
                .iter()
                .map(|device| DeviceSurface {
                    name: device.name.clone(),
                    address: StaticVa(device.addr),
                    wide: device.wide,
                    xrefs: device.xrefs,
                    created: device.created,
                })
                .collect(),
            irp_handlers: report
                .irp
                .iter()
                .map(|handler| IrpHandlerSurface {
                    major: handler.major,
                    name: handler.name.clone(),
                    derived_name: handler.derived.clone(),
                    address: StaticVa(handler.addr),
                })
                .collect(),
            indirect_dispatch: report
                .irp
                .iter()
                .map(|handler| IndirectDispatchEdge {
                    kind: "DRIVER_MAJOR_FUNCTION".into(),
                    table: "DRIVER_OBJECT.MajorFunction".into(),
                    entry_name: Some(handler.name.clone()),
                    table_address: None,
                    declared_table_size: None,
                    table_offset: handler.table_offset,
                    pointer_value: Some(PointerValue(handler.addr)),
                    target: Some(StaticVa(handler.addr)),
                    loader: StaticVa(handler.loader_addr),
                    caller: None,
                    guarded_call_wrapper: None,
                    reachability: Reachability::ConfirmedIndirect,
                    provenance: "STATIC_TABLE_STORE".into(),
                })
                .chain(
                    report
                        .fast_io_tables
                        .iter()
                        .map(|table| IndirectDispatchEdge {
                            kind: "FAST_IO_TABLE_ASSIGNMENT".into(),
                            table: "DRIVER_OBJECT.FastIoDispatch".into(),
                            entry_name: Some("TABLE_BASE".into()),
                            table_address: Some(StaticVa(table.table_addr)),
                            declared_table_size: table.declared_size,
                            table_offset: crate::analysis::ktypes::FAST_IO_DISPATCH_OFFSET,
                            pointer_value: Some(PointerValue(table.table_addr)),
                            target: None,
                            loader: StaticVa(table.loader_addr),
                            caller: None,
                            guarded_call_wrapper: None,
                            reachability: Reachability::Unresolved,
                            provenance: table.provenance.clone(),
                        }),
                )
                .chain(report.fast_io.iter().map(|handler| IndirectDispatchEdge {
                    kind: "FAST_IO_DISPATCH".into(),
                    table: "FAST_IO_DISPATCH".into(),
                    entry_name: Some(handler.name.clone()),
                    table_address: Some(StaticVa(handler.table_addr)),
                    declared_table_size: None,
                    table_offset: handler.table_offset,
                    pointer_value: Some(PointerValue(handler.pointer_value)),
                    target: handler.target.map(StaticVa),
                    loader: StaticVa(handler.loader_addr),
                    caller: None,
                    guarded_call_wrapper: None,
                    reachability: handler.reachability,
                    provenance: handler.provenance.clone(),
                }))
                .collect(),
            callback_registrations: report
                .callback_registrations
                .iter()
                .map(|registration| CallbackRegistration {
                    api: registration.api.clone(),
                    category: registration.category.clone(),
                    registration_site: StaticVa(registration.registration_site),
                    owner_function: registration.owner_function.clone(),
                    callback_argument: registration.callback_argument,
                    context_object: registration.context_object.map(StaticVa),
                    target: registration.target.map(StaticVa),
                    activations: registration
                        .activations
                        .iter()
                        .map(|activation| CallbackActivation {
                            api: activation.api.clone(),
                            site: StaticVa(activation.site),
                            owner_function: activation.owner_function.clone(),
                            context_object: activation.context_object.map(StaticVa),
                            owner_object: activation.owner_object.map(StaticVa),
                            ordering_confirmed: activation.ordering_confirmed,
                            reachability: activation.reachability,
                            provenance: activation.provenance.clone(),
                        })
                        .collect(),
                    cancellations: registration
                        .cancellations
                        .iter()
                        .map(|cancellation| CallbackCancellation {
                            api: cancellation.api.clone(),
                            site: StaticVa(cancellation.site),
                            owner_function: cancellation.owner_function.clone(),
                            context_object: cancellation.context_object.map(StaticVa),
                            owner_object: cancellation.owner_object.map(StaticVa),
                            after_activation_confirmed: cancellation.after_activation_confirmed,
                            reachability: cancellation.reachability,
                            provenance: cancellation.provenance.clone(),
                        })
                        .collect(),
                    registration_reachability: registration.registration_reachability,
                    target_reachability: registration.target_reachability,
                    provenance: registration.provenance.clone(),
                })
                .collect(),
            callback_activations: report
                .callback_activations
                .iter()
                .map(|activation| CallbackActivation {
                    api: activation.api.clone(),
                    site: StaticVa(activation.site),
                    owner_function: activation.owner_function.clone(),
                    context_object: activation.context_object.map(StaticVa),
                    owner_object: activation.owner_object.map(StaticVa),
                    ordering_confirmed: activation.ordering_confirmed,
                    reachability: activation.reachability,
                    provenance: activation.provenance.clone(),
                })
                .collect(),
            callback_cancellations: report
                .callback_cancellations
                .iter()
                .map(|cancellation| CallbackCancellation {
                    api: cancellation.api.clone(),
                    site: StaticVa(cancellation.site),
                    owner_function: cancellation.owner_function.clone(),
                    context_object: cancellation.context_object.map(StaticVa),
                    owner_object: cancellation.owner_object.map(StaticVa),
                    after_activation_confirmed: cancellation.after_activation_confirmed,
                    reachability: cancellation.reachability,
                    provenance: cancellation.provenance.clone(),
                })
                .collect(),
            ioctls: report
                .ioctls
                .iter()
                .map(|ioctl| IoctlSurface {
                    code: ioctl.code,
                    device_type: ioctl.device_type,
                    function: ioctl.function,
                    method_code: ioctl.method_code,
                    method: ioctl.method.clone(),
                    access: ioctl.access,
                    address: StaticVa(ioctl.addr),
                })
                .collect(),
            primitives: report
                .primitives
                .iter()
                .filter(|primitive| primitive.severity >= query.minimum_severity)
                .filter(|primitive| {
                    !query.confirmed_reachable_only || confirmed(primitive.reachability)
                })
                .map(|primitive| PrimitiveSurface {
                    api: primitive.api.clone(),
                    class: primitive.class.clone(),
                    severity: primitive.severity,
                    reachable: confirmed(primitive.reachability),
                    reachability: primitive.reachability,
                    sites: primitive
                        .sites
                        .iter()
                        .map(|site| PrimitiveSite {
                            address: StaticVa(site.from),
                            function: site.in_func.clone(),
                            function_offset: site.at_off,
                        })
                        .collect(),
                })
                .collect(),
            known_bad: report
                .known_bad
                .iter()
                .map(|known| KnownBadDriver {
                    file: known.file.clone(),
                    vendor: known.vendor.clone(),
                    product: known.product.clone(),
                    category: known.category.clone(),
                    signer: known.signer.clone(),
                    malicious: known.malicious,
                })
                .collect(),
        }
    }

    /// Apply presentation filters to an already materialized stable surface.
    /// This keeps front ends from caching or importing the internal report.
    pub fn filtered(&self, query: DriverSurfaceQuery) -> Self {
        let mut filtered = self.clone();
        filtered.primitives.retain(|primitive| {
            primitive.severity >= query.minimum_severity
                && (!query.confirmed_reachable_only || primitive.reachability.is_confirmed())
        });
        filtered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::driver::{
        CallbackActivation as ReportCallbackActivation,
        CallbackCancellation as ReportCallbackCancellation,
        CallbackRegistration as ReportCallbackRegistration, DriverReport, FastIoHandler,
        FastIoTableAssignment, Primitive,
    };

    #[test]
    fn unresolved_is_not_exported_as_confirmed_unreachable() {
        let report = DriverReport {
            is_driver: true,
            primitives: vec![Primitive {
                api: "IndirectTarget".into(),
                class: "callback".into(),
                severity: 3,
                sites: Vec::new(),
                reachable: false,
                reachability: Reachability::Unresolved,
            }],
            ..DriverReport::default()
        };
        let all = DriverSurface::from_report(&report, DriverSurfaceQuery::default());
        assert_eq!(all.primitives.len(), 1);
        assert_eq!(all.primitives[0].reachability, Reachability::Unresolved);
        assert!(!all.primitives[0].reachable);
        let confirmed = DriverSurface::from_report(
            &report,
            DriverSurfaceQuery {
                minimum_severity: 1,
                confirmed_reachable_only: true,
            },
        );
        assert!(confirmed.primitives.is_empty());
        assert!(all
            .filtered(DriverSurfaceQuery {
                minimum_severity: 1,
                confirmed_reachable_only: true,
            })
            .primitives
            .is_empty());
    }

    #[test]
    fn callback_registration_is_preserved_when_target_is_unresolved() {
        use crate::analysis::sinks::Site;
        let report = DriverReport {
            primitives: vec![Primitive {
                api: "ObRegisterCallbacks".into(),
                class: "callback".into(),
                severity: 3,
                sites: vec![Site {
                    from: 0x140001000,
                    in_func: Some("DriverEntry".into()),
                    at_off: 0x20,
                }],
                reachable: true,
                reachability: Reachability::ConfirmedDirect,
            }],
            callback_registrations: vec![ReportCallbackRegistration {
                api: "ObRegisterCallbacks".into(),
                category: "OBJECT_CALLBACK_STRUCTURE".into(),
                registration_site: 0x140001000,
                owner_function: Some("DriverEntry".into()),
                callback_argument: None,
                context_object: None,
                target: None,
                activations: Vec::new(),
                cancellations: Vec::new(),
                registration_reachability: Reachability::ConfirmedDirect,
                target_reachability: Reachability::Unresolved,
                provenance: "STRUCTURE_BACKED_TARGET_UNRESOLVED".into(),
            }],
            ..DriverReport::default()
        };
        let surface = DriverSurface::from_report(&report, DriverSurfaceQuery::default());
        let registration = &surface.callback_registrations[0];
        assert_eq!(registration.callback_argument, None);
        assert_eq!(registration.target, None);
        assert_eq!(
            registration.registration_reachability,
            Reachability::ConfirmedDirect
        );
        assert_eq!(registration.target_reachability, Reachability::Unresolved);
        assert_eq!(registration.registration_site, StaticVa(0x140001000));
        assert_eq!(
            registration.provenance,
            "STRUCTURE_BACKED_TARGET_UNRESOLVED"
        );
    }

    #[test]
    fn unresolved_fast_io_pointer_is_not_dropped_or_promoted_to_a_target() {
        let report = DriverReport {
            fast_io: vec![FastIoHandler {
                name: "FastIoRead".into(),
                table_addr: 0x140002000,
                table_offset: 0x10,
                pointer_value: 0xfffff80012345678,
                target: None,
                loader_addr: 0x140001020,
                reachability: Reachability::Unresolved,
                provenance: "STATIC_FAST_IO_POINTER_TARGET_UNRESOLVED".into(),
            }],
            ..DriverReport::default()
        };
        let surface = DriverSurface::from_report(&report, DriverSurfaceQuery::default());
        let edge = &surface.indirect_dispatch[0];
        assert_eq!(edge.kind, "FAST_IO_DISPATCH");
        assert_eq!(edge.entry_name.as_deref(), Some("FastIoRead"));
        assert_eq!(edge.pointer_value, Some(PointerValue(0xfffff80012345678)));
        assert_eq!(edge.target, None);
        assert_eq!(edge.reachability, Reachability::Unresolved);
    }

    #[test]
    fn fast_io_table_assignment_survives_when_table_bytes_are_unavailable() {
        let report = DriverReport {
            fast_io_tables: vec![FastIoTableAssignment {
                table_addr: 0x140009000,
                loader_addr: 0x140001040,
                declared_size: None,
                provenance: "STATIC_FAST_IO_TABLE_BYTES_UNAVAILABLE".into(),
            }],
            ..DriverReport::default()
        };
        let surface = DriverSurface::from_report(&report, DriverSurfaceQuery::default());
        let edge = &surface.indirect_dispatch[0];
        assert_eq!(edge.kind, "FAST_IO_TABLE_ASSIGNMENT");
        assert_eq!(edge.pointer_value, Some(PointerValue(0x140009000)));
        assert_eq!(edge.target, None);
        assert_eq!(edge.reachability, Reachability::Unresolved);
    }

    #[test]
    fn dpc_lifecycle_evidence_keeps_object_order_and_reachability() {
        let report = DriverReport {
            callback_registrations: vec![ReportCallbackRegistration {
                api: "KeInitializeDpc".into(),
                category: "DPC".into(),
                registration_site: 0x140001000,
                owner_function: Some("ScheduleDpc".into()),
                callback_argument: Some(1),
                context_object: Some(0x140004000),
                target: Some(0x140002000),
                activations: vec![ReportCallbackActivation {
                    api: "KeSetTimer".into(),
                    site: 0x140001020,
                    owner_function: Some("ScheduleDpc".into()),
                    context_object: Some(0x140004000),
                    owner_object: Some(0x140005000),
                    ordering_confirmed: true,
                    reachability: Reachability::ConfirmedDirect,
                    provenance: "STATIC_DPC_QUEUE_ARGUMENT_SAME_BLOCK_AFTER_INITIALIZATION".into(),
                }],
                cancellations: vec![ReportCallbackCancellation {
                    api: "KeCancelTimer".into(),
                    site: 0x140001030,
                    owner_function: Some("ScheduleDpc".into()),
                    context_object: None,
                    owner_object: Some(0x140005000),
                    after_activation_confirmed: true,
                    reachability: Reachability::ConfirmedDirect,
                    provenance:
                        "STATIC_TIMER_OWNER_LINK_SAME_BLOCK_AFTER_ACTIVATION_RESULT_UNKNOWN".into(),
                }],
                registration_reachability: Reachability::ConfirmedDirect,
                target_reachability: Reachability::ConfirmedIndirect,
                provenance: "DIRECT_ARGUMENT_STATIC_FUNCTION_AND_MATCHED_DPC_QUEUE_OBJECT".into(),
            }],
            ..DriverReport::default()
        };
        let surface = DriverSurface::from_report(&report, DriverSurfaceQuery::default());
        let registration = &surface.callback_registrations[0];
        assert_eq!(registration.context_object, Some(StaticVa(0x140004000)));
        assert_eq!(registration.target, Some(StaticVa(0x140002000)));
        assert_eq!(registration.activations.len(), 1);
        assert!(registration.activations[0].ordering_confirmed);
        assert_eq!(registration.cancellations.len(), 1);
        assert!(registration.cancellations[0].after_activation_confirmed);
        assert_eq!(
            registration.cancellations[0].owner_object,
            registration.activations[0].owner_object
        );
        assert_eq!(
            registration.activations[0].context_object,
            registration.context_object
        );
        assert_eq!(
            registration.target_reachability,
            Reachability::ConfirmedIndirect
        );
    }

    #[test]
    fn unmatched_callback_lifecycle_events_survive_the_stable_surface() {
        let report = DriverReport {
            callback_activations: vec![ReportCallbackActivation {
                api: "KeSetTimer".into(),
                site: 0x140001020,
                owner_function: Some("ArmUnknownTimer".into()),
                context_object: None,
                owner_object: Some(0x140005000),
                ordering_confirmed: false,
                reachability: Reachability::ConfirmedDirect,
                provenance: "STATIC_DPC_ACTIVATION_ARGUMENT".into(),
            }],
            callback_cancellations: vec![ReportCallbackCancellation {
                api: "KeCancelTimer".into(),
                site: 0x140001040,
                owner_function: Some("ArmUnknownTimer".into()),
                context_object: None,
                owner_object: Some(0x140005000),
                after_activation_confirmed: false,
                reachability: Reachability::ConfirmedDirect,
                provenance: "STATIC_DPC_CANCELLATION_ARGUMENT_RESULT_UNKNOWN".into(),
            }],
            ..DriverReport::default()
        };
        let surface = DriverSurface::from_report(&report, DriverSurfaceQuery::default());
        assert!(surface.callback_registrations.is_empty());
        assert_eq!(surface.callback_activations.len(), 1);
        assert_eq!(surface.callback_cancellations.len(), 1);
        assert_eq!(
            surface.callback_activations[0].owner_object,
            Some(StaticVa(0x140005000))
        );
        assert_eq!(surface.callback_activations[0].context_object, None);
        assert_eq!(surface.callback_cancellations[0].context_object, None);
    }
}
