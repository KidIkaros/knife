//! Evidence-honest Windows kernel type catalog for front ends.
//!
//! Catalog presence is not permission to apply a layout. Version-sensitive
//! structures remain names-only or `SYMBOLS_REQUIRED` until authoritative
//! symbols/types identify the target build.

use crate::analysis::ktypes::{KField, IO_STACK_LOCATION, LIST_ENTRY, UNICODE_STRING};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LayoutApplicability {
    PublicX64Abi,
    SymbolsRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelField {
    pub offset: u64,
    pub width: u8,
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelTypeLayout {
    pub layout_id: String,
    pub type_name: String,
    pub architecture: String,
    pub source: String,
    pub applicability: LayoutApplicability,
    pub auto_apply: bool,
    pub fields: Vec<KernelField>,
    pub notes: String,
}

fn layout(
    layout_id: &str,
    type_name: &str,
    applicability: LayoutApplicability,
    auto_apply: bool,
    fields: &[KField],
    notes: &str,
) -> KernelTypeLayout {
    KernelTypeLayout {
        layout_id: layout_id.into(),
        type_name: type_name.into(),
        architecture: "x86_64".into(),
        source: "PUBLIC_WDK_OR_AUTHORITATIVE_SYMBOLS".into(),
        applicability,
        auto_apply,
        fields: fields
            .iter()
            .map(|field| KernelField {
                offset: field.offset,
                width: field.width,
                name: field.name.into(),
                type_name: field.ty.into(),
            })
            .collect(),
        notes: notes.into(),
    }
}

pub fn catalog() -> Vec<KernelTypeLayout> {
    let mut layouts = vec![
        layout(
            "nt-unicode-string-x64",
            "UNICODE_STRING",
            LayoutApplicability::PublicX64Abi,
            true,
            UNICODE_STRING,
            "Public ABI layout; typed rendering supplements raw offsets.",
        ),
        layout(
            "nt-list-entry-x64",
            "LIST_ENTRY",
            LayoutApplicability::PublicX64Abi,
            true,
            LIST_ENTRY,
            "Public intrusive-list ABI layout.",
        ),
        layout(
            "nt-io-stack-location-device-io-control-x64",
            "IO_STACK_LOCATION",
            LayoutApplicability::SymbolsRequired,
            false,
            IO_STACK_LOCATION,
            "Displayed as a candidate until target-build symbols or equivalent evidence support the layout.",
        ),
    ];
    for type_name in [
        "DRIVER_OBJECT",
        "DEVICE_OBJECT",
        "FILE_OBJECT",
        "IRP",
        "MDL",
        "EPROCESS",
        "ETHREAD",
        "OBJECT_HEADER",
        "HANDLE",
        "ACCESS_MASK",
    ] {
        layouts.push(layout(
            &format!("nt-{}-symbols", type_name.to_ascii_lowercase().replace('_', "-")),
            type_name,
            LayoutApplicability::SymbolsRequired,
            false,
            &[],
            "Structure is recognized, but no offsets are applied without target-build symbols or recorded equivalent evidence.",
        ));
    }
    layouts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_auto_applies_only_stable_public_layouts() {
        let catalog = catalog();
        let unicode = catalog
            .iter()
            .find(|layout| layout.type_name == "UNICODE_STRING")
            .unwrap();
        assert!(unicode.auto_apply);
        assert!(unicode
            .fields
            .iter()
            .any(|field| field.offset == 8 && field.width == 8 && field.name == "Buffer"));
        assert!(catalog
            .iter()
            .filter(|layout| layout.auto_apply)
            .all(|layout| { layout.applicability == LayoutApplicability::PublicX64Abi }));
        for private_or_versioned in ["FILE_OBJECT", "IRP", "EPROCESS", "OBJECT_HEADER"] {
            let layout = catalog
                .iter()
                .find(|layout| layout.type_name == private_or_versioned)
                .unwrap();
            assert!(!layout.auto_apply);
            assert!(layout.fields.is_empty());
            assert_eq!(layout.applicability, LayoutApplicability::SymbolsRequired);
        }
    }
}
