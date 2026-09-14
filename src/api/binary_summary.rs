//! Typed binary identity, mitigation, triage, signing, and capability summary.

use crate::address::{FileOffset, Rva, StaticVa};
use crate::analysis::{capabilities, hardening, hashes, signing, triage};
use crate::model::{Binary, Format};
use crate::workspace::Session;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImageAddress {
    Rva(Rva),
    StaticVa(StaticVa),
}

impl ImageAddress {
    pub const fn get(self) -> u64 {
        match self {
            Self::Rva(value) => value.get(),
            Self::StaticVa(value) => value.get(),
        }
    }

    fn from_binary(binary: &Binary, value: u64) -> Self {
        Self::from_format(binary.format, value)
    }

    fn from_format(format: Format, value: u64) -> Self {
        if format == Format::Pe {
            Self::Rva(Rva(value))
        } else {
            Self::StaticVa(StaticVa(value))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionSummary {
    pub name: String,
    pub address: ImageAddress,
    pub virtual_size: u64,
    pub flags: String,
    pub entropy: f64,
    pub static_address: Option<StaticVa>,
    pub file_offset: FileOffset,
    pub file_size: u64,
}

pub fn sections(binary: &Binary) -> Vec<SectionSummary> {
    binary
        .sections
        .iter()
        .map(|section| SectionSummary {
            name: section.name.clone(),
            address: ImageAddress::from_binary(binary, section.vaddr),
            virtual_size: section.vsize,
            flags: section.flags(),
            entropy: section.entropy,
            static_address: crate::analysis::engine::display_base(binary)
                .checked_add(section.vaddr)
                .map(StaticVa),
            file_offset: FileOffset(section.file_off),
            file_size: section.file_size,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub imphash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationSummary {
    pub name: String,
    pub state: String,
    pub kind: String,
    pub detail: String,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationsSummary {
    pub exposure: String,
    pub score: u32,
    pub missing: usize,
    pub applicable: usize,
    pub findings: Vec<MitigationSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageSignalSummary {
    pub text: String,
    pub weight: i32,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageSummary {
    pub score: i32,
    pub verdict: String,
    pub signals: Vec<TriageSignalSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningSummary {
    pub signed: bool,
    pub entries: usize,
    pub subjects: Vec<String>,
    pub thumbprints: Vec<String>,
    pub region_offset: Option<FileOffset>,
    pub region_size: Option<u64>,
    pub header_claims_signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub category: String,
    pub apis: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinarySummary {
    pub path: String,
    pub format: String,
    pub architecture: String,
    pub bits: u32,
    pub size: u64,
    pub image_base: StaticVa,
    pub entry: ImageAddress,
    pub subsystem: Option<String>,
    pub is_library: bool,
    pub is_stripped: bool,
    pub functions_recovered: usize,
    pub functions_named: usize,
    /// Recovery stopped at its configured budget, so coverage is partial.
    pub recovery_truncated: bool,
    pub sections: Vec<SectionSummary>,
    pub hashes: BinaryHashes,
    pub mitigations: MitigationsSummary,
    pub triage: TriageSummary,
    pub signing: SigningSummary,
    pub capabilities: Vec<CapabilitySummary>,
}

impl BinarySummary {
    pub fn from_session(session: &Session, yara_names: &[String]) -> Self {
        let file_hashes = hashes::file_hashes(&session.bytes);
        let hardening = hardening::run(&session.bin);
        let capability_matches = capabilities::matches(
            session
                .bin
                .all_imported_functions()
                .chain(session.bin.exports.iter().map(String::as_str)),
        );
        let triage = triage::run(&session.bin, &capability_matches, yara_names);
        let signing = signing::summarize(&session.bin, &session.bytes);

        let mut by_category: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for capability in &capability_matches {
            by_category
                .entry(capability.category)
                .or_default()
                .push(capability.api.clone());
        }
        let mut capability_summaries: Vec<_> = by_category
            .into_iter()
            .map(|(category, mut apis)| {
                apis.sort();
                apis.dedup();
                CapabilitySummary {
                    category: category.to_string(),
                    apis,
                }
            })
            .collect();
        capability_summaries.sort_by(|left, right| {
            right
                .apis
                .len()
                .cmp(&left.apis.len())
                .then(left.category.cmp(&right.category))
        });

        Self {
            path: session.bin.path.clone(),
            format: session.bin.format.label().to_string(),
            architecture: session.bin.arch.label().to_string(),
            bits: session.bin.bits,
            size: session.bin.size,
            image_base: StaticVa(session.bin.image_base),
            entry: ImageAddress::from_binary(&session.bin, session.bin.entry),
            subsystem: session.bin.subsystem.clone(),
            is_library: session.bin.is_lib,
            is_stripped: session.bin.is_stripped,
            functions_recovered: session.an.functions.len(),
            functions_named: session
                .an
                .functions
                .iter()
                .filter(|function| function.named)
                .count(),
            recovery_truncated: session.an.truncated,
            sections: sections(&session.bin),
            hashes: BinaryHashes {
                md5: file_hashes.md5,
                sha1: file_hashes.sha1,
                sha256: file_hashes.sha256,
                imphash: hashes::imphash(&session.bin),
            },
            mitigations: MitigationsSummary {
                exposure: hardening.exposure.label().to_string(),
                score: hardening.score,
                missing: hardening.missing,
                applicable: hardening.applicable,
                findings: hardening
                    .findings
                    .into_iter()
                    .map(|finding| MitigationSummary {
                        name: finding.name.to_string(),
                        state: finding.state.label().to_string(),
                        kind: finding.state.kind().to_string(),
                        detail: finding.detail,
                        impact: finding.impact.to_string(),
                    })
                    .collect(),
            },
            triage: TriageSummary {
                score: triage.score,
                verdict: triage.verdict.label().to_string(),
                signals: triage
                    .signals
                    .into_iter()
                    .map(|signal| TriageSignalSummary {
                        text: signal.text,
                        weight: signal.weight,
                        kind: signal.kind.to_string(),
                    })
                    .collect(),
            },
            signing: SigningSummary {
                signed: signing.signed,
                entries: signing.entries,
                subjects: signing.subjects,
                thumbprints: signing.thumbprints,
                region_offset: session.bin.sig_region.map(|(offset, _)| FileOffset(offset)),
                region_size: session.bin.sig_region.map(|(_, size)| size),
                header_claims_signed: session.bin.has_signature,
            },
            capabilities: capability_summaries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_image_locations_retain_rva_kind() {
        assert_eq!(
            ImageAddress::from_format(Format::Pe, 0x3000),
            ImageAddress::Rva(Rva(0x3000))
        );
        assert_eq!(
            ImageAddress::from_format(Format::Elf, 0x401000),
            ImageAddress::StaticVa(StaticVa(0x401000))
        );
    }

    #[test]
    fn section_queries_keep_file_offsets_rvas_and_static_addresses_distinct() {
        let bytes = crate::formats::fixture::pe_with_driver();
        let binary = crate::formats::analyze("fixture.sys", &bytes).unwrap();
        let rows = sections(&binary);
        assert_eq!(rows.len(), binary.sections.len());
        for (row, original) in rows.iter().zip(&binary.sections) {
            assert_eq!(row.address, ImageAddress::Rva(Rva(original.vaddr)));
            assert_eq!(
                row.static_address,
                binary.image_base.checked_add(original.vaddr).map(StaticVa)
            );
            assert_eq!(row.file_offset, FileOffset(original.file_off));
            assert_eq!(row.file_size, original.file_size);
        }
    }
}
