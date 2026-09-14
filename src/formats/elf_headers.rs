//! Lossless ELF header inspection, independent of function recovery.
use anyhow::{bail, Context, Result};
use goblin::elf::{header, program_header, section_header, Elf};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FileHeader {
    pub e_ident: [u8; 16],
    pub class: &'static str,
    pub byte_order: &'static str,
    pub os_abi: u8,
    pub abi_version: u8,
    pub identification_version: u8,
    pub resolved_program_count: usize,
    pub resolved_section_count: usize,
    pub resolved_string_table_index: usize,
    pub e_type: u16,
    pub type_name: &'static str,
    pub e_machine: u16,
    pub machine_name: &'static str,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Debug, Serialize)]
pub struct ProgramHeader {
    pub index: usize,
    pub p_type: u32,
    pub type_name: &'static str,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
    pub permissions: String,
    pub section_indices: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub struct SectionHeader {
    pub index: usize,
    pub name: Option<String>,
    pub sh_name: usize,
    pub sh_type: u32,
    pub type_name: &'static str,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[derive(Debug, Serialize)]
pub struct ElfHeaders {
    pub header: FileHeader,
    pub segments: Vec<ProgramHeader>,
    pub sections: Vec<SectionHeader>,
}

/// Parse with the existing Goblin decoder. Unknown numeric values are retained.
/// No disassembler, annotation database or analysis worker is required.
pub fn inspect(bytes: &[u8]) -> Result<ElfHeaders> {
    if !bytes.starts_with(b"\x7fELF") {
        bail!("ELF header inspection requires an ELF file");
    }
    std::panic::catch_unwind(|| inspect_inner(bytes))
        .map_err(|_| anyhow::anyhow!("malformed ELF: parser rejected input"))?
}

fn inspect_inner(bytes: &[u8]) -> Result<ElfHeaders> {
    let h = Elf::parse_header(bytes).context("cannot decode ELF header")?;
    let ctx = goblin::container::Ctx::new(h.container()?, h.endianness()?);
    if usize::from(h.e_ehsize) != header::Header::size(ctx) {
        bail!("invalid ELF header size");
    }
    if h.e_shoff != 0 && usize::from(h.e_shentsize) != section_header::SectionHeader::size(ctx) {
        bail!("invalid ELF section header entry size");
    }
    if h.e_shoff == 0 && h.e_shnum != 0 {
        bail!("section count without section table");
    }
    let raw_sections = section_header::SectionHeader::parse(
        bytes,
        usize::try_from(h.e_shoff)?,
        usize::from(h.e_shnum),
        ctx,
    )?;
    let first = raw_sections.first();
    let program_count = if h.e_phnum == 0xffff {
        usize::try_from(
            first
                .context("extended program count requires section zero")?
                .sh_info,
        )?
    } else {
        usize::from(h.e_phnum)
    };
    if program_count != 0
        && (h.e_phoff == 0
            || usize::from(h.e_phentsize) != program_header::ProgramHeader::size(ctx))
    {
        bail!("invalid ELF program header table offset or entry size");
    }
    let raw_programs = program_header::ProgramHeader::parse(
        bytes,
        usize::try_from(h.e_phoff)?,
        program_count,
        ctx,
    )?;
    let string_index = if h.e_shstrndx == 0xffff {
        usize::try_from(
            first
                .context("extended string index requires section zero")?
                .sh_link,
        )?
    } else {
        usize::from(h.e_shstrndx)
    };
    let names = if string_index == 0 {
        goblin::strtab::Strtab::default()
    } else {
        let s = raw_sections
            .get(string_index)
            .context("invalid section name table index")?;
        if s.sh_type != section_header::SHT_STRTAB {
            bail!("section name table is not SHT_STRTAB");
        }
        goblin::strtab::Strtab::parse(
            bytes,
            usize::try_from(s.sh_offset)?,
            usize::try_from(s.sh_size)?,
            0,
        )?
    };
    let header = FileHeader {
        e_ident: h.e_ident,
        class: match h.e_ident[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "UNKNOWN",
        },
        byte_order: match h.e_ident[5] {
            1 => "little-endian",
            2 => "big-endian",
            _ => "UNKNOWN",
        },
        os_abi: h.e_ident[7],
        abi_version: h.e_ident[8],
        identification_version: h.e_ident[6],
        resolved_program_count: raw_programs.len(),
        resolved_section_count: raw_sections.len(),
        resolved_string_table_index: string_index,
        e_type: h.e_type,
        type_name: header::et_to_str(h.e_type),
        e_machine: h.e_machine,
        machine_name: header::machine_to_str(h.e_machine),
        e_version: h.e_version,
        e_entry: h.e_entry,
        e_phoff: h.e_phoff,
        e_shoff: h.e_shoff,
        e_flags: h.e_flags,
        e_ehsize: h.e_ehsize,
        e_phentsize: h.e_phentsize,
        e_phnum: h.e_phnum,
        e_shentsize: h.e_shentsize,
        e_shnum: h.e_shnum,
        e_shstrndx: h.e_shstrndx,
    };
    let segments = raw_programs
        .iter()
        .enumerate()
        .map(|(index, p)| ProgramHeader {
            index,
            p_type: p.p_type,
            type_name: program_header::pt_to_str(p.p_type),
            p_flags: p.p_flags,
            p_offset: p.p_offset,
            p_vaddr: p.p_vaddr,
            p_paddr: p.p_paddr,
            p_filesz: p.p_filesz,
            p_memsz: p.p_memsz,
            p_align: p.p_align,
            permissions: format!(
                "{}{}{}",
                if p.p_flags & 4 != 0 { "R" } else { "-" },
                if p.p_flags & 2 != 0 { "W" } else { "-" },
                if p.p_flags & 1 != 0 { "X" } else { "-" }
            ),
            section_indices: raw_sections
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    s.sh_type != section_header::SHT_NULL
                        && s.sh_flags & u64::from(section_header::SHF_ALLOC) != 0
                        && contained(s.sh_addr, s.sh_size, p.p_vaddr, p.p_memsz)
                        && (s.sh_type == section_header::SHT_NOBITS
                            || contained(s.sh_offset, s.sh_size, p.p_offset, p.p_filesz))
                        && (p.p_type != program_header::PT_TLS
                            || s.sh_flags & u64::from(section_header::SHF_TLS) != 0)
                })
                .map(|(i, _)| i)
                .collect(),
        })
        .collect();
    let sections = raw_sections
        .iter()
        .enumerate()
        .map(|(index, s)| SectionHeader {
            index,
            name: names.get_at(s.sh_name).map(str::to_owned),
            sh_name: s.sh_name,
            sh_type: s.sh_type,
            type_name: section_header::sht_to_str(s.sh_type),
            sh_flags: s.sh_flags,
            sh_addr: s.sh_addr,
            sh_offset: s.sh_offset,
            sh_size: s.sh_size,
            sh_link: s.sh_link,
            sh_info: s.sh_info,
            sh_addralign: s.sh_addralign,
            sh_entsize: s.sh_entsize,
        })
        .collect();
    Ok(ElfHeaders {
        header,
        segments,
        sections,
    })
}

fn contained(start: u64, size: u64, outer: u64, extent: u64) -> bool {
    match (start.checked_add(size), outer.checked_add(extent)) {
        (Some(end), Some(limit)) => start >= outer && start < limit && end <= limit,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(class: u8, endian: u8) -> Vec<u8> {
        let mut b = vec![0; if class == 1 { 52 } else { 64 }];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', class, endian, 1]);
        let put16 = |b: &mut [u8], at, v: u16| {
            b[at..at + 2].copy_from_slice(&if endian == 1 {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            });
        };
        put16(&mut b, 16, 2);
        put16(&mut b, 18, 62);
        b[if endian == 1 { 20 } else { 23 }] = 1;
        put16(
            &mut b,
            if class == 1 { 40 } else { 52 },
            if class == 1 { 52 } else { 64 },
        );
        b
    }

    #[test]
    fn both_classes_and_byte_orders_without_sections() {
        for class in [1, 2] {
            for endian in [1, 2] {
                let b = minimal(class, endian);
                let result = inspect(&b).unwrap();
                assert_eq!(result.header.e_type, 2);
                assert_eq!(result.header.e_machine, 62);
                assert_eq!(result.header.e_ident, b[..16]);
                assert!(result.sections.is_empty());
                assert!(result.segments.is_empty());
            }
        }
    }

    #[test]
    fn truncated_and_non_elf_are_errors() {
        let b = minimal(2, 1);
        for end in 0..b.len() {
            assert!(inspect(&b[..end]).is_err());
        }
        assert!(inspect(b"MZ not ELF").is_err());
    }

    #[test]
    fn raw_tables_and_extended_counts_are_preserved() {
        let mut b = crate::formats::fixture::elf_with_plt_call();
        let normal = inspect(&b).unwrap();
        assert_eq!(normal.segments.len(), 3);
        assert_eq!(normal.sections.len(), 5);
        assert_eq!(normal.sections[0].sh_type, 0);
        assert_eq!(normal.sections[2].name.as_deref(), Some(".text"));
        assert!(normal.segments[0].section_indices.contains(&2));
        assert_eq!(normal.segments[0].permissions, "RWX");
        let shoff = normal.header.e_shoff as usize;
        b[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
        b[60..62].copy_from_slice(&0u16.to_le_bytes());
        b[62..64].copy_from_slice(&0xffffu16.to_le_bytes());
        b[shoff + 32..shoff + 40].copy_from_slice(&5u64.to_le_bytes());
        b[shoff + 40..shoff + 44].copy_from_slice(&4u32.to_le_bytes());
        b[shoff + 44..shoff + 48].copy_from_slice(&3u32.to_le_bytes());
        let extended = inspect(&b).unwrap();
        assert_eq!(extended.header.e_phnum, 0xffff);
        assert_eq!(extended.header.e_shnum, 0);
        assert_eq!(extended.header.resolved_program_count, 3);
        assert_eq!(extended.header.resolved_section_count, 5);
        assert_eq!(extended.header.resolved_string_table_index, 4);
        assert_eq!(extended.sections[2].name, normal.sections[2].name);
    }

    #[test]
    fn malformed_tables_reject_and_unknown_values_survive() {
        let b = crate::formats::fixture::elf_with_plt_call();
        for (at, value) in [(32, u64::MAX), (40, u64::MAX)] {
            let mut bad = b.clone();
            bad[at..at + 8].copy_from_slice(&value.to_le_bytes());
            assert!(inspect(&bad).is_err());
        }
        let mut bad = b.clone();
        bad[54..56].copy_from_slice(&1u16.to_le_bytes());
        assert!(inspect(&bad).is_err());
        let mut unknown = b;
        unknown[16..18].copy_from_slice(&0xfe12u16.to_le_bytes());
        unknown[64..68].copy_from_slice(&0x71234567u32.to_le_bytes());
        let r = inspect(&unknown).unwrap();
        assert_eq!(r.header.e_type, 0xfe12);
        assert_eq!(r.segments[0].p_type, 0x71234567);
        assert!(!contained(u64::MAX, 4, 0, u64::MAX));
    }

    #[test]
    fn program_tables_decode_in_both_classes_and_byte_orders() {
        for class in [1, 2] {
            for endian in [1, 2] {
                let mut b = minimal(class, endian);
                let header_size = b.len();
                let ph_size = if class == 1 { 32 } else { 56 };
                b.resize(header_size + ph_size, 0);
                let put = |b: &mut [u8], at: usize, width: usize, value: u64| {
                    let raw = if endian == 1 {
                        value.to_le_bytes()
                    } else {
                        value.to_be_bytes()
                    };
                    let range = if endian == 1 { 0..width } else { 8 - width..8 };
                    b[at..at + width].copy_from_slice(&raw[range]);
                };
                if class == 1 {
                    put(&mut b, 28, 4, header_size as u64);
                    put(&mut b, 42, 2, ph_size as u64);
                    put(&mut b, 44, 2, 1);
                    put(&mut b, header_size + 8, 4, 0x8048000);
                    put(&mut b, header_size + 16, 4, 16);
                    put(&mut b, header_size + 20, 4, 32);
                    put(&mut b, header_size + 24, 4, 5);
                } else {
                    put(&mut b, 32, 8, header_size as u64);
                    put(&mut b, 54, 2, ph_size as u64);
                    put(&mut b, 56, 2, 1);
                    put(&mut b, header_size + 4, 4, 5);
                    put(&mut b, header_size + 16, 8, 0x8048000);
                    put(&mut b, header_size + 32, 8, 16);
                    put(&mut b, header_size + 40, 8, 32);
                }
                put(&mut b, header_size, 4, 1);
                let result = inspect(&b).unwrap();
                assert_eq!(result.segments[0].p_vaddr, 0x8048000);
                assert_eq!(result.segments[0].p_filesz, 16);
                assert_eq!(result.segments[0].p_memsz, 32);
                assert_eq!(result.segments[0].permissions, "R-X");
                assert!(inspect(&b[..b.len() - 1]).is_err());
            }
        }
    }
}
