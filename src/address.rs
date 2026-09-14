//! Explicit address kinds and checked conversions.
//!
//! These wrappers let analysis code state which address space a value belongs
//! to while existing analysis APIs migrate incrementally from raw `u64`s.

use serde::{Deserialize, Serialize};

macro_rules! address_type {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub u64);

        impl $name {
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }
    };
}

address_type!(FileOffset);
address_type!(Rva);
address_type!(StaticVa);
address_type!(RuntimeVa);
address_type!(PointerValue);
address_type!(MemoryContent);

/// Bases required to correlate one image's static and runtime addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressMapping {
    pub static_image_base: StaticVa,
    pub runtime_image_base: RuntimeVa,
}

impl AddressMapping {
    pub fn rva_from_static(self, address: StaticVa) -> Option<Rva> {
        address.0.checked_sub(self.static_image_base.0).map(Rva)
    }

    pub fn rva_from_runtime(self, address: RuntimeVa) -> Option<Rva> {
        address.0.checked_sub(self.runtime_image_base.0).map(Rva)
    }

    pub fn static_from_rva(self, rva: Rva) -> Option<StaticVa> {
        self.static_image_base.0.checked_add(rva.0).map(StaticVa)
    }

    pub fn runtime_from_rva(self, rva: Rva) -> Option<RuntimeVa> {
        self.runtime_image_base.0.checked_add(rva.0).map(RuntimeVa)
    }

    pub fn static_from_runtime(self, address: RuntimeVa) -> Option<StaticVa> {
        self.static_from_rva(self.rva_from_runtime(address)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_address_maps_to_static_rva() {
        let mapping = AddressMapping {
            static_image_base: StaticVa(0x140000000),
            runtime_image_base: RuntimeVa(0x180000000),
        };
        assert_eq!(
            mapping.rva_from_runtime(RuntimeVa(0x180002000)),
            Some(Rva(0x2000))
        );
        assert_eq!(
            mapping.static_from_runtime(RuntimeVa(0x180002000)),
            Some(StaticVa(0x140002000))
        );
    }

    #[test]
    fn address_kind_keeps_location_distinct_from_content() {
        let location = RuntimeVa(0x180001018);
        let content = MemoryContent(0x180002000);
        assert_ne!(location.get(), content.get());
    }

    #[test]
    fn conversion_rejects_underflow_and_overflow() {
        let mapping = AddressMapping {
            static_image_base: StaticVa(u64::MAX - 1),
            runtime_image_base: RuntimeVa(0x1000),
        };
        assert_eq!(mapping.rva_from_runtime(RuntimeVa(0xfff)), None);
        assert_eq!(mapping.static_from_rva(Rva(2)), None);
    }
}
