use std::collections::HashMap;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use ssi::security::{multibase, Multibase, MultibaseBuf};

use crate::aamva_dlid;

use super::{CitizenshipV2, OpticalBarcodeCredentialSubject};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct AamvaDriversLicenseScannableInformation {
    /// Multibase-base64url encoded three byte/24 bit value providing
    /// information about which fields in the PDF417 are digitally signed.
    protected_component_index: EncodedProtectedComponentIndex,
}

unsafe impl OpticalBarcodeCredentialSubject for AamvaDriversLicenseScannableInformation {
    type Context = CitizenshipV2;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncodedProtectedComponentIndex(pub MultibaseBuf);

impl EncodedProtectedComponentIndex {
    pub fn encode(index: &ProtectedComponentIndex) -> Self {
        Self(index.encode())
    }

    pub fn decode(&self) -> Result<ProtectedComponentIndex, InvalidProtectedComponentIndex> {
        ProtectedComponentIndex::decode(&self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtectedComponentIndex(u32);

impl ProtectedComponentIndex {
    pub fn decode(multibase: &Multibase) -> Result<Self, InvalidProtectedComponentIndex> {
        let (_, bytes) = multibase.decode()?;
        match <[u8; 3]>::try_from(bytes) {
            Ok(b) => Ok(Self(u32::from_be_bytes([0, b[0], b[1], b[2]]))),
            Err(_) => Err(InvalidProtectedComponentIndex::Invalid),
        }
    }

    pub fn encode(&self) -> MultibaseBuf {
        let bytes = self.0.to_be_bytes();
        MultibaseBuf::encode(multibase::Base::Base64Url, &bytes[1..])
    }

    fn mask_of_index(i: usize) -> u32 {
        1u32 << i
    }

    fn mask_of(e: aamva_dlid::MandatoryDataElement) -> u32 {
        Self::mask_of_index(*PROTECTED_COMPONENTS_INDEXES.get(&e).unwrap())
    }

    fn contains_index(&self, i: usize) -> bool {
        self.0 & Self::mask_of_index(i) != 0
    }

    pub fn contains(&self, e: aamva_dlid::MandatoryDataElement) -> bool {
        self.0 & Self::mask_of(e) != 0
    }

    pub fn insert(&mut self, e: aamva_dlid::MandatoryDataElement) {
        self.0 |= Self::mask_of(e)
    }

    pub fn remove(&mut self, e: aamva_dlid::MandatoryDataElement) {
        self.0 &= !Self::mask_of(e)
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = aamva_dlid::MandatoryDataElement> {
        PROTECTED_COMPONENTS_LIST
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if self.contains_index(i) {
                    Some(*e)
                } else {
                    None
                }
            })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidProtectedComponentIndex {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error("invalid component index set")]
    Invalid,
}

lazy_static! {
    static ref PROTECTED_COMPONENTS_LIST: [aamva_dlid::MandatoryDataElement; 22] = {
        let mut list = aamva_dlid::MandatoryDataElement::LIST;
        list.sort_by_key(aamva_dlid::MandatoryDataElement::id);
        list
    };
    static ref PROTECTED_COMPONENTS_INDEXES: HashMap<aamva_dlid::MandatoryDataElement, usize> = {
        let mut map = HashMap::new();

        for (i, e) in PROTECTED_COMPONENTS_LIST.iter().enumerate() {
            map.insert(*e, i);
        }

        map
    };
}
