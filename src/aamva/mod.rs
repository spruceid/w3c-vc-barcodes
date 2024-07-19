use std::{borrow::Cow, collections::HashMap};

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssi::security::{multibase, Multibase, MultibaseBuf};

pub mod dlid;
use dlid::MandatoryDataElement;

use crate::optical_barcode_credential::OpticalBarcodeCredentialSubject;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct AamvaDriversLicenseScannableInformation {
    /// Multibase-base64url encoded three byte/24 bit value providing
    /// information about which fields in the PDF417 are digitally signed.
    protected_component_index: EncodedProtectedComponentIndex,
}

unsafe impl OpticalBarcodeCredentialSubject for AamvaDriversLicenseScannableInformation {
    // type Context = CitizenshipV2;
    type ExtraInformation = HashMap<MandatoryDataElement, String>;

    fn create_optical_data(&self, xi: &Self::ExtraInformation) -> [u8; 32] {
        let index = self.protected_component_index.decode().unwrap();
        index.to_optical_data_bytes(|field| Cow::Borrowed(xi.get(&field).unwrap()))
    }
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

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtectedComponentIndex(u32);

impl ProtectedComponentIndex {
    pub fn new() -> Self {
        Self::default()
    }

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

    pub fn into_u32(&self) -> u32 {
        self.0
    }

    fn mask_of_index(i: usize) -> u32 {
        1u32 << (23 - i)
    }

    fn mask_of(e: MandatoryDataElement) -> u32 {
        Self::mask_of_index(*PROTECTED_COMPONENTS_INDEXES.get(&e).unwrap())
    }

    fn contains_index(&self, i: usize) -> bool {
        self.0 & Self::mask_of_index(i) != 0
    }

    pub fn contains(&self, e: MandatoryDataElement) -> bool {
        self.0 & Self::mask_of(e) != 0
    }

    pub fn insert(&mut self, e: MandatoryDataElement) {
        self.0 |= Self::mask_of(e)
    }

    pub fn remove(&mut self, e: MandatoryDataElement) {
        self.0 &= !Self::mask_of(e)
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = MandatoryDataElement> {
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

    pub fn to_optical_data_bytes<'a>(
        &self,
        fetch_data: impl Fn(MandatoryDataElement) -> Cow<'a, str>,
    ) -> [u8; 32] {
        let mut data_to_canonicalize = Vec::new();

        for field in self.iter() {
            let data = fetch_data(field);

            let mut entry = String::with_capacity(3 + data.len() + 1);
            entry.push_str(field.string_id());
            entry.push_str(&data);
            entry.push('\n');

            data_to_canonicalize.push(entry);
        }

        data_to_canonicalize.sort_unstable();

        let canonical_data = data_to_canonicalize.join("");

        eprintln!("canonical: {canonical_data:?}");

        Sha256::digest(canonical_data.as_bytes()).into()
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
    pub static ref PROTECTED_COMPONENTS_LIST: [MandatoryDataElement; 22] = {
        let mut list = MandatoryDataElement::LIST;
        list.sort_by_key(MandatoryDataElement::id);
        list
    };
    pub static ref PROTECTED_COMPONENTS_INDEXES: HashMap<MandatoryDataElement, usize> = {
        let mut map = HashMap::new();

        for (i, e) in PROTECTED_COMPONENTS_LIST.iter().enumerate() {
            map.insert(*e, i);
        }

        map
    };
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::aamva::{dlid::MandatoryDataElement, PROTECTED_COMPONENTS_INDEXES};

    use super::ProtectedComponentIndex;

    const MANDATORY_AAMVA_FIELDS: [&'static str; 22] = [
        "JOHN",
        "NONE",
        "123 MAIN ST",
        "ANYVILLE",
        "UTO",
        "F87P20000",
        "F987654321",
        "069 IN",
        "BRO",
        "04192030",
        "04191988",
        "1",
        "01012024",
        "C",
        "NONE",
        "NONE",
        "UTODOCDISCRIM",
        "UTO",
        "SMITH",
        "N",
        "N",
        "N",
    ];

    /// <https://w3c-ccg.github.io/vc-barcodes/#creating-opticaldatabytes>
    #[test]
    fn creating_optical_data_bytes() {
        let expected = [
            188u8, 38, 200, 146, 227, 213, 90, 250, 50, 18, 126, 254, 47, 177, 91, 23, 64, 129,
            104, 223, 136, 81, 116, 67, 136, 125, 137, 165, 117, 63, 152, 207,
        ];

        let mut index = ProtectedComponentIndex::new();
        index.insert(MandatoryDataElement::CustomerFirstName);
        index.insert(MandatoryDataElement::CustomerFamilyName);
        index.insert(MandatoryDataElement::CustomerIdNumber);
        assert_eq!(index.into_u32(), 0b100000100000000000100000);

        let bytes = index.to_optical_data_bytes(|field| {
            Cow::Borrowed(MANDATORY_AAMVA_FIELDS[PROTECTED_COMPONENTS_INDEXES[&field]])
        });

        assert_eq!(bytes, expected)
    }

    #[test]
    fn compress_protected_component_index() {
        let mut index = ProtectedComponentIndex::new();
        index.insert(MandatoryDataElement::CustomerFirstName);
        index.insert(MandatoryDataElement::CustomerFamilyName);
        index.insert(MandatoryDataElement::CustomerIdNumber);
        let encoded = index.encode();

        assert_eq!(encoded.as_str(), "uggAg")
    }
}
