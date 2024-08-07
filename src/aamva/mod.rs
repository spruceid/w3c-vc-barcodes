use dlid::{
    pdf_417::{read_array, RecordEntry},
    DlMandatoryElement, DlMandatoryElements,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssi::security::{
    multibase::{self, Base},
    Multibase, MultibaseBuf,
};
use std::{collections::HashMap, io};

pub mod dlid;

use crate::optical_barcode_credential::{
    decode_from_bytes, encode_to_bytes, DecodeError, OpticalBarcodeCredentialSubject,
    VerifiableOpticalBarcodeCredential,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct AamvaDriversLicenseScannableInformation {
    /// Multibase-base64url encoded three byte/24 bit value providing
    /// information about which fields in the PDF417 are digitally signed.
    protected_component_index: EncodedProtectedComponentIndex,
}

unsafe impl OpticalBarcodeCredentialSubject for AamvaDriversLicenseScannableInformation {
    // type Context = CitizenshipV2;
    type ExtraInformation = DlMandatoryElements;

    fn create_optical_data(&self, xi: &Self::ExtraInformation) -> [u8; 32] {
        let index = self.protected_component_index.decode().unwrap();
        index.to_optical_data_bytes(xi)
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

    fn mask_of(e: DlMandatoryElement) -> u32 {
        Self::mask_of_index(*PROTECTED_COMPONENTS_INDEXES.get(&e).unwrap())
    }

    fn contains_index(&self, i: usize) -> bool {
        self.0 & Self::mask_of_index(i) != 0
    }

    pub fn contains(&self, e: DlMandatoryElement) -> bool {
        self.0 & Self::mask_of(e) != 0
    }

    pub fn insert(&mut self, e: DlMandatoryElement) {
        self.0 |= Self::mask_of(e)
    }

    pub fn remove(&mut self, e: DlMandatoryElement) {
        self.0 &= !Self::mask_of(e)
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = DlMandatoryElement> {
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

    pub fn to_optical_data_bytes(&self, elements: &DlMandatoryElements) -> [u8; 32] {
        let mut data_to_canonicalize = Vec::new();

        for field in self.iter() {
            let data = elements.get(field);

            let mut entry = Vec::with_capacity(3 + data.len() + 1);
            entry.extend(field.id());
            entry.extend(data);
            entry.push(b'\n');

            data_to_canonicalize.push(entry);
        }

        data_to_canonicalize.sort_unstable();
        let canonical_data = data_to_canonicalize.as_slice().join([].as_slice());
        Sha256::digest(canonical_data).into()
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
    pub static ref PROTECTED_COMPONENTS_LIST: [DlMandatoryElement; 22] = {
        let mut list = DlMandatoryElement::LIST;
        list.sort_by_key(DlMandatoryElement::id);
        list
    };
    pub static ref PROTECTED_COMPONENTS_INDEXES: HashMap<DlMandatoryElement, usize> = {
        let mut map = HashMap::new();

        for (i, e) in PROTECTED_COMPONENTS_LIST.iter().enumerate() {
            map.insert(*e, i);
        }

        map
    };
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use crate::aamva::dlid::DlMandatoryElement;

    use super::{dlid::DlSubfile, ProtectedComponentIndex};

    const DL_SUBFILE_BYTES: &str = "DLDACJOHN\nDADNONE\nDAG123 MAIN ST\nDAIANYVILLE\nDAJUTO\nDAKF87P20000\nDAQF987654321\nDAU069 IN\nDAYBRO\nDBA04192030\nDBB04191988\nDBC1\nDBD01012024\nDCAC\nDCBNONE\nDCDNONE\nDCFUTODOCDISCRIM\nDCGUTO\nDCSSMITH\nDDEN\nDDFN\nDDGN\r";

    lazy_static! {
        static ref DL_SUBFILE: DlSubfile = {
            use crate::aamva::dlid::pdf_417::DecodeSubfile;
            DlSubfile::decode_subfile_from_bytes(DL_SUBFILE_BYTES.as_bytes()).unwrap()
        };
    }

    /// <https://w3c-ccg.github.io/vc-barcodes/#creating-opticaldatabytes>
    #[test]
    fn creating_optical_data_bytes() {
        let expected = [
            188u8, 38, 200, 146, 227, 213, 90, 250, 50, 18, 126, 254, 47, 177, 91, 23, 64, 129,
            104, 223, 136, 81, 116, 67, 136, 125, 137, 165, 117, 63, 152, 207,
        ];

        let mut index = ProtectedComponentIndex::new();
        index.insert(DlMandatoryElement::CustomerFirstName);
        index.insert(DlMandatoryElement::CustomerFamilyName);
        index.insert(DlMandatoryElement::CustomerIdNumber);
        assert_eq!(index.into_u32(), 0b100000100000000000100000);

        let bytes = index.to_optical_data_bytes(&DL_SUBFILE.mandatory);

        assert_eq!(bytes, expected)
    }

    #[test]
    fn compress_protected_component_index() {
        let mut index = ProtectedComponentIndex::new();
        index.insert(DlMandatoryElement::CustomerFirstName);
        index.insert(DlMandatoryElement::CustomerFamilyName);
        index.insert(DlMandatoryElement::CustomerIdNumber);
        let encoded = index.encode();

        assert_eq!(encoded.as_str(), "uggAg")
    }
}

pub struct ZZSubfile {
    pub zza: String,
}

impl ZZSubfile {
    pub async fn encode_credential(
        vc: &VerifiableOpticalBarcodeCredential<AamvaDriversLicenseScannableInformation>,
    ) -> Self {
        Self {
            zza: Base::Base64UrlPad.encode(encode_to_bytes(vc).await),
        }
    }

    pub async fn decode_credential(
        &self,
    ) -> Result<
        VerifiableOpticalBarcodeCredential<AamvaDriversLicenseScannableInformation>,
        ZZDecodeError,
    > {
        let bytes = Base::Base64UrlPad.decode(&self.zza)?;
        decode_from_bytes::<AamvaDriversLicenseScannableInformation>(&bytes)
            .await
            .map_err(Into::into)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ZZDecodeError {
    #[error(transparent)]
    Base64(#[from] multibase::Error),

    #[error(transparent)]
    CborLd(#[from] DecodeError),
}

impl dlid::pdf_417::DecodeSubfile for ZZSubfile {
    fn decode_subfile(reader: &mut impl io::BufRead) -> io::Result<Self> {
        if read_array(reader)? != *b"ZZ" {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let (entry, last) = RecordEntry::decode(reader)?;

        if !last || entry.field != *b"ZZA" {
            return Err(io::ErrorKind::InvalidData.into());
        }

        Ok(Self {
            zza: String::from_utf8(entry.value).map_err(|_| io::ErrorKind::InvalidData)?,
        })
    }
}

impl From<ZZSubfile> for dlid::pdf_417::Subfile {
    fn from(value: ZZSubfile) -> Self {
        let mut data = Vec::new();
        let mut cursor = io::Cursor::new(&mut data);
        RecordEntry::encode_ref(&mut cursor, b"ZZA", value.zza.as_bytes(), true).unwrap();
        Self::new(*b"ZZ", data)
    }
}
