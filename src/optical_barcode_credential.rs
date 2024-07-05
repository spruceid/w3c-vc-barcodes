use std::collections::HashMap;

use iref::UriBuf;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use ssi::{
    claims::{
        data_integrity::{
            suites::ecdsa_rdfc_2019::ES256OrES384, CryptographicSuite, DataIntegrity, ProofOptions,
        },
        vc::{syntax::IdOr, v2::SpecializedJsonCredential},
        SignatureError,
    },
    security::{multibase, Multibase, MultibaseBuf},
    status::bitstring_status_list::BitstringStatusListCredential,
    verification_methods::{MessageSigner, Multikey, Signer, VerificationMethodResolver},
};

use crate::{aamva_pdf417, ecdsa_xi_2023::EcdsaXi2023};

pub type OpticalBarcodeCredential = SpecializedJsonCredential<OpticalBarcodeCredentialSubject>;

/// Creates a new optical barcode credential.
pub async fn create<'a, S>(
    optical_data: &'a [u8],
    issuer: UriBuf,
    credential_subject: OpticalBarcodeCredentialSubject,
    status_list: Option<&BitstringStatusListCredential>,
    resolver: &impl VerificationMethodResolver<Method = Multikey>,
    signer: &S,
    options: ProofOptions<ssi::verification_methods::Multikey, ()>,
) -> Result<DataIntegrity<OpticalBarcodeCredential, EcdsaXi2023<'a>>, SignatureError>
where
    S: Signer<Multikey>,
    S::MessageSigner: MessageSigner<ES256OrES384>,
{
    let unsigned = OpticalBarcodeCredential::new(None, IdOr::Id(issuer), vec![credential_subject]);

    // unsigned.credential_status = credential_subject;

    EcdsaXi2023::default()
        .sign(unsigned, resolver, signer, options)
        .await
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum OpticalBarcodeCredentialSubject {
    AamvaDriversLicenseScannableInformation {
        /// Multibase-base64url encoded three byte/24 bit value providing
        /// information about which fields in the PDF417 are digitally signed.
        protected_component_index: MultibaseBuf,
    },
    MachineReadableZone,
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

    fn mask_of(e: aamva_pdf417::MandatoryDataElement) -> u32 {
        Self::mask_of_index(*PROTECTED_COMPONENTS_INDEXES.get(&e).unwrap())
    }

    fn contains_index(&self, i: usize) -> bool {
        self.0 & Self::mask_of_index(i) != 0
    }

    pub fn contains(&self, e: aamva_pdf417::MandatoryDataElement) -> bool {
        self.0 & Self::mask_of(e) != 0
    }

    pub fn insert(&mut self, e: aamva_pdf417::MandatoryDataElement) {
        self.0 |= Self::mask_of(e)
    }

    pub fn remove(&mut self, e: aamva_pdf417::MandatoryDataElement) {
        self.0 &= !Self::mask_of(e)
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = aamva_pdf417::MandatoryDataElement> {
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
    static ref PROTECTED_COMPONENTS_LIST: [aamva_pdf417::MandatoryDataElement; 22] = {
        let mut list = aamva_pdf417::MandatoryDataElement::LIST;
        list.sort_by_key(aamva_pdf417::MandatoryDataElement::id);
        list
    };
    static ref PROTECTED_COMPONENTS_INDEXES: HashMap<aamva_pdf417::MandatoryDataElement, usize> = {
        let mut map = HashMap::new();

        for (i, e) in PROTECTED_COMPONENTS_LIST.iter().enumerate() {
            map.insert(*e, i);
        }

        map
    };
}
