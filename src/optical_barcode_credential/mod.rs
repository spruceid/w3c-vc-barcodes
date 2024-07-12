use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssi::{
    claims::{
        data_integrity::DataIntegrity,
        vc::{
            syntax::{IdOr, IdentifiedObject, RequiredContext, RequiredType},
            v2::SpecializedJsonCredential,
        },
    },
    security::multibase,
};

use crate::{
    ecdsa_xi_2023::EcdsaXi2023, terse_bitstring_status_list_entry::TerseBitstringStatusListEntry,
};

mod contexts;
pub use contexts::*;
mod signature;
pub use signature::*;
mod verification;
pub use verification::*;
mod compression;
pub use compression::*;

mod aamva;
pub use aamva::*;

/// Optical barcode credential.
///
/// See: <https://w3c-ccg.github.io/vc-barcodes/#opticalbarcodecredential>
pub type OpticalBarcodeCredential<T> = SpecializedJsonCredential<
    T,
    <T as OpticalBarcodeCredentialSubject>::Context,
    OpticalBarcodeCredentialType,
    IdOr<IdentifiedObject>,
    TerseBitstringStatusListEntry,
>;

pub struct OpticalBarcodeCredentialType;

impl RequiredType for OpticalBarcodeCredentialType {
    const REQUIRED_TYPE: &'static str = "OpticalBarcodeCredential";
}

/// Credential subject type for an optical barcode credential.
///
/// # Safety
///
/// This must be either
///   - [`AamvaDriversLicenseScannableInformation`], or
///   - [`MachineReadableZone`].
pub unsafe trait OpticalBarcodeCredentialSubject: Serialize + DeserializeOwned {
    type Context: RequiredContext;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct MachineReadableZone {}

impl MachineReadableZone {
    pub fn encode_data(bytes: &[u8]) -> String {
        format!("VC1-{}", multibase::Base::Base32Upper.encode(bytes))
    }
}

unsafe impl OpticalBarcodeCredentialSubject for MachineReadableZone {
    type Context = VdlV2;
}

pub fn change_xi_lifetime<'a, 'b, T: OpticalBarcodeCredentialSubject>(
    vc: DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'a [u8]>>,
) -> DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'b [u8]>> {
    unsafe {
        // SAFETY: the lifetime in `EcdsaXi2023` is completely unused,
        //         it does not refer any data stored in `vc`.
        std::mem::transmute::<
            DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'a [u8]>>,
            DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'b [u8]>>,
        >(vc)
    }
}

pub fn change_xi_lifetime_ref<'r, 'a, 'b, T: OpticalBarcodeCredentialSubject>(
    vc: &'r DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'a [u8]>>,
) -> &'r DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'b [u8]>> {
    unsafe {
        // SAFETY: the lifetime in `EcdsaXi2023` is completely unused,
        //         it does not refer any data stored in `vc`.
        std::mem::transmute::<
            &'r DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'a [u8]>>,
            &'r DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'b [u8]>>,
        >(vc)
    }
}
