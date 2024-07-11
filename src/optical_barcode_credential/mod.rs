use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssi::claims::{
    data_integrity::DataIntegrity,
    vc::{
        syntax::{IdOr, IdentifiedObject, RequiredType},
        v2::SpecializedJsonCredential,
    },
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
pub type OpticalBarcodeCredential<T = AnyOpticalBarcodeCredentialSubject> =
    SpecializedJsonCredential<
        T,
        (),
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
///   - [`AamvaDriversLicenseScannableInformation`],
///   - [`MachineReadableZone`], or
///   - [`AnyOpticalBarcodeCredentialSubject`].
pub unsafe trait OpticalBarcodeCredentialSubject: Serialize + DeserializeOwned {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum AnyOpticalBarcodeCredentialSubject {
    AamvaDriversLicenseScannableInformation(AamvaDriversLicenseScannableInformation),
    MachineReadableZone(MachineReadableZone),
}

unsafe impl OpticalBarcodeCredentialSubject for AnyOpticalBarcodeCredentialSubject {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct MachineReadableZone {}

unsafe impl OpticalBarcodeCredentialSubject for MachineReadableZone {}

pub fn change_xi_lifetime<'a, 'b, T>(
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

pub fn change_xi_lifetime_ref<'r, 'a, 'b, T>(
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
