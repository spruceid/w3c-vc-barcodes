use serde::{de::DeserializeOwned, Serialize};
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

/// Optical barcode credential.
///
/// See: <https://w3c-ccg.github.io/vc-barcodes/#opticalbarcodecredential>
pub type OpticalBarcodeCredential<T> = SpecializedJsonCredential<
    T,
    VcBarcodesV1,
    OpticalBarcodeCredentialType,
    IdOr<IdentifiedObject>,
    TerseBitstringStatusListEntry,
>;

pub type VerifiableOpticalBarcodeCredential<T> =
    DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>;

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
    // type Context: RequiredContext;
    type ExtraInformation: ?Sized;

    fn create_optical_data(&self, xi: &Self::ExtraInformation) -> [u8; 32];
}
