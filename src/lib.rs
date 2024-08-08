//! This library provides [Verifiable Credential Barcodes v0.7][vc-barcodes]
//! based on ssi.
//!
//! [vc-barcodes]: <https://w3c-ccg.github.io/vc-barcodes/>
//!
//! The `examples` folder contains a few examples showing how to create and
//! verify VCBs.
pub use ssi::claims::chrono::{DateTime, Utc};

pub mod aamva;
pub mod ecdsa_xi_2023;
pub mod mrz;
pub mod optical_barcode_credential;
pub mod terse_bitstring_status_list_entry;

pub use aamva::AamvaDriversLicenseScannableInformation;
pub use ecdsa_xi_2023::EcdsaXi2023;
pub use mrz::{MachineReadableZone, MRZ};
pub use optical_barcode_credential::{
    create, create_from_optical_data, verify, OpticalBarcodeCredential,
};
