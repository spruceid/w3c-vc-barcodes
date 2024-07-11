//! This library provides [Verifiable Credential Barcodes v0.7][vc-barcodes]
//! based on ssi.
//!
//! [vc-barcodes]: <https://w3c-ccg.github.io/vc-barcodes/>
pub use ssi::claims::chrono::{DateTime, Utc};

pub mod aamva_dlid;
pub mod ecdsa_xi_2023;
pub mod optical_barcode_credential;
pub mod terse_bitstring_status_list_entry;

pub use ecdsa_xi_2023::EcdsaXi2023;
pub use optical_barcode_credential::{create, verify, OpticalBarcodeCredential};
