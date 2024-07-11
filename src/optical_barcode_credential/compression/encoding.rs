use cbor_ld::{EncodeOptions, IdMap};
use ssi::claims::data_integrity::DataIntegrity;

use crate::{
    ecdsa_xi_2023::EcdsaXi2023,
    optical_barcode_credential::{OpticalBarcodeCredentialSubject, CONTEXT_LOADER},
    OpticalBarcodeCredential,
};

use super::COMPRESSION_TABLE;

fn encode_options() -> EncodeOptions {
    EncodeOptions {
        context_map: IdMap::new_derived(Some(&*COMPRESSION_TABLE)),
        ..Default::default()
    }
}

pub async fn encode<'a, T>(
    vc: &DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'a [u8]>>,
) -> cbor_ld::CborValue
where
    T: OpticalBarcodeCredentialSubject,
{
    let json = json_syntax::to_value(vc).unwrap();
    cbor_ld::encode_with(&json, &*CONTEXT_LOADER, encode_options())
        .await
        .unwrap()
}

pub async fn encode_to_bytes<'a, T>(
    vc: &DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'a [u8]>>,
) -> Vec<u8>
where
    T: OpticalBarcodeCredentialSubject,
{
    let json = json_syntax::to_value(vc).unwrap();
    cbor_ld::encode_to_bytes_with(&json, &*CONTEXT_LOADER, encode_options())
        .await
        .unwrap()
}
