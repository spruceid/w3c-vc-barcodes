use cbor_ld::{DecodeOptions, IdMap};
use ssi::claims::data_integrity::DataIntegrity;

use crate::{
    ecdsa_xi_2023::EcdsaXi2023,
    optical_barcode_credential::{OpticalBarcodeCredentialSubject, CONTEXT_LOADER},
    OpticalBarcodeCredential,
};

use super::COMPRESSION_TABLE;

fn decode_options() -> DecodeOptions {
    DecodeOptions {
        context_map: IdMap::new_derived(Some(&*COMPRESSION_TABLE)),
        ..Default::default()
    }
}

pub async fn decode<T>(
    cbor: &cbor_ld::CborValue,
) -> Result<DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>, DecodeError>
where
    T: OpticalBarcodeCredentialSubject,
{
    let json = cbor_ld::decode_with(cbor, &*CONTEXT_LOADER, decode_options()).await?;
    json_syntax::from_value(json).map_err(Into::into)
}

pub async fn decode_from_bytes<T>(
    bytes: &[u8],
) -> Result<DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>, DecodeError>
where
    T: OpticalBarcodeCredentialSubject,
{
    let json = cbor_ld::decode_from_bytes_with(bytes, &*CONTEXT_LOADER, decode_options()).await?;
    json_syntax::from_value(json).map_err(Into::into)
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error(transparent)]
    CborLd(#[from] cbor_ld::DecodeError),

    #[error(transparent)]
    Json(#[from] json_syntax::DeserializeError),
}
