use ssi::claims::data_integrity::DataIntegrity;

use crate::{
    ecdsa_xi_2023::EcdsaXi2023,
    optical_barcode_credential::{OpticalBarcodeCredentialSubject, CONTEXT_LOADER},
    OpticalBarcodeCredential,
};

pub async fn decode<T>(
    cbor: &cbor_ld::CborValue,
) -> Result<DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>, DecodeError>
where
    T: OpticalBarcodeCredentialSubject,
{
    let json = cbor_ld::decode(cbor, &*CONTEXT_LOADER).await?;
    json_syntax::from_value(json).map_err(Into::into)
}

pub async fn decode_from_bytes<T>(
    bytes: &[u8],
) -> Result<DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>, DecodeError>
where
    T: OpticalBarcodeCredentialSubject,
{
    let json = cbor_ld::decode_from_bytes(bytes, &*CONTEXT_LOADER).await?;
    json_syntax::from_value(json).map_err(Into::into)
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error(transparent)]
    CborLd(#[from] cbor_ld::DecodeError),

    #[error(transparent)]
    Json(#[from] json_syntax::DeserializeError),
}
