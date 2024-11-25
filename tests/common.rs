use std::{fs, path::Path};

use iref::Uri;
use json_syntax::Parse;
use ssi::{
    claims::data_integrity::{DataIntegrity, ProofConfiguration},
    status::{
        bitstring_status_list_20240406::{BitstringStatusListCredential, StatusList, TimeToLive},
        client::{MaybeCached, ProviderError, TypedStatusMapProvider},
    },
};
use w3c_vc_barcodes::{
    optical_barcode_credential::OpticalBarcodeCredentialSubject, EcdsaXi2023,
    OpticalBarcodeCredential,
};

pub fn load_unsigned<T>(path: impl AsRef<Path>) -> OpticalBarcodeCredential<T>
where
    T: OpticalBarcodeCredentialSubject,
{
    let content = fs::read_to_string(path).unwrap();
    let json = json_syntax::Value::parse_str(&content).unwrap().0;
    json_syntax::from_value(json).unwrap()
}

pub fn load_signed<T>(
    path: impl AsRef<Path>,
) -> DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>
where
    T: OpticalBarcodeCredentialSubject,
{
    let content = fs::read_to_string(path).unwrap();
    let json = json_syntax::Value::parse_str(&content).unwrap().0;
    json_syntax::from_value(json).unwrap()
}

pub fn load_proof_configuration(path: impl AsRef<Path>) -> ProofConfiguration<EcdsaXi2023> {
    let content = fs::read_to_string(path).unwrap();
    let json = json_syntax::Value::parse_str(&content).unwrap().0;
    json_syntax::from_value(json).unwrap()
}

pub struct StatusLists;

impl TypedStatusMapProvider<Uri, BitstringStatusListCredential> for StatusLists {
    async fn get_typed(&self, id: &Uri) -> Result<MaybeCached<StatusList>, ProviderError> {
        eprintln!("fetch <{id}>");
        Ok(MaybeCached::NotCached(StatusList::from_bytes(
            1.try_into().unwrap(),
            vec![0u8; 125],
            TimeToLive::DEFAULT,
        )))
    }
}
