mod common;
use std::collections::HashMap;

use common::*;
use json_syntax::Print;
use ssi::{
    dids::{AnyDidMethod, DIDResolver},
    status::bitstring_status_list::StatusPurpose,
    verification_methods::SingleSecretSigner,
    JWK,
};
use w3c_vc_barcodes::{
    aamva::{
        dlid::MandatoryDataElement, AamvaDriversLicenseScannableInformation,
        PROTECTED_COMPONENTS_LIST,
    },
    optical_barcode_credential::{self, SignatureParameters, VerificationParameters},
    terse_bitstring_status_list_entry::{ConstTerseStatusListProvider, StatusListInfo},
    verify,
};

const MANDATORY_AAMVA_FIELDS: [&'static str; 22] = [
    "JOHN",
    "NONE",
    "123 MAIN ST",
    "ANYVILLE",
    "UTO",
    "F87P20000",
    "F987654321",
    "069 IN",
    "BRO",
    "04192030",
    "04191988",
    "1",
    "01012024",
    "C",
    "NONE",
    "NONE",
    "UTODOCDISCRIM",
    "UTO",
    "SMITH",
    "N",
    "N",
    "N",
];

fn create_extra_information() -> HashMap<MandatoryDataElement, String> {
    let mut fields = HashMap::new();

    for (i, value) in MANDATORY_AAMVA_FIELDS.into_iter().enumerate() {
        fields.insert(PROTECTED_COMPONENTS_LIST[i], value.to_owned());
    }

    fields
}

#[async_std::test]
async fn aamva_sign() {
    let input =
        load_unsigned::<AamvaDriversLicenseScannableInformation>("tests/aamva/unsecured.jsonld");
    let fields = create_extra_information();

    let options = load_proof_configuration("tests/aamva/configuration.jsonld").into_options();

    let jwk = JWK::generate_p256();

    let params = SignatureParameters::new(
        AnyDidMethod::default().into_vm_resolver(),
        SingleSecretSigner::new(jwk),
        None,
    );

    optical_barcode_credential::sign(input, &fields, options, params)
        .await
        .unwrap();
}

#[async_std::test]
async fn aamva_verify() {
    let vc = load_signed::<AamvaDriversLicenseScannableInformation>("tests/aamva/secured.jsonld");
    let fields = create_extra_information();

    let status_list_client = ConstTerseStatusListProvider::new(
        StatusLists,
        StatusListInfo::new(1000, StatusPurpose::Revocation),
    );

    let params = VerificationParameters::new_with(
        AnyDidMethod::default().into_vm_resolver(),
        status_list_client,
    );

    let result = verify(&vc, &fields, params).await.unwrap();
    assert_eq!(result, Ok(()))
}

#[async_std::test]
async fn aamva_compress() {
    let vc = load_signed::<AamvaDriversLicenseScannableInformation>("tests/aamva/secured.jsonld");
    let bytes = optical_barcode_credential::encode_to_bytes(&vc).await;
    let expected_bytes = hex::decode("d90664a60183198000198001198002189d82187618a418b8a3189c18a618ce18b218d01ae592208118baa2189c18a018a8447582002018be18aa18c0a5189c186c18d60418e018e618e258417ab7c2e56b49e2cce62184ce26818e15a8b173164401b5d3bb93ffd6d2b5eb8f6ac0971502ae3dd49d17ec66528164034c912685b8111bc04cdc9ec13dbadd91cc18e418ac").unwrap();
    if bytes != expected_bytes {
        eprintln!("output: {}", hex::encode(bytes));
        panic!("invalid compression")
    }
}

#[async_std::test]
async fn aamva_decompress() {
    let input = hex::decode("d90664a60183198000198001198002189d82187618a418b8a3189c18a618ce18b218d01ae592208118baa2189c18a018a8447582002018be18aa18c0a5189c186c18d60418e018e618e258417ab7c2e56b49e2cce62184ce26818e15a8b173164401b5d3bb93ffd6d2b5eb8f6ac0971502ae3dd49d17ec66528164034c912685b8111bc04cdc9ec13dbadd91cc18e418ac").unwrap();
    let output = json_syntax::to_value(
        optical_barcode_credential::decode_from_bytes::<AamvaDriversLicenseScannableInformation>(
            &input,
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let expected = json_syntax::to_value(load_signed::<AamvaDriversLicenseScannableInformation>(
        "tests/aamva/secured.jsonld",
    ))
    .unwrap();
    if output != expected {
        eprintln!("output: {}", output.pretty_print());
        panic!("invalid decompression")
    }
}
