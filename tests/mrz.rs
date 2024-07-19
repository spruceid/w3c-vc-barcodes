use json_syntax::Print;
use ssi::{
    dids::{AnyDidMethod, DIDResolver},
    verification_methods::SingleSecretSigner,
    JWK,
};
use w3c_vc_barcodes::{
    optical_barcode_credential::{self, SignatureParameters, VerificationParameters},
    verify, MachineReadableZone, MRZ,
};

mod common;
pub use common::*;

const DATA: MRZ = [
    *b"IAUTO0000007010SRC0000000701<<",
    *b"8804192M2601058NOT<<<<<<<<<<<5",
    *b"SMITH<<JOHN<<<<<<<<<<<<<<<<<<<",
];

#[async_std::test]
async fn mrz_sign() {
    let input = load_unsigned::<MachineReadableZone>("tests/mrz/unsecured.jsonld");

    let options = load_proof_configuration("tests/mrz/configuration.jsonld").into_options();

    let jwk = JWK::generate_p256();

    let params = SignatureParameters::new(
        AnyDidMethod::default().into_vm_resolver(),
        SingleSecretSigner::new(jwk),
        None,
    );

    optical_barcode_credential::sign(input, &DATA, options, params)
        .await
        .unwrap();
}

#[async_std::test]
async fn mrz_verify() {
    let vc = load_signed::<MachineReadableZone>("tests/mrz/secured.jsonld");

    let params = VerificationParameters::new(AnyDidMethod::default().into_vm_resolver());

    let result = verify(&vc, &DATA, params).await.unwrap();
    assert_eq!(result, Ok(()))
}

const COMPRESSED: &str = "d90664a50183198000198001198002189d82187618a418baa1189c18a218be18ae18c0a5189c186c18d20418dc18e218de58417a9ec7f688f60caa8c757592250b3f6d6e18419941f186e1ed4245770e687502d51d01cd2c2295e4338178a51a35c2f044a85598e15db9aef00261bc5c95a744e718e018b0";

#[async_std::test]
async fn mrz_compress() {
    let vc = load_signed::<MachineReadableZone>("tests/mrz/secured.jsonld");
    let bytes = optical_barcode_credential::encode_to_bytes(&vc).await;
    let expected_bytes = hex::decode(COMPRESSED).unwrap();
    if bytes != expected_bytes {
        eprintln!("output: {}", hex::encode(bytes));
        panic!("invalid compression")
    }
}

#[async_std::test]
async fn mrz_decompress() {
    let input = hex::decode(COMPRESSED).unwrap();
    let output = json_syntax::to_value(
        optical_barcode_credential::decode_from_bytes::<MachineReadableZone>(&input)
            .await
            .unwrap(),
    )
    .unwrap();
    let expected = json_syntax::to_value(load_signed::<MachineReadableZone>(
        "tests/mrz/secured.jsonld",
    ))
    .unwrap();
    if output != expected {
        eprintln!("output: {}", output.pretty_print());
        panic!("invalid decompression")
    }
}

const QR_CODE_PAYLOAD: &str = "VC1-RSJRPWCR803A3P0098G3A3-B02-J743853U53KGK0XJ6MKJ1OI0M.FO053.33963DN04$RAQS+4SMC8C3KM7VX4VAPL9%EILI:I1O$D:23%GJ0OUCPS0H8D2FB9D5G00U39.PXG49%SOGGB*K$Z6%GUSCLWEJ8%B95MOD0P NG-I:V8N63K53";

#[test]
fn mrz_qr_code_encode() {
    let input = hex::decode(COMPRESSED).unwrap();
    let qr_data = MachineReadableZone::encode_qr_code_payload(&input);
    assert_eq!(qr_data, QR_CODE_PAYLOAD);
}

#[test]
fn mrz_qr_code_decode() {
    let bytes = MachineReadableZone::decode_qr_code_payload(QR_CODE_PAYLOAD).unwrap();
    let hex = hex::encode(&bytes);
    assert_eq!(hex, COMPRESSED);
}
