use json_syntax::Print;
use lazy_static::lazy_static;
use ssi::{
    dids::{AnyDidMethod, DIDResolver},
    status::bitstring_status_list::StatusPurpose,
    verification_methods::SingleSecretSigner,
    JWK,
};
use std::io::Cursor;
use w3c_vc_barcodes::{
    aamva::{
        dlid::{pdf_417, DlSubfile},
        AamvaDriversLicenseScannableInformation, ZZSubfile,
    },
    optical_barcode_credential::{self, SignatureParameters, VerificationParameters},
    terse_bitstring_status_list_entry::{ConstTerseStatusListProvider, StatusListInfo},
    verify,
};

mod common;
use common::*;

const DL_SUBFILE_BYTES: &str = "DLDACJOHN\nDADNONE\nDAG123 MAIN ST\nDAIANYVILLE\nDAJUTO\nDAKF87P20000  \nDAQF987654321\nDAU069 IN\nDAYBRO\nDBA04192030\nDBB04191988\nDBC1\nDBD01012024\nDCAC\nDCBNONE\nDCDNONE\nDCFUTODOCDISCRIM\nDCGUTO\nDCSSMITH\nDDEN\nDDFN\nDDGN\nDAW158\nDCK1234567890\nDDAN\r";

lazy_static! {
    static ref DL_SUBFILE: DlSubfile = {
        use pdf_417::DecodeSubfile;
        DlSubfile::decode_subfile_from_bytes(DL_SUBFILE_BYTES.as_bytes()).unwrap()
    };
}

#[async_std::test]
async fn aamva_sign() {
    let input =
        load_unsigned::<AamvaDriversLicenseScannableInformation>("tests/aamva/unsecured.jsonld");

    let options = load_proof_configuration("tests/aamva/configuration.jsonld").into_options();

    let jwk = JWK::generate_p256();

    let params = SignatureParameters::new(
        AnyDidMethod::default().into_vm_resolver(),
        SingleSecretSigner::new(jwk),
        None,
    );

    optical_barcode_credential::sign(input, &DL_SUBFILE.mandatory, options, params)
        .await
        .unwrap();
}

#[async_std::test]
async fn aamva_verify() {
    let vc = load_signed::<AamvaDriversLicenseScannableInformation>("tests/aamva/secured.jsonld");

    let status_list_client = ConstTerseStatusListProvider::new(
        StatusLists,
        StatusListInfo::new(1000, StatusPurpose::Revocation),
    );

    let params = VerificationParameters::new_with(
        AnyDidMethod::default().into_vm_resolver(),
        status_list_client,
    );

    let result = verify(&vc, &DL_SUBFILE.mandatory, params).await.unwrap();
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

const PDF417_PAYLOAD: &str = "@\n\x1e\rANSI 000000090002DL00410234ZZ02750202DLDAQF987654321\nDCSSMITH\nDDEN\nDACJOHN\nDDFN\nDADNONE\nDDGN\nDCAC\nDCBNONE\nDCDNONE\nDBD01012024\nDBB04191988\nDBA04192030\nDBC1\nDAU069 IN\nDAYBRO\nDAG123 MAIN ST\nDAIANYVILLE\nDAJUTO\nDAKF87P20000  \nDCFUTODOCDISCRIM\nDCGUTO\nDAW158\nDCK1234567890\nDDAN\rZZZZA2QZkpgGDGYAAGYABGYACGJ2CGHYYpBi4oxicGKYYzhiyGNAa5ZIggRi6ohicGKAYqER1ggAgGL4YqhjApRicGGwY1gQY4BjmGOJYQXq3wuVrSeLM5iGEziaBjhWosXMWRAG107uT_9bSteuPasCXFQKuPdSdF-xmUoFkA0yRJoW4ERvATNyewT263ZHMGOQYrA==\r";

#[async_std::test]
async fn aamva_pdf417_payload_decode() {
    let mut cursor = Cursor::new(PDF417_PAYLOAD);
    let mut file = pdf_417::File::new(&mut cursor).unwrap();
    let dl: DlSubfile = file.read_subfile(b"DL").unwrap().unwrap();
    let zz: ZZSubfile = file.read_subfile(b"ZZ").unwrap().unwrap();
    let vc = zz.decode_credential().await.unwrap();

    let status_list_client = ConstTerseStatusListProvider::new(
        StatusLists,
        StatusListInfo::new(1000, StatusPurpose::Revocation),
    );

    let params = VerificationParameters::new_with(
        AnyDidMethod::default().into_vm_resolver(),
        status_list_client,
    );

    let result = verify(&vc, &dl.mandatory, params).await.unwrap();
    assert_eq!(result, Ok(()))
}

#[async_std::test]
async fn aamva_pdf417_payload_encode() {
    let vc = load_signed::<AamvaDriversLicenseScannableInformation>("tests/aamva/secured.jsonld");

    let mut file = pdf_417::FileBuilder::new(0, 9, 0);
    file.push(DL_SUBFILE.clone());
    file.push(ZZSubfile::encode_credential(&vc).await);
    let bytes = file.into_bytes();

    eprintln!("result: {:?}", std::str::from_utf8(&bytes).unwrap());

    assert_eq!(bytes, PDF417_PAYLOAD.as_bytes())
}
