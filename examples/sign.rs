use qrcode::{render::unicode, QrCode};
use ssi::{
    claims::data_integrity::ProofOptions,
    dids::{AnyDidMethod, DIDKey, DIDResolver},
    verification_methods::SingleSecretSigner,
    JWK,
};
use static_iref::uri;
use w3c_vc_barcodes::{
    optical_barcode_credential::{encode_to_bytes, SignatureParameters},
    MachineReadableZone, MRZ,
};

/// Machine Readable Zone on the card.
const MRZ_DATA: MRZ = [
    *b"IAUTO0000007010SRC0000000701<<",
    *b"8804192M2601058NOT<<<<<<<<<<<5",
    *b"SMITH<<JOHN<<<<<<<<<<<<<<<<<<<",
];

#[async_std::main]
async fn main() {
    let jwk = JWK::generate_p256();

    let vm = DIDKey::generate_url(&jwk).unwrap();
    let options = ProofOptions::from_method(vm.into_iri().into());

    let params = SignatureParameters::new(
        AnyDidMethod::default().into_vm_resolver(),
        SingleSecretSigner::new(jwk),
        None,
    );

    // Issue a JSON-LD VCB for the MRZ data.
    let vc = w3c_vc_barcodes::create(
        &MRZ_DATA,
        uri!("http://example.org/issuer").to_owned(),
        MachineReadableZone {},
        options,
        params,
    )
    .await
    .unwrap();

    // Compress the VCB using CBOR-LD.
    let bytes = encode_to_bytes(&vc).await;
    eprintln!("payload ({} bytes): {}", bytes.len(), hex::encode(&bytes));

    // Encode the QR-code payload and generate the QR-code.
    let qr_code = QrCode::new(MachineReadableZone::encode_qr_code_payload(&bytes)).unwrap();
    eprintln!(
        "QR-payload: {}",
        MachineReadableZone::encode_qr_code_payload(&bytes)
    );
    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{image}")
}
