use qrcode::{render::unicode, QrCode};
use ssi::{
    claims::data_integrity::ProofOptions,
    dids::{AnyDidMethod, DIDKey, DIDResolver},
    verification_methods::SingleSecretSigner,
    JWK,
};
use static_iref::uri;
use w3c_vc_barcodes::optical_barcode_credential::{
    encode_to_bytes, MachineReadableZone, SignatureParameters,
};

const OPTICAL_DATA: &[u8] = b"TEST_OPTICAL_DATA" as &[u8];

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

    let vc = w3c_vc_barcodes::create(
        OPTICAL_DATA,
        uri!("http://example.org/issuer").to_owned(),
        MachineReadableZone {},
        options,
        params,
    )
    .await
    .unwrap();

    let bytes = encode_to_bytes(&vc).await;
    eprintln!("payload ({} bytes): {}", bytes.len(), hex::encode(&bytes));

    let qr_code = QrCode::new(MachineReadableZone::encode_data(&bytes)).unwrap();
    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{image}")
}
