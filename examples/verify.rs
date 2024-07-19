use ssi::dids::{AnyDidMethod, DIDResolver};
use w3c_vc_barcodes::{
    optical_barcode_credential::{decode_from_bytes, verify, VerificationParameters},
    MachineReadableZone, MRZ,
};

const DATA: MRZ = [
    *b"IAUTO0000007010SRC0000000701<<",
    *b"8804192M2601058NOT<<<<<<<<<<<5",
    *b"SMITH<<JOHN<<<<<<<<<<<<<<<<<<<",
];

const INPUT_HEX: &str = "d90664a50183198000198001198002189d82187618a418baa1189c18a218be18ae18c0a5189c186c18d20418dc18e218de58417a9ec7f688f60caa8c757592250b3f6d6e18419941f186e1ed4245770e687502d51d01cd2c2295e4338178a51a35c2f044a85598e15db9aef00261bc5c95a744e718e018b0";

#[async_std::main]
async fn main() {
    let input = hex::decode(INPUT_HEX).unwrap();
    let vc = decode_from_bytes::<MachineReadableZone>(&input)
        .await
        .unwrap();

    let params = VerificationParameters::new(AnyDidMethod::default().into_vm_resolver());

    let result = verify(&vc, &DATA, params).await.unwrap();

    assert!(result.is_ok());
}
