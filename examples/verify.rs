use ssi::dids::{AnyDidMethod, DIDResolver};
use w3c_vc_barcodes::{
    optical_barcode_credential::{decode_from_bytes, verify, VerificationParameters},
    MachineReadableZone, MRZ,
};

/// Machine Readable Zone on the card.
const MRZ_DATA: MRZ = [
    *b"IAUTO0000007010SRC0000000701<<",
    *b"8804192M2601058NOT<<<<<<<<<<<5",
    *b"SMITH<<JOHN<<<<<<<<<<<<<<<<<<<",
];

/// QR-code payload.
const QR_CODE_PAYLOAD: &str = "VC1-RSJRPWCQ803A3P0098G1534KG$-ENXK$EM053653O53QJGZKE$9FQ$DTVD7*5$KEW:5ZQE%$E3JE34N053.33.536KGB:CM/6C73D96*CP963F63B6337B5NFBUJA 0PG9ZA4E*6*/5G0P.74+6FFHN+AFHNUWXUDN3$R46CHZJOE5NH F6UFXFPCZ10L05:8NJQJMOXSEXAKHPISA5*O6M1DF5RE73T70/L4%O4J/66QOFMFPCU.270X1X$L6HBOC81 LVMQ.$M:8U6FDX*I1Z7I6B:8GRC0%53*9EC$ILQGUVS94NQ8OQZ0BYF8NE29LAMM1SS50G5-B03";

#[async_std::main]
async fn main() {
    // First we decode the QR-code payload to get the VCB in CBOR-LD form.
    let input = MachineReadableZone::decode_qr_code_payload(QR_CODE_PAYLOAD).unwrap();

    // Then we decompress the CBOR-LD VCB to get a regular JSON-LD VCB.
    let vc = decode_from_bytes::<MachineReadableZone>(&input)
        .await
        .unwrap();

    // Finally we verify the VCB against the MRZ data.
    let params = VerificationParameters::new(AnyDidMethod::default().into_vm_resolver());
    let result = verify(&vc, &MRZ_DATA, params).await.unwrap();
    assert!(result.is_ok());
}
