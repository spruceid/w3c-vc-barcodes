use ssi::dids::{AnyDidMethod, DIDResolver};
use w3c_vc_barcodes::optical_barcode_credential::{
    decode_from_bytes, verify_from_optical_data, MachineReadableZone, VerificationParameters,
};

const OPTICAL_DATA: &[u8] = b"TEST_OPTICAL_DATA" as &[u8];
const INPUT_HEX: &str = "d90501a5018218217768747470733a2f2f773369642e6f72672f76646c2f7632189d82187618a618b4a1189c734d616368696e655265616461626c655a6f6e6518b88201726578616d706c652e6f72672f69737375657218baa6189c186c18ca821a669106d819022b18cc6d65636473612d78692d3230323318d618dc18d858417ac9c52723ae238fcb48692f30aac90b41a717788f351bbe6b0610de34f0e91701280ba9ca00a650dbd0de6eee19a59cacf482851055dd3a8ac25d3cbbb7a9f3d318da83190401582380240277f3b6df3a2b832c4f7d2555a509a11333c9f26c9fc36302d6dce6ffb59834db582380240277f3b6df3a2b832c4f7d2555a509a11333c9f26c9fc36302d6dce6ffb59834db";

#[async_std::main]
async fn main() {
    let input = hex::decode(INPUT_HEX).unwrap();
    let vc = decode_from_bytes::<MachineReadableZone>(&input)
        .await
        .unwrap();

    let params = VerificationParameters::new(AnyDidMethod::default().into_vm_resolver());

    let result = verify_from_optical_data(&vc, OPTICAL_DATA, params)
        .await
        .unwrap();

    assert!(result.is_ok());
}
