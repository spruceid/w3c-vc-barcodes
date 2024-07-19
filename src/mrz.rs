use std::collections::HashMap;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssi::security::multibase;

use crate::optical_barcode_credential::OpticalBarcodeCredentialSubject;

pub type MRZ = [[u8; 30]; 3];

#[derive(Debug, thiserror::Error)]
#[error("invalid QR code payload")]
pub struct InvalidQrCodePayload;

impl From<multibase::Error> for InvalidQrCodePayload {
    fn from(_value: multibase::Error) -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct MachineReadableZone {}

impl MachineReadableZone {
    pub fn encode_qr_code_payload(bytes: &[u8]) -> String {
        format!("VC1-{}", multibase45_encode(bytes))
    }

    pub fn decode_qr_code_payload(value: &str) -> Result<Vec<u8>, InvalidQrCodePayload> {
        let base45 = value.strip_prefix("VC1-").ok_or(InvalidQrCodePayload)?;
        multibase45_decode(base45).map_err(Into::into)
    }
}

const BASE_45_TABLE: [char; 45] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '$',
    '%', '*', '+', '-', '.', '/', ':',
];

lazy_static! {
    static ref BASE_45_REVERSE_TABLE: HashMap<char, u16> = {
        let mut table = HashMap::new();

        for (i, c) in BASE_45_TABLE.iter().enumerate() {
            table.insert(*c, i as u16);
        }

        table
    };
}

fn multibase45_encode(bytes: &[u8]) -> String {
    let mut result = String::new();
    result.push('R');
    base45_encode_to(&mut result, bytes);
    result
}

fn base45_encode_to(buffer: &mut String, bytes: &[u8]) {
    let mut bytes = bytes.iter();
    while let Some(&a) = bytes.next() {
        match bytes.next() {
            Some(&b) => {
                let mut value = (a as usize) << 8 | b as usize;
                let c = value % 45;
                value /= 45;
                let d = value % 45;
                value /= 45;
                let e = value;

                buffer.push(BASE_45_TABLE[c]);
                buffer.push(BASE_45_TABLE[d]);
                buffer.push(BASE_45_TABLE[e]);
            }
            None => {
                let mut value = a as usize;
                let c = value % 45;
                value /= 45;
                let d = value;

                buffer.push(BASE_45_TABLE[c]);
                buffer.push(BASE_45_TABLE[d]);
            }
        }
    }
}

fn multibase45_decode(value: &str) -> Result<Vec<u8>, multibase::Error> {
    if value.is_empty() {
        Err(multibase::Error::InvalidBaseString)
    } else {
        match value.as_bytes()[0] {
            b'R' => {
                let mut buffer = Vec::new();
                base45_decode_to(&mut buffer, &value[1..])?;
                Ok(buffer)
            }
            base => Err(multibase::Error::UnknownBase(base as char)),
        }
    }
}

fn base45_decode_to(bytes: &mut Vec<u8>, value: &str) -> Result<(), multibase::Error> {
    let mut chars = value.chars();

    while let Some(c) = chars.next() {
        let c = BASE_45_REVERSE_TABLE
            .get(&c)
            .ok_or(multibase::Error::InvalidBaseString)?;
        match chars.next() {
            Some(d) => {
                let d = BASE_45_REVERSE_TABLE
                    .get(&d)
                    .ok_or(multibase::Error::InvalidBaseString)?;
                match chars.next() {
                    Some(e) => {
                        let e = BASE_45_REVERSE_TABLE
                            .get(&e)
                            .ok_or(multibase::Error::InvalidBaseString)?;
                        let value = (c + d * 45)
                            .checked_add(
                                45u16
                                    .checked_mul(e * 45)
                                    .ok_or(multibase::Error::InvalidBaseString)?,
                            )
                            .ok_or(multibase::Error::InvalidBaseString)?;
                        let a = ((value & 0xff00) >> 8) as u8;
                        let b = (value & 0x00ff) as u8;
                        bytes.push(a);
                        bytes.push(b);
                    }
                    None => {
                        let a = (c + d * 45) as u8;
                        bytes.push(a);
                    }
                }
            }
            None => return Err(multibase::Error::InvalidBaseString),
        }
    }

    Ok(())
}

unsafe impl OpticalBarcodeCredentialSubject for MachineReadableZone {
    // type Context = VdlV2;
    type ExtraInformation = MRZ;

    fn create_optical_data(&self, xi: &Self::ExtraInformation) -> [u8; 32] {
        let mut canonical_data = Vec::with_capacity(28 * 3);

        canonical_data.extend(&xi[0]);
        canonical_data.push(b'\n');
        canonical_data.extend(&xi[1]);
        canonical_data.push(b'\n');
        canonical_data.extend(&xi[2]);
        canonical_data.push(b'\n');

        Sha256::digest(canonical_data).into()
    }
}
