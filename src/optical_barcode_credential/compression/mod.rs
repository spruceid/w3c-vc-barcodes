mod encoding;
use std::io::Cursor;

use cbor_ld::{contexts::REGISTERED_CONTEXTS, IdMap};
pub use encoding::*;
mod decoding;
pub use decoding::*;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref COMPRESSION_TABLE: IdMap = {
        let mut map = IdMap::new_derived(Some(&*REGISTERED_CONTEXTS));

        let cursor = Cursor::new(include_str!("cbor-ld-compression-table.csv"));
        let mut reader = csv::Reader::from_reader(cursor);
        for (i, result) in reader.records().enumerate() {
            let record = result.unwrap();
            map.insert(record.as_slice().to_owned(), 0x8000 + i as u64);
        }

        map
    };
}
