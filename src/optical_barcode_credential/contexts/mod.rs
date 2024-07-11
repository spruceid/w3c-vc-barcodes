use std::collections::HashMap;

use iref::IriBuf;
use json_syntax::{Parse, Value};
use lazy_static::lazy_static;
use ssi::json_ld::RemoteDocument;
use static_iref::iri;

lazy_static! {
    pub static ref CONTEXT_LOADER: HashMap<IriBuf, RemoteDocument> = {
        let mut map = HashMap::new();

        map.insert(
            iri!("https://www.w3.org/ns/credentials/v2").to_owned(),
            load(include_str!("credentials_v2.jsonld")),
        );
        map.insert(
            iri!("https://w3id.org/citizenship/v2").to_owned(),
            load(include_str!("citizenship_v2.jsonld")),
        );

        map
    };
}

fn load(json: &str) -> RemoteDocument {
    RemoteDocument::new(None, None, Value::parse_str(json).unwrap().0)
}
