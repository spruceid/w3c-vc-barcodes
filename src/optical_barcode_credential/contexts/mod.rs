use std::collections::HashMap;

use iref::{Iri, IriBuf};
use json_syntax::{Parse, Value};
use lazy_static::lazy_static;
use ssi::{claims::vc::syntax::RequiredContext, json_ld::RemoteDocument};
use static_iref::iri;

lazy_static! {
    pub static ref CONTEXT_LOADER: HashMap<IriBuf, RemoteDocument> = {
        let mut map = HashMap::new();

        map.insert(
            iri!("https://www.w3.org/ns/credentials/v2").to_owned(),
            load(include_str!("credentials_v2.jsonld")),
        );
        map.insert(
            iri!("https://w3id.org/vc-barcodes/v1").to_owned(),
            load(include_str!("vc-barcodes_v1.jsonld")),
        );
        map.insert(
            iri!("https://w3id.org/utopia/v2").to_owned(),
            load(include_str!("utopia_v2.jsonld")),
        );
        map.insert(
            iri!("https://w3id.org/vdl/v2").to_owned(),
            load(include_str!("vdl_v2.jsonld")),
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

pub struct VdlV2;

impl RequiredContext for VdlV2 {
    const CONTEXT_IRI: &'static Iri = iri!("https://w3id.org/vdl/v2");
}

pub struct CitizenshipV2;

impl RequiredContext for CitizenshipV2 {
    const CONTEXT_IRI: &'static Iri = iri!("https://w3id.org/citizenship/v2");
}

pub struct VcBarcodesV1;

impl RequiredContext for VcBarcodesV1 {
    const CONTEXT_IRI: &'static Iri = iri!("https://w3id.org/vc-barcodes/v1");
}
