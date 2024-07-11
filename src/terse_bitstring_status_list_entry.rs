use iref::UriBuf;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use ssi::{
    claims::vc::{MaybeIdentified, Typed},
    status::bitstring_status_list::{BitstringStatusListEntry, StatusPurpose},
};

#[derive(Debug, thiserror::Error)]
pub enum IncompressibleStatusListEntry {
    #[error("missing list index")]
    MissingListIndex,

    #[error("invalid list index")]
    InvalidListIndex,

    #[error("missing status purpose")]
    MissingStatusPurpose,

    #[error("invalid status purpose")]
    InvalidStatusPurpose,

    #[error("unexpected status purpose")]
    UnexpectedStatusPurpose,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub struct TerseBitstringStatusListEntry {
    #[serde(rename = "terseStatusListBaseUrl")]
    pub base_url: UriBuf,

    #[serde(rename = "terseStatusListIndex")]
    pub index: u32,
}

impl TerseBitstringStatusListEntry {
    pub fn new(base_url: UriBuf, index: u32) -> Self {
        Self { base_url, index }
    }

    /// Creates a new terse bit-string status list entry from a
    /// [`BitstringStatusListEntry`].
    pub fn from_bitstring_status_list_entry(
        status: BitstringStatusListEntry,
        list_len: usize,
    ) -> Result<Self, IncompressibleStatusListEntry> {
        let mut terse_status_list_base_url = status.status_list_credential;

        let list_index: u32 = terse_status_list_base_url
            .path()
            .last()
            .ok_or(IncompressibleStatusListEntry::MissingListIndex)?
            .as_str()
            .parse()
            .map_err(|_| IncompressibleStatusListEntry::InvalidListIndex)?;

        terse_status_list_base_url.path_mut().pop();

        let status_purpose: StatusPurpose = terse_status_list_base_url
            .path()
            .last()
            .ok_or(IncompressibleStatusListEntry::MissingStatusPurpose)?
            .as_str()
            .parse()
            .map_err(|_| IncompressibleStatusListEntry::InvalidStatusPurpose)?;

        if status_purpose != status.status_purpose {
            return Err(IncompressibleStatusListEntry::UnexpectedStatusPurpose);
        }

        terse_status_list_base_url.path_mut().pop();

        let terse_status_list_index =
            list_index * list_len as u32 + status.status_list_index as u32;

        Ok(Self {
            base_url: terse_status_list_base_url,
            index: terse_status_list_index,
        })
    }

    /// Converts this entry into a [`BitstringStatusListEntry`].
    ///
    /// Used after verification has been performed on the verifiable credential,
    /// during the validation process.
    ///
    /// See: <https://w3c-ccg.github.io/vc-barcodes/#convert-status-list-entries>
    pub fn to_bitstring_status_list_entry(
        &self,
        list_len: usize,
        status_purpose: StatusPurpose,
    ) -> BitstringStatusListEntry {
        let list_index = self.index as usize / list_len;
        let status_list_index = self.index as usize % list_len;
        let status_list_credential =
            UriBuf::new(format!("{}/{status_purpose}/{list_index}", self.base_url).into_bytes())
                .unwrap();

        BitstringStatusListEntry::new(
            None,
            status_purpose,
            status_list_credential,
            status_list_index,
        )
    }
}

impl MaybeIdentified for TerseBitstringStatusListEntry {
    fn id(&self) -> Option<&iref::Uri> {
        None
    }
}

impl Typed for TerseBitstringStatusListEntry {
    fn types(&self) -> &[String] {
        std::slice::from_ref(&TYPE)
    }
}

lazy_static! {
    static ref TYPE: String = "TerseBitstringStatusListEntry".to_string();
}
