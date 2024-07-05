use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi::status::bitstring_status_list::{BitstringStatusListEntry, StatusPurpose};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub struct TerseBitstringStatusListEntry {
    pub terse_status_list_base_url: UriBuf,
    pub terse_status_list_index: u32,
}

impl TerseBitstringStatusListEntry {
    /// Creates a new terse bit-string status list entry from a
    /// [`BitstringStatusListEntry`].
    pub fn from_bitstring_status_list_entry(status: BitstringStatusListEntry) -> Self {
        todo!()
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
        let list_index = self.terse_status_list_index as usize / list_len;
        let status_list_index = self.terse_status_list_index as usize % list_len;
        let status_list_credential = UriBuf::new(
            format!(
                "{}/{status_purpose}/{list_index}",
                self.terse_status_list_base_url
            )
            .into_bytes(),
        )
        .unwrap();

        BitstringStatusListEntry::new(
            None,
            status_purpose.into(),
            status_list_credential,
            status_list_index,
        )
    }
}
