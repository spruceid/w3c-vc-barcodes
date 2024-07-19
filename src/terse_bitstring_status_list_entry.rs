use iref::{Uri, UriBuf};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use ssi::{
    claims::vc::{MaybeIdentified, Typed},
    status::{
        bitstring_status_list::{
            BitstringStatusListCredential, BitstringStatusListEntry, StatusList, StatusPurpose,
        },
        client::{MaybeCached, TypedStatusMapProvider},
    },
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
    pub fn to_bitstring_status_list_entry(&self, info: StatusListInfo) -> BitstringStatusListEntry {
        let list_index = self.index as usize / info.list_len;
        let status_list_index = self.index as usize % info.list_len;
        let status_list_credential = UriBuf::new(
            format!("{}/{}/{list_index}", self.base_url, info.status_purpose).into_bytes(),
        )
        .unwrap();

        BitstringStatusListEntry::new(
            None,
            info.status_purpose,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusListInfo {
    pub list_len: usize,
    pub status_purpose: StatusPurpose,
}

impl StatusListInfo {
    pub fn new(list_len: usize, status_purpose: StatusPurpose) -> Self {
        Self {
            list_len,
            status_purpose,
        }
    }
}

pub trait TerseStatusListProvider {
    #[allow(async_fn_in_trait)]
    async fn get(
        &self,
        terse_entry: &TerseBitstringStatusListEntry,
    ) -> Result<
        (MaybeCached<StatusList>, BitstringStatusListEntry),
        ssi::status::client::ProviderError,
    >;

    #[allow(async_fn_in_trait)]
    async fn get_status(
        &self,
        terse_entry: &TerseBitstringStatusListEntry,
    ) -> Result<(StatusPurpose, Option<u8>), ssi::status::client::ProviderError> {
        let (list, entry) = self.get(terse_entry).await?;
        let status = list.get(entry.status_list_index);
        Ok((entry.status_purpose, status))
    }
}

pub struct NoTerseStatusListProvider;

impl TerseStatusListProvider for NoTerseStatusListProvider {
    async fn get(
        &self,
        _terse_entry: &TerseBitstringStatusListEntry,
    ) -> Result<
        (MaybeCached<StatusList>, BitstringStatusListEntry),
        ssi::status::client::ProviderError,
    > {
        Err(ssi::status::client::ProviderError::Internal(
            "no status map provider".to_owned(),
        ))
    }
}

pub struct ConstTerseStatusListProvider<C> {
    pub client: C,
    pub info: StatusListInfo,
}

impl<C> ConstTerseStatusListProvider<C> {
    pub fn new(client: C, info: StatusListInfo) -> Self {
        Self { client, info }
    }
}

impl<C> TerseStatusListProvider for ConstTerseStatusListProvider<C>
where
    C: TypedStatusMapProvider<Uri, BitstringStatusListCredential>,
{
    async fn get(
        &self,
        terse_entry: &TerseBitstringStatusListEntry,
    ) -> Result<
        (MaybeCached<StatusList>, BitstringStatusListEntry),
        ssi::status::client::ProviderError,
    > {
        let entry = terse_entry.to_bitstring_status_list_entry(self.info);
        let list = self.client.get_typed(&entry.status_list_credential).await?;
        Ok((list, entry))
    }
}
