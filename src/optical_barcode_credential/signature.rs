use iref::UriBuf;
use ssi::{
    claims::{
        data_integrity::{
            suites::ecdsa_rdfc_2019::ES256OrES384, CryptographicSuite, DataIntegrity, ProofOptions,
        },
        vc::syntax::{IdOr, NonEmptyVec},
        JsonLdLoaderProvider, SignatureError,
    },
    status::bitstring_status_list::BitstringStatusListEntry,
    verification_methods::{MessageSigner, Multikey, Signer, VerificationMethodResolver},
};

use crate::{
    ecdsa_xi_2023::{EcdsaXi2023, ExtraInformation},
    terse_bitstring_status_list_entry::TerseBitstringStatusListEntry,
};

use super::{
    change_xi_lifetime, OpticalBarcodeCredential, OpticalBarcodeCredentialSubject, CONTEXT_LOADER,
};

/// Optical barcode credential signature parameters.
pub struct SignatureParameters<R, S> {
    pub resolver: R,
    pub signer: S,
    pub status: Option<Status>,
}

impl<'a, R, S> SignatureParameters<R, S> {
    pub fn new(resolver: R, signer: S, status: Option<Status>) -> Self {
        Self {
            resolver,
            signer,
            status,
        }
    }
}

/// Creates a new optical barcode credential.
///
/// See: <https://w3c-ccg.github.io/vc-barcodes/#credential-creation>
pub async fn create<'a, T, R, S>(
    optical_data: &'a [u8],
    issuer: UriBuf,
    credential_subject: T,
    options: ProofOptions<ssi::verification_methods::Multikey, ()>,
    params: SignatureParameters<R, S>,
) -> Result<DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>, SignatureError>
where
    T: OpticalBarcodeCredentialSubject,
    R: VerificationMethodResolver<Method = Multikey>,
    S: Signer<Multikey>,
    S::MessageSigner: MessageSigner<ES256OrES384>,
{
    let mut unsigned =
        OpticalBarcodeCredential::new(None, IdOr::Id(issuer), NonEmptyVec::new(credential_subject));

    if let Some(status_list) = params.status {
        unsigned.credential_status.push(
            TerseBitstringStatusListEntry::from_bitstring_status_list_entry(
                status_list.entry,
                status_list.list_len,
            )
            .map_err(SignatureError::other)?,
        )
    }

    let vc = EcdsaXi2023::<&'a [u8]>::default()
        .sign_with(
            XiSignatureEnvironment(&*CONTEXT_LOADER),
            unsigned,
            params.resolver,
            params.signer,
            options,
            ExtraInformation(optical_data),
        )
        .await?;

    Ok(change_xi_lifetime(vc))
}

struct XiSignatureEnvironment<'a, L>(&'a L);

impl<'a, L: ssi::json_ld::Loader> JsonLdLoaderProvider for XiSignatureEnvironment<'a, L> {
    type Loader = L;

    fn loader(&self) -> &Self::Loader {
        self.0
    }
}

pub struct Status {
    entry: BitstringStatusListEntry,
    list_len: usize,
}
