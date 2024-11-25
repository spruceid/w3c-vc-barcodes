use iref::UriBuf;
use ssi::{
    claims::{
        data_integrity::{CryptographicSuite, DataIntegrity, ProofOptions},
        vc::syntax::{IdOr, NonEmptyVec},
        JsonLdLoaderProvider, SignatureError,
    },
    crypto::algorithm::ES256OrES384,
    status::bitstring_status_list_20240406::BitstringStatusListEntry,
    verification_methods::{MessageSigner, Multikey, Signer, VerificationMethodResolver},
};

use crate::{
    ecdsa_xi_2023::{EcdsaXi2023, ExtraInformation},
    terse_bitstring_status_list_entry::TerseBitstringStatusListEntry,
};

use super::{OpticalBarcodeCredential, OpticalBarcodeCredentialSubject, CONTEXT_LOADER};

/// Optical barcode credential signature parameters.
pub struct SignatureParameters<R, S> {
    pub resolver: R,
    pub signer: S,
    pub status: Option<Status>,
}

impl<R, S> SignatureParameters<R, S> {
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
pub async fn create<T, R, S>(
    extra_information: &T::ExtraInformation,
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
    let optical_data = credential_subject.create_optical_data(extra_information);
    create_from_optical_data(&optical_data, issuer, credential_subject, options, params).await
}

/// Creates a new optical barcode credential.
///
/// See: <https://w3c-ccg.github.io/vc-barcodes/#credential-creation>
pub async fn create_from_optical_data<T, R, S>(
    optical_data: &[u8],
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
    let unsigned =
        OpticalBarcodeCredential::new(None, IdOr::Id(issuer), NonEmptyVec::new(credential_subject));

    sign_from_optical_data(unsigned, optical_data, options, params).await
}

pub async fn sign<'a, T, R, S>(
    unsigned: OpticalBarcodeCredential<T>,
    extra_information: &T::ExtraInformation,
    options: ProofOptions<ssi::verification_methods::Multikey, ()>,
    params: SignatureParameters<R, S>,
) -> Result<DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>, SignatureError>
where
    T: OpticalBarcodeCredentialSubject,
    R: VerificationMethodResolver<Method = Multikey>,
    S: Signer<Multikey>,
    S::MessageSigner: MessageSigner<ES256OrES384>,
{
    let optical_data = unsigned
        .credential_subjects
        .first()
        .unwrap()
        .create_optical_data(extra_information);
    sign_from_optical_data(unsigned, &optical_data, options, params).await
}

pub async fn sign_from_optical_data<T, R, S>(
    mut unsigned: OpticalBarcodeCredential<T>,
    optical_data: impl Into<Vec<u8>>,
    options: ProofOptions<ssi::verification_methods::Multikey, ()>,
    params: SignatureParameters<R, S>,
) -> Result<DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>, SignatureError>
where
    T: OpticalBarcodeCredentialSubject,
    R: VerificationMethodResolver<Method = Multikey>,
    S: Signer<Multikey>,
    S::MessageSigner: MessageSigner<ES256OrES384>,
{
    if let Some(status_list) = params.status {
        unsigned.credential_status.push(
            TerseBitstringStatusListEntry::from_bitstring_status_list_entry(
                status_list.entry,
                status_list.list_len,
            )
            .map_err(SignatureError::other)?,
        )
    }

    EcdsaXi2023
        .sign_with(
            XiSignatureEnvironment(&*CONTEXT_LOADER),
            unsigned,
            params.resolver,
            params.signer,
            options,
            ExtraInformation(optical_data.into()),
        )
        .await
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

#[cfg(test)]
mod tests {
    use ssi::{
        claims::data_integrity::ProofOptions,
        dids::{AnyDidMethod, DIDKey, DIDResolver},
        verification_methods::SingleSecretSigner,
        JWK,
    };
    use static_iref::uri;

    use crate::{create, MachineReadableZone, MRZ};

    use super::SignatureParameters;

    fn assert_send(_: impl Send) {}

    const MRZ_DATA: MRZ = [
        *b"IAUTO0000007010SRC0000000701<<",
        *b"8804192M2601058NOT<<<<<<<<<<<5",
        *b"SMITH<<JOHN<<<<<<<<<<<<<<<<<<<",
    ];

    #[async_std::test]
    async fn create_is_send() {
        let jwk = JWK::generate_p256();

        let vm = DIDKey::generate_url(&jwk).unwrap();
        let options = ProofOptions::from_method(vm.into_iri().into());

        let params = SignatureParameters::new(
            AnyDidMethod::default().into_vm_resolver(),
            SingleSecretSigner::new(jwk),
            None,
        );

        assert_send(create(
            &MRZ_DATA,
            uri!("http://example.org/issuer").to_owned(),
            MachineReadableZone {},
            options,
            params,
        ))
    }
}
