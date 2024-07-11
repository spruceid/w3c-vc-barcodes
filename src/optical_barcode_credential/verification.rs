use iref::Uri;
use ssi::{
    claims::{
        data_integrity::DataIntegrity, DateTimeProvider, JsonLdLoaderProvider,
        ProofValidationError, ResolverProvider, ResourceProvider, Verification,
    },
    status::bitstring_status_list::{BitstringStatusListCredential, StatusPurpose},
    verification_methods::{Multikey, VerificationMethodResolver},
};

use crate::{
    ecdsa_xi_2023::{EcdsaXi2023, ExtraInformation},
    DateTime, Utc,
};

use super::{
    change_xi_lifetime_ref, OpticalBarcodeCredential, OpticalBarcodeCredentialSubject,
    CONTEXT_LOADER,
};

/// Optical barcode credential verification parameters.
pub struct VerificationParameters<R, C = NoStatusMapProvider> {
    pub resolver: R,
    pub status: Option<StatusVerification<C>>,
    pub date_time: Option<DateTime<Utc>>,
}

impl<R> VerificationParameters<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            status: None,
            date_time: None,
        }
    }
}

impl<R, C> VerificationParameters<R, C> {
    pub fn new_with(resolver: R, status: StatusVerification<C>) -> Self {
        Self {
            resolver,
            status: Some(status),
            date_time: None,
        }
    }
}

pub async fn verify<'a, 'b, T, R, C>(
    vc: &DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'b [u8]>>,
    optical_data: &'a [u8],
    params: VerificationParameters<R, C>,
) -> Result<Verification, ProofValidationError>
where
    T: OpticalBarcodeCredentialSubject,
    R: VerificationMethodResolver<Method = Multikey>,
    C: ssi::status::client::TypedStatusMapProvider<Uri, BitstringStatusListCredential>,
{
    let vc: &DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023<&'a [u8]>> =
        change_xi_lifetime_ref(vc);

    for terse_entry in &vc.credential_status {
        let status_params = params
            .status
            .as_ref()
            .ok_or_else(|| ProofValidationError::other("no status list parameters"))?;

        let entry = terse_entry
            .to_bitstring_status_list_entry(status_params.list_len, status_params.status_purpose);

        let status_list = status_params
            .client
            .get_typed(&entry.status_list_credential)
            .await
            .map_err(ProofValidationError::other)?;

        let status = status_list
            .get(entry.status_list_index)
            .ok_or_else(|| ProofValidationError::other("missing status"))?;

        match status_params.status_purpose {
            StatusPurpose::Revocation => {
                if status != 0 {
                    return Err(ProofValidationError::other("revoked"));
                }
            }
            StatusPurpose::Suspension => {
                if status != 0 {
                    return Err(ProofValidationError::other("suspended"));
                }
            }
            StatusPurpose::Message => (),
        }
    }

    let params = XiVerificationParameters::new(
        optical_data,
        ssi::claims::VerificationParameters {
            resolver: params.resolver,
            json_ld_loader: &*CONTEXT_LOADER,
            eip712_types_loader: (),
            date_time: params.date_time,
        },
    );

    vc.verify(params).await
}

pub struct StatusVerification<C> {
    list_len: usize,
    status_purpose: StatusPurpose,
    client: C,
}

struct XiVerificationParameters<'a, P> {
    extra_information: ExtraInformation<'a>,
    params: P,
}

impl<'a, P> XiVerificationParameters<'a, P> {
    fn new(extra_information: &'a [u8], params: P) -> Self {
        Self {
            extra_information: ExtraInformation(extra_information),
            params,
        }
    }
}

impl<'a, P: DateTimeProvider> DateTimeProvider for XiVerificationParameters<'a, P> {
    fn date_time(
        &self,
    ) -> ssi::claims::chrono::prelude::DateTime<ssi::claims::chrono::prelude::Utc> {
        self.params.date_time()
    }
}

impl<'a, P: ResolverProvider> ResolverProvider for XiVerificationParameters<'a, P> {
    type Resolver = P::Resolver;

    fn resolver(&self) -> &Self::Resolver {
        self.params.resolver()
    }
}

impl<'a, P: JsonLdLoaderProvider> JsonLdLoaderProvider for XiVerificationParameters<'a, P> {
    type Loader = P::Loader;

    fn loader(&self) -> &Self::Loader {
        self.params.loader()
    }
}

impl<'a, P> ResourceProvider<ExtraInformation<'a>> for XiVerificationParameters<'a, P> {
    fn get_resource(&self) -> &ExtraInformation<'a> {
        &self.extra_information
    }
}

pub struct NoStatusMapProvider;

impl ssi::status::client::TypedStatusMapProvider<Uri, BitstringStatusListCredential>
    for NoStatusMapProvider
{
    async fn get_typed(
        &self,
        _id: &Uri,
    ) -> Result<
        ssi::status::client::MaybeCached<
            <BitstringStatusListCredential as ssi::status::EncodedStatusMap>::Decoded,
        >,
        ssi::status::client::ProviderError,
    > {
        Err(ssi::status::client::ProviderError::Internal(
            "no status map provider".to_owned(),
        ))
    }
}
