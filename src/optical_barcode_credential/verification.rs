use ssi::{
    claims::{
        data_integrity::DataIntegrity, DateTimeProvider, JsonLdLoaderProvider,
        ProofValidationError, ResolverProvider, ResourceProvider, Verification,
    },
    status::bitstring_status_list_20240406::StatusPurpose,
    verification_methods::{Multikey, VerificationMethodResolver},
};

use crate::{
    ecdsa_xi_2023::{EcdsaXi2023, ExtraInformation},
    terse_bitstring_status_list_entry::{NoTerseStatusListProvider, TerseStatusListProvider},
    DateTime, Utc,
};

use super::{OpticalBarcodeCredential, OpticalBarcodeCredentialSubject, CONTEXT_LOADER};

/// Optical barcode credential verification parameters.
pub struct VerificationParameters<R, C = NoTerseStatusListProvider> {
    pub resolver: R,
    pub status_list_client: Option<C>,
    pub date_time: Option<DateTime<Utc>>,
}

impl<R> VerificationParameters<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            status_list_client: None,
            date_time: None,
        }
    }
}

impl<R, C> VerificationParameters<R, C> {
    pub fn new_with(resolver: R, status_list_client: C) -> Self {
        Self {
            resolver,
            status_list_client: Some(status_list_client),
            date_time: None,
        }
    }
}

pub async fn verify<T, R, C>(
    vc: &DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>,
    extra_information: &T::ExtraInformation,
    params: VerificationParameters<R, C>,
) -> Result<Verification, ProofValidationError>
where
    T: OpticalBarcodeCredentialSubject,
    R: VerificationMethodResolver<Method = Multikey>,
    C: TerseStatusListProvider,
{
    let optical_data = vc
        .credential_subjects
        .first()
        .unwrap()
        .create_optical_data(extra_information);
    verify_from_optical_data(vc, &optical_data, params).await
}

pub async fn verify_from_optical_data<T, R, C>(
    vc: &DataIntegrity<OpticalBarcodeCredential<T>, EcdsaXi2023>,
    optical_data: impl Into<Vec<u8>>,
    params: VerificationParameters<R, C>,
) -> Result<Verification, ProofValidationError>
where
    T: OpticalBarcodeCredentialSubject,
    R: VerificationMethodResolver<Method = Multikey>,
    C: TerseStatusListProvider,
{
    for terse_entry in &vc.credential_status {
        let client = params
            .status_list_client
            .as_ref()
            .ok_or_else(|| ProofValidationError::other("no status list parameters"))?;

        // let entry = terse_entry
        //     .to_bitstring_status_list_entry(status_params.list_len, status_params.status_purpose);

        let (status_purpose, status) = client
            .get_status(terse_entry)
            .await
            .map_err(ProofValidationError::other)?;

        let status = status.ok_or_else(|| ProofValidationError::other("missing status"))?;

        match status_purpose {
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
        optical_data.into(),
        ssi::claims::VerificationParameters {
            resolver: params.resolver,
            json_ld_loader: &*CONTEXT_LOADER,
            eip712_types_loader: (),
            date_time: params.date_time,
        },
    );

    vc.verify(params).await
}

struct XiVerificationParameters<P> {
    extra_information: ExtraInformation,
    params: P,
}

impl<P> XiVerificationParameters<P> {
    fn new(extra_information: Vec<u8>, params: P) -> Self {
        Self {
            extra_information: ExtraInformation(extra_information),
            params,
        }
    }
}

impl<P: DateTimeProvider> DateTimeProvider for XiVerificationParameters<P> {
    fn date_time(
        &self,
    ) -> ssi::claims::chrono::prelude::DateTime<ssi::claims::chrono::prelude::Utc> {
        self.params.date_time()
    }
}

impl<P: ResolverProvider> ResolverProvider for XiVerificationParameters<P> {
    type Resolver = P::Resolver;

    fn resolver(&self) -> &Self::Resolver {
        self.params.resolver()
    }
}

impl<P: JsonLdLoaderProvider> JsonLdLoaderProvider for XiVerificationParameters<P> {
    type Loader = P::Loader;

    fn loader(&self) -> &Self::Loader {
        self.params.loader()
    }
}

impl<P> ResourceProvider<ExtraInformation> for XiVerificationParameters<P> {
    fn get_resource(&self) -> &ExtraInformation {
        &self.extra_information
    }
}

#[cfg(test)]
mod tests {
    use ssi::dids::{AnyDidMethod, DIDResolver};

    use crate::{optical_barcode_credential::decode_from_bytes, verify, MachineReadableZone, MRZ};

    fn assert_send(_: impl Send) {}

    const MRZ_DATA: MRZ = [
        *b"IAUTO0000007010SRC0000000701<<",
        *b"8804192M2601058NOT<<<<<<<<<<<5",
        *b"SMITH<<JOHN<<<<<<<<<<<<<<<<<<<",
    ];

    const QR_CODE_PAYLOAD: &str = "VC1-RSJRPWCQ803A3P0098G1534KG$-ENXK$EM053653O53QJGZKE$9FQ$DTVD7*5$KEW:5ZQE%$E3JE34N053.33.536KGB:CM/6C73D96*CP963F63B6337B5NFBUJA 0PG9ZA4E*6*/5G0P.74+6FFHN+AFHNUWXUDN3$R46CHZJOE5NH F6UFXFPCZ10L05:8NJQJMOXSEXAKHPISA5*O6M1DF5RE73T70/L4%O4J/66QOFMFPCU.270X1X$L6HBOC81 LVMQ.$M:8U6FDX*I1Z7I6B:8GRC0%53*9EC$ILQGUVS94NQ8OQZ0BYF8NE29LAMM1SS50G5-B03";

    #[async_std::test]
    async fn verify_is_send() {
        let input = MachineReadableZone::decode_qr_code_payload(QR_CODE_PAYLOAD).unwrap();
        let vc = decode_from_bytes::<MachineReadableZone>(&input)
            .await
            .unwrap();
        let params = super::VerificationParameters::new(AnyDidMethod::default().into_vm_resolver());
        assert_send(verify(&vc, &MRZ_DATA, params))
    }
}
