use sha2::{Digest, Sha256, Sha384};
use ssi::{
    claims::{
        data_integrity::{
            canonicalization::CanonicalClaimsAndConfiguration,
            hashing::ConcatOutputSize,
            signing::{Base58Btc, MultibaseSigning},
            suite::{
                standard::{
                    HashingAlgorithm, HashingError, TransformationAlgorithm, TransformationError,
                    TypedTransformationAlgorithm,
                },
                ConfigurationAlgorithm, ConfigurationError,
            },
            CryptosuiteStr, ProofConfiguration, ProofConfigurationRef, ProofOptions,
            StandardCryptographicSuite, Type, TypeRef, UnsupportedProofSuite,
        },
        JsonLdLoaderProvider,
    },
    crypto::algorithm::ES256OrES384,
    json_ld::{Expandable, JsonLdNodeObject},
    rdf::{AnyLdEnvironment, LdEnvironment},
    verification_methods::{multikey, Multikey},
};
use std::marker::PhantomData;

/// The `ecdsa-xi-2023` cryptosuite.
///
/// See: <https://w3c-ccg.github.io/vc-barcodes/#ecdsa-xi-2023>
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaXi2023<X = &'static [u8]>(PhantomData<X>);

impl<X> TryFrom<Type> for EcdsaXi2023<X> {
    type Error = UnsupportedProofSuite;

    fn try_from(value: Type) -> Result<Self, Self::Error> {
        match value {
            Type::DataIntegrityProof(cryptosuite) if cryptosuite == "ecdsa-xi-2023" => {
                Ok(Self(PhantomData))
            }
            other => Err(UnsupportedProofSuite::Compact(other)),
        }
    }
}

impl<'a> StandardCryptographicSuite for EcdsaXi2023<&'a [u8]> {
    type Configuration = EcdsaXi2023ConfigurationAlgorithm;

    type Transformation = EcdsaXi2023TransformationAlgorithm;

    type Hashing = EcdsaXi2023HashingAlgorithm;

    type VerificationMethod = Multikey;

    type SignatureAlgorithm = MultibaseSigning<ES256OrES384, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("ecdsa-xi-2023").unwrap())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExtraInformation<'a>(pub &'a [u8]);

pub struct EcdsaXi2023ConfigurationAlgorithm;

impl<'a> ConfigurationAlgorithm<EcdsaXi2023<&'a [u8]>> for EcdsaXi2023ConfigurationAlgorithm {
    type InputVerificationMethod = Multikey;
    type InputSuiteOptions = ();
    type InputSignatureOptions = ExtraInformation<'a>;
    type InputVerificationOptions = ExtraInformation<'a>;
    type TransformationOptions = ExtraInformation<'a>;

    fn configure_signature(
        suite: &EcdsaXi2023<&'a [u8]>,
        proof_options: ProofOptions<Multikey, ()>,
        signature_options: ExtraInformation<'a>,
    ) -> Result<
        (
            ProofConfiguration<EcdsaXi2023<&'a [u8]>>,
            ExtraInformation<'a>,
        ),
        ConfigurationError,
    > {
        let configuration = proof_options.into_configuration(*suite)?;
        Ok((configuration, signature_options))
    }

    fn configure_verification(
        _suite: &EcdsaXi2023<&'a [u8]>,
        verification_options: &ExtraInformation<'a>,
    ) -> Result<ExtraInformation<'a>, ConfigurationError> {
        Ok(*verification_options)
    }
}

pub struct WithExtraInformation<'a, T> {
    data: T,
    extra_information: &'a [u8],
}

pub struct EcdsaXi2023TransformationAlgorithm;

impl<'a> TransformationAlgorithm<EcdsaXi2023<&'a [u8]>> for EcdsaXi2023TransformationAlgorithm {
    type Output = WithExtraInformation<'a, CanonicalClaimsAndConfiguration>;
}

impl<'a, T, C> TypedTransformationAlgorithm<EcdsaXi2023<&'a [u8]>, T, C>
    for EcdsaXi2023TransformationAlgorithm
where
    T: JsonLdNodeObject + Expandable,
    C: JsonLdLoaderProvider,
{
    async fn transform(
        context: &C,
        data: &T,
        proof_configuration: ProofConfigurationRef<'_, EcdsaXi2023<&'a [u8]>>,
        _verification_method: &Multikey,
        transformation_options: ExtraInformation<'a>,
    ) -> Result<Self::Output, TransformationError> {
        let mut ld = LdEnvironment::default();

        let expanded = data
            .expand_with(&mut ld, context.loader())
            .await
            .map_err(|e| TransformationError::JsonLdExpansion(e.to_string()))?;

        Ok(WithExtraInformation {
            data: CanonicalClaimsAndConfiguration {
                claims: ld
                    .canonical_form_of(&expanded)
                    .map_err(TransformationError::JsonLdDeserialization)?,
                configuration: proof_configuration
                    .expand(context, data)
                    .await
                    .map_err(TransformationError::ProofConfigurationExpansion)?
                    .nquads_lines(),
            },
            extra_information: transformation_options.0,
        })
    }
}

pub struct EcdsaXi2023HashingAlgorithm;

impl<'a> HashingAlgorithm<EcdsaXi2023<&'a [u8]>> for EcdsaXi2023HashingAlgorithm {
    type Output = EcdsaXi2023Hash;

    fn hash(
        input: WithExtraInformation<CanonicalClaimsAndConfiguration>,
        _proof_configuration: ProofConfigurationRef<EcdsaXi2023<&'a [u8]>>,
        verification_method: &Multikey,
    ) -> Result<Self::Output, HashingError> {
        match verification_method
            .public_key
            .decode()
            .map_err(|_| HashingError::InvalidKey)?
        {
            multikey::DecodedMultikey::P256(_) => {
                let proof_configuration_hash = input
                    .data
                    .configuration
                    .iter()
                    .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
                    .finalize();

                let claims_hash = input
                    .data
                    .claims
                    .iter()
                    .fold(Sha256::new(), |h, line| h.chain_update(line.as_bytes()))
                    .finalize();

                let rdf_hash = ConcatOutputSize::concat(proof_configuration_hash, claims_hash);

                let optical_data_hash: [u8; 32] = Sha256::digest(input.extra_information).into();

                let mut hash = [0; 32 * 3];
                hash[..64].copy_from_slice(&rdf_hash);
                hash[64..].copy_from_slice(&optical_data_hash);

                Ok(EcdsaXi2023Hash::Sha256(hash))
            }
            multikey::DecodedMultikey::P384(_) => {
                let proof_configuration_hash = input
                    .data
                    .configuration
                    .iter()
                    .fold(Sha384::new(), |h, line| h.chain_update(line.as_bytes()))
                    .finalize();

                let claims_hash = input
                    .data
                    .claims
                    .iter()
                    .fold(Sha384::new(), |h, line| h.chain_update(line.as_bytes()))
                    .finalize();

                let rdf_hash = ConcatOutputSize::concat(proof_configuration_hash, claims_hash);

                let optical_data_hash: [u8; 48] = Sha384::digest(input.extra_information).into();

                let mut hash = [0; 48 * 3];
                hash[..96].copy_from_slice(&rdf_hash);
                hash[96..].copy_from_slice(&optical_data_hash);

                Ok(EcdsaXi2023Hash::Sha384(hash))
            }
            _ => Err(HashingError::InvalidKey),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EcdsaXi2023Hash {
    Sha256([u8; 32 * 3]),
    Sha384([u8; 48 * 3]),
}

impl AsRef<[u8]> for EcdsaXi2023Hash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha256(b) => b.as_ref(),
            Self::Sha384(b) => b.as_ref(),
        }
    }
}
