use std::marker::PhantomData;

use sha2::{Digest, Sha256, Sha384};
use ssi::{
    claims::data_integrity::{
        canonicalization::{
            CanonicalClaimsAndConfiguration, CanonicalizeClaimsAndConfiguration,
            HashCanonicalClaimsAndConfiguration,
        },
        signing::{Base58Btc, MultibaseSigning},
        suite::{
            standard::{HashingAlgorithm, HashingError},
            NoConfiguration,
        },
        suites::ecdsa_rdfc_2019::ES256OrES384,
        ProofConfigurationRef, StandardCryptographicSuite, TypeRef,
    },
    verification_methods::Multikey,
};

/// The `ecdsa-xi-2023` cryptosuite.
///
/// See: <https://w3c-ccg.github.io/vc-barcodes/#ecdsa-xi-2023>
#[derive(Debug, Default, Clone)]
pub struct EcdsaXi2023<'a>(PhantomData<&'a ()>);

impl<'a> StandardCryptographicSuite for EcdsaXi2023<'a> {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = EcdsaXi2023HashingAlgorithm;

    type VerificationMethod = Multikey;

    type SignatureAlgorithm = MultibaseSigning<ES256OrES384, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof("ecdsa-xi-2023")
    }
}

pub struct EcdsaXi2023HashingAlgorithm;

impl<'a> HashingAlgorithm<EcdsaXi2023<'a>> for EcdsaXi2023HashingAlgorithm {
    type Output = EcdsaXi2023Hash;

    fn hash(
        input: CanonicalClaimsAndConfiguration,
        proof_configuration: ProofConfigurationRef<EcdsaXi2023>,
        verification_method: &Multikey,
    ) -> Result<Self::Output, HashingError> {
        let optical_data: Vec<u8> = get_optical_data();

        match verification_method.public_key.codec() {
            ssi::multicodec::P256_PUB => {
                let rdf_hash = HashCanonicalClaimsAndConfiguration::<Sha256>::hash(
                    input,
                    proof_configuration,
                    verification_method,
                )?;

                let optical_data_hash: [u8; 32] = Sha256::digest(&optical_data).into();

                let mut hash = [0; 32 * 3];
                hash[..64].copy_from_slice(&rdf_hash);
                hash[64..].copy_from_slice(&optical_data_hash);

                Ok(EcdsaXi2023Hash::Sha256(hash))
            }
            ssi::multicodec::P384_PUB => {
                let rdf_hash = HashCanonicalClaimsAndConfiguration::<Sha384>::hash(
                    input,
                    proof_configuration,
                    verification_method,
                )?;

                let optical_data_hash: [u8; 48] = Sha384::digest(&optical_data).into();

                let mut hash = [0; 48 * 3];
                hash[..96].copy_from_slice(&rdf_hash);
                hash[96..].copy_from_slice(&optical_data_hash);

                Ok(EcdsaXi2023Hash::Sha384(hash))
            }
            _ => Err(HashingError::InvalidKey),
        }
    }
}

fn get_optical_data() -> Vec<u8> {
    todo!()
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
