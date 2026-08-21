use crate::Attestation;
use sha2::{Digest, Sha256};

pub trait AttestationSigner {
    type Error;
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DigestSigner;

impl AttestationSigner for DigestSigner {
    type Error = std::convert::Infallible;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(Sha256::digest(payload).to_vec())
    }
}

pub fn canonical_attestation_bytes(attestation: &Attestation) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(attestation)
}
