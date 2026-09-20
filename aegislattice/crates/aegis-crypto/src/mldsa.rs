//! ML-DSA (FIPS 204) — Module Lattice-based Digital Signature Algorithm.
//! Wraps `oqs::sig::Sig` for ML-DSA-44, ML-DSA-65, and ML-DSA-87.

use oqs::sig::{self, Sig};
use zeroize::Zeroizing;
use crate::CryptoError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlDsaLevel {
    L44,
    L65,
    L87,
}

impl MlDsaLevel {
    fn oqs_alg(self) -> sig::Algorithm {
        match self {
            Self::L44 => sig::Algorithm::MlDsa44,
            Self::L65 => sig::Algorithm::MlDsa65,
            Self::L87 => sig::Algorithm::MlDsa87,
        }
    }
}

pub struct MlDsaKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
    pub level: MlDsaLevel,
}

pub fn keygen(level: MlDsaLevel) -> Result<MlDsaKeyPair, CryptoError> {
    let sig = Sig::new(level.oqs_alg()).map_err(|e| CryptoError::KeyGen(e.to_string()))?;
    let (pk, sk) = sig.keypair().map_err(|e| CryptoError::KeyGen(e.to_string()))?;
    Ok(MlDsaKeyPair { public_key: pk.into_vec(), secret_key: Zeroizing::new(sk.into_vec()), level })
}

pub fn sign(level: MlDsaLevel, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sig_obj = Sig::new(level.oqs_alg()).map_err(|e| CryptoError::Sign(e.to_string()))?;
    let sk = sig_obj.secret_key_from_bytes(secret_key)
        .ok_or_else(|| CryptoError::Sign("invalid secret key".into()))?;
    let signature = sig_obj.sign(message, &sk).map_err(|e| CryptoError::Sign(e.to_string()))?;
    Ok(signature.into_vec())
}

pub fn verify(level: MlDsaLevel, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    let sig_obj = Sig::new(level.oqs_alg()).map_err(|e| CryptoError::Verify(e.to_string()))?;
    let pk = sig_obj.public_key_from_bytes(public_key)
        .ok_or_else(|| CryptoError::Verify("invalid public key".into()))?;
    let sig = sig_obj.signature_from_bytes(signature)
        .ok_or_else(|| CryptoError::Verify("invalid signature bytes".into()))?;
    Ok(sig_obj.verify(message, &sig, &pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_ml_dsa_65() {
        let kp = keygen(MlDsaLevel::L65).expect("keygen");
        let msg = b"AegisLattice CBOM integrity proof";
        let sig = sign(MlDsaLevel::L65, &kp.secret_key, msg).expect("sign");
        assert!(verify(MlDsaLevel::L65, &kp.public_key, msg, &sig).expect("verify"));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp  = keygen(MlDsaLevel::L65).expect("keygen");
        let msg = b"original message";
        let sig = sign(MlDsaLevel::L65, &kp.secret_key, msg).expect("sign");
        assert!(!verify(MlDsaLevel::L65, &kp.public_key, b"tampered message", &sig).expect("verify"));
    }
}
