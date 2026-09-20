//! ML-KEM (FIPS 203) — Module Lattice-based Key Encapsulation Mechanism.
//!
//! Wraps `oqs::kem::Kem` for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
//! Key sizes (bytes):
//!   ML-KEM-768  public key: 1184, secret key: 2400, ciphertext: 1088, shared secret: 32

use oqs::kem::{self, Kem};
use zeroize::Zeroizing;
use crate::CryptoError;
use serde::{Deserialize, Serialize};

/// ML-KEM security level selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlKemLevel {
    /// ML-KEM-512  — NIST level 1 (AES-128 equivalent)
    L512,
    /// ML-KEM-768  — NIST level 3 (AES-192 equivalent) — **recommended**
    L768,
    /// ML-KEM-1024 — NIST level 5 (AES-256 equivalent)
    L1024,
}

impl MlKemLevel {
    fn oqs_alg(self) -> kem::Algorithm {
        match self {
            Self::L512  => kem::Algorithm::MlKem512,
            Self::L768  => kem::Algorithm::MlKem768,
            Self::L1024 => kem::Algorithm::MlKem1024,
        }
    }
}

/// A generated ML-KEM key pair.
pub struct MlKemKeyPair {
    pub public_key: Vec<u8>,
    /// Stored in a Zeroizing container — wiped on drop.
    pub secret_key: Zeroizing<Vec<u8>>,
    pub level: MlKemLevel,
}

/// Generate a fresh ML-KEM key pair.
pub fn keygen(level: MlKemLevel) -> Result<MlKemKeyPair, CryptoError> {
    let kem = Kem::new(level.oqs_alg()).map_err(|e| CryptoError::KeyGen(e.to_string()))?;
    let (pk, sk) = kem.keypair().map_err(|e| CryptoError::KeyGen(e.to_string()))?;
    Ok(MlKemKeyPair {
        public_key: pk.into_vec(),
        secret_key: Zeroizing::new(sk.into_vec()),
        level,
    })
}

/// Encapsulate a shared secret against a public key.
/// Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(
    level: MlKemLevel,
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let kem = Kem::new(level.oqs_alg()).map_err(|e| CryptoError::Encaps(e.to_string()))?;
    let pk = kem
        .public_key_from_bytes(public_key)
        .ok_or_else(|| CryptoError::Encaps("invalid public key bytes".into()))?;
    let (ct, ss) = kem.encapsulate(&pk).map_err(|e| CryptoError::Encaps(e.to_string()))?;
    Ok((ct.into_vec(), Zeroizing::new(ss.into_vec())))
}

/// Decapsulate a ciphertext with the secret key to recover the shared secret.
pub fn decapsulate(
    level: MlKemLevel,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let kem = Kem::new(level.oqs_alg()).map_err(|e| CryptoError::Decaps(e.to_string()))?;
    let sk = kem
        .secret_key_from_bytes(secret_key)
        .ok_or_else(|| CryptoError::Decaps("invalid secret key bytes".into()))?;
    let ct = kem
        .ciphertext_from_bytes(ciphertext)
        .ok_or_else(|| CryptoError::Decaps("invalid ciphertext bytes".into()))?;
    let ss = kem.decapsulate(&sk, &ct).map_err(|e| CryptoError::Decaps(e.to_string()))?;
    Ok(Zeroizing::new(ss.into_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ml_kem_768() {
        let kp  = keygen(MlKemLevel::L768).expect("keygen");
        let (ct, ss_enc) = encapsulate(MlKemLevel::L768, &kp.public_key).expect("encaps");
        let ss_dec = decapsulate(MlKemLevel::L768, &kp.secret_key, &ct).expect("decaps");
        assert_eq!(*ss_enc, *ss_dec, "shared secrets must match");
        assert_eq!(ss_enc.len(), 32, "shared secret must be 32 bytes");
    }

    #[test]
    fn decaps_corrupted_ct_produces_random_key() {
        // FIPS 203 mandates that decapsulation with a bad ciphertext returns a
        // random-looking value rather than an error (implicit rejection).
        let kp = keygen(MlKemLevel::L768).expect("keygen");
        let (mut ct, _) = encapsulate(MlKemLevel::L768, &kp.public_key).expect("encaps");
        ct[0] ^= 0xFF; // corrupt one byte
        // Must not panic — implicit rejection path
        let result = decapsulate(MlKemLevel::L768, &kp.secret_key, &ct);
        assert!(result.is_ok(), "decaps with bad CT should use implicit rejection, not panic");
    }
}
