//! Hybrid KEM — X25519 + ML-KEM-768.
//!
//! Follows IETF draft-ietf-tls-hybrid-design:
//! `SS_hybrid = KDF(SS_classical || SS_pqc || CT_pqc || PK_classical)`
//!
//! This scheme is TLS 1.3 compatible (RFC 8446 §4.2.8 extension point).

use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use ring::hkdf;
use zeroize::Zeroizing;
use crate::{mlkem, CryptoError};
use serde::{Deserialize, Serialize};

/// Combined public key for hybrid KEM.
#[derive(Debug, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// 32-byte X25519 public key
    pub x25519: Vec<u8>,
    /// 1184-byte ML-KEM-768 public key
    pub mlkem768: Vec<u8>,
}

/// Combined secret key for hybrid KEM.
pub struct HybridSecretKey {
    pub x25519: Zeroizing<[u8; 32]>,
    pub mlkem768: Zeroizing<Vec<u8>>,
}

/// Hybrid encapsulation output sent to recipient.
#[derive(Debug, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// 32-byte X25519 ephemeral public key
    pub x25519_epk: Vec<u8>,
    /// 1088-byte ML-KEM-768 ciphertext
    pub mlkem_ct: Vec<u8>,
}

/// Generate a hybrid key pair.
pub fn keygen() -> Result<(HybridPublicKey, HybridSecretKey), CryptoError> {
    // Classical
    let x_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let x_public  = X25519PublicKey::from(&x_secret);

    // PQC
    let pqc_kp = mlkem::keygen(mlkem::MlKemLevel::L768)?;

    Ok((
        HybridPublicKey {
            x25519:   x_public.as_bytes().to_vec(),
            mlkem768: pqc_kp.public_key,
        },
        HybridSecretKey {
            x25519:   Zeroizing::new(*x_secret.as_bytes()),
            mlkem768: pqc_kp.secret_key,
        },
    ))
}

/// Encapsulate — performed by the client/initiator.
/// Returns `(ciphertext, shared_secret_32_bytes)`.
pub fn encapsulate(
    recipient_pk: &HybridPublicKey,
) -> Result<(HybridCiphertext, Zeroizing<Vec<u8>>), CryptoError> {
    // Classical DH
    let ephem = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let ephem_pk = X25519PublicKey::from(&ephem);
    let their_x25519: [u8; 32] = recipient_pk.x25519
        .as_slice().try_into()
        .map_err(|_| CryptoError::Encaps("invalid X25519 public key length".into()))?;
    let ss_classical = ephem.diffie_hellman(&X25519PublicKey::from(their_x25519));

    // PQC
    let (mlkem_ct, ss_pqc) = mlkem::encapsulate(mlkem::MlKemLevel::L768, &recipient_pk.mlkem768)?;

    // Combine via HKDF-SHA256
    let combined = _hkdf_combine(
        ss_classical.as_bytes(),
        &ss_pqc,
        ephem_pk.as_bytes(),
        &recipient_pk.x25519,
    )?;

    Ok((
        HybridCiphertext {
            x25519_epk: ephem_pk.as_bytes().to_vec(),
            mlkem_ct,
        },
        combined,
    ))
}

/// Decapsulate — performed by the server/recipient.
pub fn decapsulate(
    ct: &HybridCiphertext,
    sk: &HybridSecretKey,
    our_pk_x25519: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Classical DH
    let epk_bytes: [u8; 32] = ct.x25519_epk.as_slice().try_into()
        .map_err(|_| CryptoError::Decaps("invalid X25519 ephemeral pk length".into()))?;
    let static_sk = StaticSecret::from(*sk.x25519);
    let ss_classical = static_sk.diffie_hellman(&X25519PublicKey::from(epk_bytes));

    // PQC
    let ss_pqc = mlkem::decapsulate(mlkem::MlKemLevel::L768, &sk.mlkem768, &ct.mlkem_ct)?;

    // Combine
    _hkdf_combine(ss_classical.as_bytes(), &ss_pqc, &ct.x25519_epk, our_pk_x25519)
}

fn _hkdf_combine(
    ss_classical: &[u8],
    ss_pqc: &[u8],
    epk: &[u8],
    spk: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut ikm = Vec::with_capacity(ss_classical.len() + ss_pqc.len() + epk.len() + spk.len());
    ikm.extend_from_slice(ss_classical);
    ikm.extend_from_slice(ss_pqc);
    ikm.extend_from_slice(epk);
    ikm.extend_from_slice(spk);

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"AegisLattice-HybridKEM-v1");
    let prk  = salt.extract(&ikm);
    let info = [b"hybrid-shared-secret" as &[u8]];
    let okm  = prk.expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| CryptoError::Encaps("HKDF expand failed".into()))?;
    let mut out = vec![0u8; 32];
    okm.fill(&mut out).map_err(|_| CryptoError::Encaps("HKDF fill failed".into()))?;
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_roundtrip() {
        let (pk, sk) = keygen().expect("keygen");
        let pk_x25519 = pk.x25519.clone();
        let (ct, ss_enc) = encapsulate(&pk).expect("encaps");
        let ss_dec = decapsulate(&ct, &sk, &pk_x25519).expect("decaps");
        assert_eq!(*ss_enc, *ss_dec, "hybrid shared secrets must match");
        assert_eq!(ss_enc.len(), 32);
    }
}
