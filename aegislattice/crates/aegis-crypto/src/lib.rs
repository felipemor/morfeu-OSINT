//! `aegis-crypto` — Post-Quantum cryptography primitives for AegisLattice.
//!
//! Implements:
//! - ML-KEM-512/768/1024 (FIPS 203 / former Kyber) via `oqs`
//! - ML-DSA-44/65/87     (FIPS 204 / former Dilithium) via `oqs`
//! - Hybrid KEM: X25519 + ML-KEM-768 for TLS 1.3 key exchange
//!   (IETF draft-ietf-tls-hybrid-design-09)
//!
//! All secret key material is wrapped in `Zeroizing<Vec<u8>>` so it is
//! wiped from memory on drop.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod hybrid;
pub mod mlkem;
pub mod mldsa;
pub mod risk;

use thiserror::Error;

/// Errors produced by the crypto layer.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGen(String),
    #[error("Encapsulation failed: {0}")]
    Encaps(String),
    #[error("Decapsulation failed: {0}")]
    Decaps(String),
    #[error("Signing failed: {0}")]
    Sign(String),
    #[error("Verification failed: {0}")]
    Verify(String),
    #[error("OQS error: {0}")]
    Oqs(String),
}
