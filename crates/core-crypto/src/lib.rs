pub mod admin;
pub mod ephemeral_store;
#[cfg(feature = "mls")]
pub mod mls;
pub mod padding;
pub mod policy;
pub mod protocol;
pub mod room_code;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("random number generation failed: {0}")]
    RandomFailed(String),
    #[error("invalid policy value: {0}")]
    InvalidPolicy(String),
    #[error("invalid padding or message too large: {0}")]
    PaddingError(String),
    #[error("invalid signature or unauthorized admin command: {0}")]
    InvalidSignature(String),
    #[error("replayed or out-of-order admin command sequence")]
    ReplayDetected,
    #[error("epoch mismatch in authenticated command (expected {expected}, got {got})")]
    EpochMismatch { expected: u64, got: u64 },
    #[error("room mismatch in authenticated command")]
    RoomMismatch,
    #[error("encoding or decoding error: {0}")]
    CodecError(String),
    #[error("ephemeral encryption error: {0}")]
    AeadError(String),
    #[error("MLS protocol error: {0}")]
    MlsError(String),
    #[error("admin identity verification failed: {0}")]
    AdminVerificationFailed(String),
}

/// Fills a buffer using the platform CSPRNG (OS CSPRNG on native, `crypto.getRandomValues` on WASM).
pub fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(dest).map_err(|e| CryptoError::RandomFailed(e.to_string()))
}

/// Generates a cryptographically strong URL-safe base64 token of `num_bytes` random bytes.
pub fn random_token_b64url(num_bytes: usize) -> Result<String, CryptoError> {
    let mut buf = vec![0u8; num_bytes];
    fill_random(&mut buf)?;
    let encoded = URL_SAFE_NO_PAD.encode(&buf);
    zeroize::Zeroize::zeroize(&mut buf);
    Ok(encoded)
}

/// Computes lowercase hex SHA-256 of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}
