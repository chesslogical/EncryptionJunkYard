//! Crypto utilities: Argon2id + ChaCha20Poly1305

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use argon2::{Argon2, Algorithm, Version, Params};
use getrandom::getrandom;
use zeroize::Zeroizing;

use crate::constants::*;
use crate::error::{LockboxError, Result};

/// Derive a key from a password and salt using Argon2id
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    memory: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(memory, iterations, parallelism, Some(KEY_LEN))
        .map_err(|e| LockboxError::EncryptionFailed(format!("Argon2 params failed: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| LockboxError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

/// Generate a random salt wrapped in Zeroizing
pub fn generate_salt() -> Zeroizing<[u8; SALT_LEN]> {
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    getrandom(&mut salt[..]).expect("Failed to get random bytes");
    salt
}

/// Generate a random nonce wrapped in Zeroizing
pub fn generate_nonce() -> Zeroizing<[u8; NONCE_LEN]> {
    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    getrandom(&mut nonce[..]).expect("Failed to get random bytes");
    nonce
}

/// Encrypt plaintext with ChaCha20Poly1305
pub fn encrypt_bytes(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| LockboxError::EncryptionFailed(format!("Cipher init failed: {}", e)))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|e| LockboxError::EncryptionFailed(format!("Encryption failed: {}", e)))
}

/// Decrypt ciphertext with ChaCha20Poly1305
pub fn decrypt_bytes(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| LockboxError::DecryptionFailed)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| LockboxError::DecryptionFailed)
}
