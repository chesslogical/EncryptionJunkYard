use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::SysRng;
use rand::TryRng; // <-- ADDED THIS LINE
use rpassword::prompt_password;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum LockboxError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed - wrong password or file tampered with")]
    DecryptionFailed,
    #[error("Invalid file format")]
    InvalidFileFormat,
    #[error("Passwords do not match")]
    PasswordMismatch,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, LockboxError>;

pub const MAGIC_BYTES: &[u8; 8] = b"LOCKBOX\x01";
pub const FORMAT_VERSION: u8 = 1;
pub const SALT_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 12;
pub const KEY_LENGTH: usize = 32;

const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LENGTH),
    )
    .map_err(|e| LockboxError::EncryptionFailed(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| LockboxError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    SysRng.try_fill_bytes(&mut salt).unwrap();
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    SysRng.try_fill_bytes(&mut nonce).unwrap();
    nonce
}

pub fn encrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| LockboxError::EncryptionFailed(format!("Cipher init failed: {}", e)))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LockboxError::EncryptionFailed(format!("Encryption failed: {}", e)))
}

pub fn decrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| LockboxError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LockboxError::DecryptionFailed)
}

pub fn create_encrypted_file(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key_from_password(password, &salt)?;
    let ciphertext = encrypt(&key, &nonce, plaintext)?;

    let filename_bytes = original_filename.as_bytes();
    if filename_bytes.len() > u16::MAX as usize {
        return Err(LockboxError::EncryptionFailed(
            "Filename too long (exceeds 65535 bytes)".to_string(),
        ));
    }
    let filename_len = filename_bytes.len() as u16;

    let mut output = Vec::with_capacity(
        MAGIC_BYTES.len()
            + 1
            + 2
            + filename_bytes.len()
            + SALT_LENGTH
            + NONCE_LENGTH
            + ciphertext.len(),
    );

    output.extend_from_slice(MAGIC_BYTES);
    output.push(FORMAT_VERSION);
    output.extend_from_slice(&filename_len.to_be_bytes());
    output.extend_from_slice(filename_bytes);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_file(password: &[u8], encrypted_data: &[u8]) -> Result<(String, Vec<u8>)> {
    const MINIMUM_SIZE: usize = 8 + 1 + 2 + 16 + 12 + 16;
    if encrypted_data.len() < MINIMUM_SIZE {
        return Err(LockboxError::InvalidFileFormat);
    }

    if &encrypted_data[0..8] != MAGIC_BYTES {
        return Err(LockboxError::InvalidFileFormat);
    }

    let version = encrypted_data[8];
    if version != FORMAT_VERSION {
        return Err(LockboxError::InvalidFileFormat);
    }

    let filename_len = u16::from_be_bytes([encrypted_data[9], encrypted_data[10]]) as usize;
    let filename_start = 11;
    let filename_end = filename_start + filename_len;
    let salt_start = filename_end;
    let salt_end = salt_start + SALT_LENGTH;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LENGTH;
    let ciphertext_start = nonce_end;

    if encrypted_data.len() < ciphertext_start + 16 {
        return Err(LockboxError::InvalidFileFormat);
    }

    let filename_bytes = &encrypted_data[filename_start..filename_end];
    let original_filename =
        String::from_utf8(filename_bytes.to_vec()).map_err(|_| LockboxError::InvalidFileFormat)?;

    let salt: [u8; SALT_LENGTH] = encrypted_data[salt_start..salt_end]
        .try_into()
        .map_err(|_| LockboxError::InvalidFileFormat)?;
    let nonce: [u8; NONCE_LENGTH] = encrypted_data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| LockboxError::InvalidFileFormat)?;
    let ciphertext = &encrypted_data[ciphertext_start..];

    let key = derive_key_from_password(password, &salt)?;
    let plaintext = decrypt(&key, &nonce, ciphertext)?;

    Ok((original_filename, plaintext))
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} [encrypt|decrypt] <file>", args[0]);
        return Ok(());
    }

    let mode = &args[1];
    let path = PathBuf::from(&args[2]);

    let password = match mode.as_str() {
        "encrypt" => get_confirmed_password()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
        "decrypt" => prompt_password("Password: ")?,
        _ => {
            println!("Invalid mode");
            return Ok(());
        }
    };

    match mode.as_str() {
        "encrypt" => encrypt_in_place(&path, password.as_bytes()),
        "decrypt" => decrypt_in_place(&path, password.as_bytes()),
        _ => Ok(()),
    }
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

fn get_confirmed_password() -> Result<String> {
    loop {
        let password = prompt_password("Password: ")?;
        let confirm = prompt_password("Confirm password: ")?;
        if password == confirm {
            return Ok(password);
        }
        println!("Passwords do not match. Try again.");
    }
}

fn encrypt_in_place(path: &Path, password: &[u8]) -> Result<()> {
    if path.extension().unwrap_or_default() == "lb" {
        return Err(LockboxError::EncryptionFailed("Already encrypted".into()));
    }
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let filename = path.file_name().unwrap_or_default().to_str().unwrap_or("");
    let encrypted = create_encrypted_file(password, filename, &data)?;

    let mut temp_path = path.to_path_buf();
    temp_path.set_extension("lb.tmp");
    fs::write(&temp_path, encrypted)?;

    fs::remove_file(path)?;
    let mut enc_path = path.to_path_buf();
    enc_path.set_extension("lb");
    fs::rename(temp_path, &enc_path)?;

    println!("Encrypted to {:?}", enc_path);
    Ok(())
}

fn decrypt_in_place(path: &Path, password: &[u8]) -> Result<()> {
    if path.extension().unwrap_or_default() != "lb" {
        return Err(LockboxError::DecryptionFailed);
    }
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let (orig_filename, plaintext) = decrypt_file(password, &data)?;

    let mut temp_path = path.to_path_buf();
    temp_path.set_extension("tmp");
    fs::write(&temp_path, plaintext)?;

    fs::remove_file(path)?;
    let mut orig_path = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    orig_path.push(orig_filename);
    fs::rename(temp_path, &orig_path)?;

    println!("Decrypted to {:?}", orig_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello, World!";
        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_roundtrip() {
        let password = b"test_password_123";
        let plaintext = b"Hello, World! This is a secret message.";
        let filename = "test.txt";
        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();
        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let plaintext = b"Secret data";
        let filename = "test.txt";
        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let result = decrypt_file(wrong_password, &encrypted);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";
        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0xFF;
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }
}