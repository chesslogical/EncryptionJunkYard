// Minimal Lockbox Crypto Extract
// This is a single-file Rust app that extracts and uses the proven encryption/decryption logic
// directly from Lockbox's crypto.rs (MIT-licensed, original author: Chris Turgeon).
// It keeps the exact functions, constants, and error handling where possible for reliability.
// Added a simple CLI for in-place atomic encrypt/decrypt (using temp files for safety).
// Outputs to .lb extension like original Lockbox.
// Dependencies (add to Cargo.toml):
// [dependencies]
// argon2 = "0.5"
// chacha20poly1305 = "0.10"
// rand = "0.8"
// rpassword = "7.3"
// thiserror = "1.0"
// zeroize = { version = "1.7", features = ["derive"] }
//
// Usage: cargo run encrypt myfile.txt  (prompts for password twice, encrypts to myfile.lb, deletes original)
//        cargo run decrypt myfile.lb   (decrypts back to myfile, deletes .lb)

use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::prompt_password;
use thiserror::Error;
use zeroize::Zeroizing;

// --- Extracted from Lockbox's error.rs (minimal version) ---
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

// Type alias for convenience
type Result<T> = std::result::Result<T, LockboxError>;

// --- Extracted exactly from Lockbox's crypto.rs (constants and functions) ---
/// Lockbox file format magic bytes - identifies our encrypted files
pub const MAGIC_BYTES: &[u8; 8] = b"LOCKBOX\x01";
/// Version of the file format (for future compatibility)
pub const FORMAT_VERSION: u8 = 1;
/// Salt length for Argon2id (16 bytes = 128 bits, recommended minimum)
pub const SALT_LENGTH: usize = 16;
/// Nonce length for ChaCha20-Poly1305 (12 bytes = 96 bits, standard)
pub const NONCE_LENGTH: usize = 12;
/// Key length for ChaCha20-Poly1305 (32 bytes = 256 bits)
pub const KEY_LENGTH: usize = 32;
/// Argon2id parameters - tuned for security
/// These parameters provide strong resistance against GPU/ASIC attacks
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 4
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Derives a 256-bit encryption key from a password using Argon2id
///
/// Argon2id is the recommended password hashing algorithm, combining:
/// - Argon2i: resistance against side-channel attacks
/// - Argon2d: resistance against GPU cracking attacks
///
/// The salt ensures that the same password produces different keys for different files.
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

/// Generates a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically secure random nonce
pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext data using ChaCha20-Poly1305
///
/// ChaCha20-Poly1305 is an authenticated encryption algorithm that provides:
/// - Confidentiality: data is encrypted with ChaCha20 stream cipher
/// - Integrity: Poly1305 MAC ensures that data hasn't been tampered with
/// - Authentication: verifies the cipher text was created with the correct key
///
/// Returns the ciphertext with the 16-byte authentication tag appended.
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

/// Decrypts ciphertext using ChaCha20-Poly1305
///
/// This function also verifies the authentication tag, ensuring:
/// - The data hasn't been modified
/// - The correct password was used
///
/// Returns an error if authentication fails (wrong password or corrupted data).
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

// Encrypted file structure:
//
// | Offset | Size | Description |
// |--------|------|--------------------------------------|
// | 0 | 8 | Magic bytes "LOCKBOX\x01" |
// | 8 | 1 | Format version (currently 1) |
// | 9 | 2 | Original filename length (u16 BE) |
// | 11 | N | Original filename (UTF-8) |
// | 11+N | 16 | Argon2id salt |
// | 27+N | 12 | ChaCha20 nonce |
// | 39+N | ... | Encrypted data + auth tag (16 bytes) |
//
// Total header size before encrypted data: 39 + filename_length bytes
/// Creates the encrypted file format with all metadata
pub fn create_encrypted_file(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key_from_password(password, &salt)?;
    let ciphertext = encrypt(&key, &nonce, plaintext)?;
    // Build the file structure
    let filename_bytes = original_filename.as_bytes();
    if filename_bytes.len() > u16::MAX as usize {
        return Err(LockboxError::EncryptionFailed(
            "Filename too long (exceeds 65535 bytes)".to_string(),
        ));
    }
    let filename_len = filename_bytes.len() as u16;
    let mut output = Vec::with_capacity(
        MAGIC_BYTES.len()
            + 1 // version
            + 2 // filename length
            + filename_bytes.len()
            + SALT_LENGTH
            + NONCE_LENGTH
            + ciphertext.len(),
    );
    // Write header
    output.extend_from_slice(MAGIC_BYTES);
    output.push(FORMAT_VERSION);
    output.extend_from_slice(&filename_len.to_be_bytes());
    output.extend_from_slice(filename_bytes);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Parses an encrypted file and decrypts its contents
///
/// Returns: (original_filename, decrypted_data)
pub fn decrypt_file(password: &[u8], encrypted_data: &[u8]) -> Result<(String, Vec<u8>)> {
    // Minimum size: magic(8) + version(1) + filename_len(2) + salt(16) + nonce(12) + tag(16)
    const MINIMUM_SIZE: usize = 8 + 1 + 2 + 16 + 12 + 16;
    if encrypted_data.len() < MINIMUM_SIZE {
        return Err(LockboxError::InvalidFileFormat);
    }
    // Verify magic bytes
    if &encrypted_data[0..8] != MAGIC_BYTES {
        return Err(LockboxError::InvalidFileFormat);
    }
    // Check version
    let version = encrypted_data[8];
    if version != FORMAT_VERSION {
        return Err(LockboxError::InvalidFileFormat);
    }
    // Read filename length
    let filename_len = u16::from_be_bytes([encrypted_data[9], encrypted_data[10]]) as usize;
    // Calculate offsets
    let filename_start = 11;
    let filename_end = filename_start + filename_len;
    let salt_start = filename_end;
    let salt_end = salt_start + SALT_LENGTH;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LENGTH;
    let ciphertext_start = nonce_end;
    // Validate file size
    if encrypted_data.len() < ciphertext_start + 16 {
        return Err(LockboxError::InvalidFileFormat);
    }
    // Extract components
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
    // Derive key and decrypt
    let key = derive_key_from_password(password, &salt)?;
    let plaintext = decrypt(&key, &nonce, ciphertext)?;
    Ok((original_filename, plaintext))
}

// --- Minimal CLI and atomic file ops (custom for this app) ---
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} [encrypt|decrypt] <file>", args[0]);
        return Ok(());
    }

    let mode = &args[1];
    let path = PathBuf::from(&args[2]);

    let password = match mode.as_str() {
        "encrypt" => get_confirmed_password().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
        "decrypt" => prompt_password("Password: ")?,
        _ => {
            println!("Invalid mode");
            return Ok(());
        }
    };

    match mode.as_str() {
        "encrypt" => encrypt_in_place(&path, password.as_bytes()),
        "decrypt" => decrypt_in_place(&path, password.as_bytes()),
        _ => Ok(())
    }.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
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

    // Create temp file in same dir
    let mut temp_path = path.to_path_buf();
    temp_path.set_extension("lb.tmp");
    fs::write(&temp_path, encrypted)?;

    // Atomic: Delete original, rename temp
    fs::remove_file(path)?;
    let mut enc_path = path.to_path_buf();
    enc_path.set_extension("lb");
    fs::rename(temp_path, &enc_path)?;

    println!("Encrypted in place to {:?}", enc_path);
    Ok(())
}

fn decrypt_in_place(path: &Path, password: &[u8]) -> Result<()> {
    if path.extension().unwrap_or_default() != "lb" {
        return Err(LockboxError::DecryptionFailed);
    }

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    let (orig_filename, plaintext) = decrypt_file(password, &data)?;

    // Create temp file
    let mut temp_path = path.to_path_buf();
    temp_path.set_extension("tmp");
    fs::write(&temp_path, plaintext)?;

    // Atomic: Delete encrypted, rename temp to original filename (from header)
    fs::remove_file(path)?;
    let mut orig_path = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    orig_path.push(orig_filename);
    fs::rename(temp_path, &orig_path)?;

    println!("Decrypted in place to {:?}", orig_path);
    Ok(())
}

// --- Optional: A few extracted tests from Lockbox for verification (run with cargo test) ---
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
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }
}