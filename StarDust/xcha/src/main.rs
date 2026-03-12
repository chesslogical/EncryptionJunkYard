use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use tempfile;

const MAGIC_HEADER: &[u8] = b"XCHACHA_ENC_v1"; // 14 bytes
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

const MAX_FILE_SIZE: u64 = 32 * 1024 * 1024 * 1024; // 32 GiB safety limit

#[derive(Parser)]
#[command(
    name = "xcha",
    version = "0.1.0",
    about = "In-memory XChaCha20-Poly1305 encrypt/decrypt files (atomic, in-place) using key.key",
)]
struct Cli {
    /// File to encrypt/decrypt (overwritten in place)
    #[arg(index = 1)]
    file: PathBuf,

    /// Force encryption (even if already looks encrypted)
    #[arg(long)]
    force_encrypt: bool,

    /// Force decryption (even if not detected as encrypted)
    #[arg(long)]
    force_decrypt: bool,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    if !cli.file.exists() {
        eprintln!("Error: File does not exist: {:?}", cli.file);
        std::process::exit(1);
    }

    let file_size = fs::metadata(&cli.file)?.len();
    if file_size > MAX_FILE_SIZE {
        eprintln!("Error: File too large (>32 GiB).");
        std::process::exit(1);
    }

    // Load fixed 32-byte key from key.key next to the executable
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path.parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Cannot determine exe directory"))?;
    let key_path = exe_dir.join("key.key");

    let mut key_bytes = [0u8; KEY_SIZE];
    let mut key_file = File::open(&key_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Cannot open key.key: {}", e)))?;
    key_file.read_exact(&mut key_bytes)?;

    let key = chacha20poly1305::Key::from_slice(&key_bytes);

    // Read the entire input file into memory
    let mut data = Vec::with_capacity(file_size as usize + 1024);
    File::open(&cli.file)?.read_to_end(&mut data)?;

    let is_encrypted = data.starts_with(MAGIC_HEADER);

    let output_data = if cli.force_encrypt || (!cli.force_decrypt && !is_encrypted) {
        println!("Encrypting → {:?}", cli.file.display());
        encrypt(&data, &key)?
    } else if cli.force_decrypt || (!cli.force_encrypt && is_encrypted) {
        println!("Decrypting → {:?}", cli.file.display());
        decrypt(&data, &key)?
    } else {
        eprintln!("File already in desired state. Use --force-encrypt or --force-decrypt.");
        std::process::exit(1);
    };

    // Atomic overwrite: write to temp file then rename
    let parent = cli.file.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&output_data)?;
    tmp.flush()?;
    tmp.persist(&cli.file)?;

    println!("Done.");
    Ok(())
}

fn encrypt(plaintext: &[u8], key: &chacha20poly1305::Key) -> io::Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut out = Vec::with_capacity(MAGIC_HEADER.len() + NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(MAGIC_HEADER);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

fn decrypt(data: &[u8], key: &chacha20poly1305::Key) -> io::Result<Vec<u8>> {
    let min_len = MAGIC_HEADER.len() + NONCE_SIZE + TAG_SIZE;
    if data.len() < min_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File too short to be valid encrypted data",
        ));
    }

    if !data.starts_with(MAGIC_HEADER) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing magic header → not an encrypted file?",
        ));
    }

    let nonce_start = MAGIC_HEADER.len();
    let nonce = XNonce::from_slice(&data[nonce_start..nonce_start + NONCE_SIZE]);

    let ct_start = nonce_start + NONCE_SIZE;
    let ciphertext = &data[ct_start..];

    let cipher = XChaCha20Poly1305::new(key);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Decryption failed (wrong key or corrupted file?): {}", e),
            )
        })
}