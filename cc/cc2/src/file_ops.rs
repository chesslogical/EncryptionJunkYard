use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::constants::*;
use crate::crypto::{derive_key, generate_nonce, generate_salt, encrypt_bytes, decrypt_bytes};
use crate::error::{LockboxError, Result};

pub fn encrypt_file(
    path: &Path,
    password: &[u8],
    memory: u32,
    iterations: u32,
    parallelism: u32,
    force: bool,
) -> Result<PathBuf> {
    if path.extension().unwrap_or_default() == "lb" && !force {
        return Err(LockboxError::EncryptionFailed("Already encrypted".into()));
    }

    let filename = path.file_name()
        .ok_or_else(|| LockboxError::InvalidFileFormat)?
        .to_string_lossy()
        .to_string();

    let salt = Zeroizing::new(generate_salt());
    let nonce = Zeroizing::new(generate_nonce());
    let key = derive_key(password, &salt[..], memory, iterations, parallelism)?;

    let filename_bytes = filename.as_bytes();
    if filename_bytes.len() > u16::MAX as usize {
        return Err(LockboxError::EncryptionFailed("Filename too long".into()));
    }
    let filename_len = filename_bytes.len() as u16;

    let mut header = Vec::new();
    header.extend_from_slice(MAGIC_BYTES);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&filename_len.to_be_bytes());
    header.extend_from_slice(filename_bytes);
    header.extend_from_slice(&salt[..]);
    header.extend_from_slice(&nonce[..]);

    let out_path = path.with_extension("lb");
    let tmp_file = NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))
        .map_err(LockboxError::Io)?;
    let mut writer = BufWriter::new(&tmp_file);

    writer.write_all(&header)?;

    let file = File::open(path).map_err(|_| LockboxError::FileNotFound(path.display().to_string()))?;
    let mut reader = BufReader::with_capacity(DEFAULT_BUFFER_SIZE, file);
    let mut buffer = vec![0u8; DEFAULT_BUFFER_SIZE];

    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 { break; }
        let ciphertext = encrypt_bytes(&buffer[..n], &key[..], &nonce[..], &header)?;
        writer.write_all(&ciphertext)?;
    }

    writer.flush()?;
    drop(writer); // release borrow
    tmp_file.persist(&out_path).map_err(|e| LockboxError::Io(e.error))?;
    Ok(out_path)
}

pub fn decrypt_file_to_path(
    path: &Path,
    password: &[u8],
    output: Option<&Path>,
    memory: u32,
    iterations: u32,
    parallelism: u32,
    _force: bool,
) -> Result<PathBuf> {
    if path.extension().unwrap_or_default() != "lb" {
        return Err(LockboxError::InvalidFileFormat);
    }

    let mut reader = BufReader::new(
        File::open(path).map_err(|_| LockboxError::FileNotFound(path.display().to_string()))?
    );

    let mut header_buf = vec![0u8; 8 + 1 + 2 + 4096];
    reader.read_exact(&mut header_buf[..11])
        .map_err(LockboxError::Io)?;
    let filename_len = u16::from_be_bytes([header_buf[9], header_buf[10]]) as usize;
    reader.read_exact(&mut header_buf[11..11 + filename_len + SALT_LEN + NONCE_LEN])
        .map_err(LockboxError::Io)?;

    let filename_bytes = &header_buf[11..11 + filename_len];
    let original_name = String::from_utf8_lossy(filename_bytes).to_string();

    let salt_start = 11 + filename_len;
    let nonce_start = salt_start + SALT_LEN;

    let salt: Zeroizing<[u8; SALT_LEN]> =
        Zeroizing::new(header_buf[salt_start..nonce_start].try_into().unwrap());
    let nonce: Zeroizing<[u8; NONCE_LEN]> =
        Zeroizing::new(header_buf[nonce_start..nonce_start + NONCE_LEN].try_into().unwrap());

    let key = derive_key(password, &salt[..], memory, iterations, parallelism)?;
    let header_len = 11 + filename_len + SALT_LEN + NONCE_LEN;
    let full_header = &header_buf[..header_len];

    let out_path = output.map_or_else(
        || path.parent().unwrap_or(Path::new(".")).join(&original_name),
        |p| p.to_path_buf()
    );

    let tmp_file = NamedTempFile::new_in(out_path.parent().unwrap_or(Path::new(".")))
        .map_err(LockboxError::Io)?;
    let mut writer = BufWriter::new(&tmp_file);
    let mut buffer = vec![0u8; DEFAULT_BUFFER_SIZE];

    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 { break; }
        let plaintext = decrypt_bytes(&buffer[..n], &key[..], &nonce[..], full_header)?;
        writer.write_all(&plaintext)?;
    }

    writer.flush()?;
    drop(writer); // release borrow
    tmp_file.persist(&out_path).map_err(|e| LockboxError::Io(e.error))?;
    Ok(out_path)
}
