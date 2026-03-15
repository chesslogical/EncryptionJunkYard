use anyhow::{anyhow, Result};
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{
    self as secretstream, Key, TAG_FINAL, TAG_MESSAGE,
};
use libsodium_rs::random;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::Path;
use zeroize::Zeroize;

pub const MAGIC: &[u8] = b"AIX8";
pub const VERSION: u8 = 1;

pub const SALT_LEN: usize = 16;

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

const ARGON2_MEM_KIB: u32 = 262144;
const ARGON2_ITER: u32 = 3;
const ARGON2_PAR: u32 = 4;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
    let params = argon2::Params::new(
        ARGON2_MEM_KIB,
        ARGON2_ITER,
        ARGON2_PAR,
        Some(secretstream::KEYBYTES),
    )
    .map_err(|e| anyhow!("Failed to create Argon2 params: {}", e))?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut key_bytes = vec![0u8; secretstream::KEYBYTES];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let key = Key::from_bytes(&key_bytes)
        .map_err(|e| anyhow!("Invalid key: {}", e))?;

    key_bytes.zeroize();

    Ok(key)
}

pub fn encrypt(input_path: &Path, temp_path: &Path, password: &str) -> Result<()> {
    let original_ext = input_path
        .extension()
        .map_or("".to_string(), |e| e.to_string_lossy().to_string());

    let ext_bytes = original_ext.as_bytes();

    if ext_bytes.len() > 255 {
        return Err(anyhow!("File extension too long"));
    }

    let ext_len = ext_bytes.len() as u8;

    let salt = random::bytes(SALT_LEN);
    let key = derive_key(password, &salt)?;

    let mut infile = BufReader::new(File::open(input_path)?);
    let mut outfile = BufWriter::new(File::create(temp_path)?);

    outfile.write_all(MAGIC)?;
    outfile.write_all(&[VERSION])?;
    outfile.write_all(&salt)?;

    let (mut push_state, header) =
        secretstream::PushState::init_push(&key)
            .map_err(|e| anyhow!("Encryption init failed: {}", e))?;

    outfile.write_all(&header)?;

    let mut meta = vec![ext_len];
    meta.extend_from_slice(ext_bytes);

    let meta_cipher = push_state
        .push(&meta, None, TAG_MESSAGE)
        .map_err(|e| anyhow!("Metadata encryption failed: {}", e))?;

    outfile.write_all(&(meta_cipher.len() as u32).to_le_bytes())?;
    outfile.write_all(&meta_cipher)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let n = infile.read(&mut buffer)?;

        if n == 0 {
            break;
        }

        let tag = if n < CHUNK_SIZE {
            TAG_FINAL
        } else {
            TAG_MESSAGE
        };

        let ciphertext = push_state
            .push(&buffer[..n], None, tag)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        outfile.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        outfile.write_all(&ciphertext)?;

        if tag == TAG_FINAL {
            break;
        }
    }

    outfile.flush()?;

    Ok(())
}

pub fn decrypt(input_path: &Path, temp_path: &Path, password: &str) -> Result<String> {
    let mut infile = File::open(input_path)?;

    let mut magic = [0u8; 4];
    infile.read_exact(&mut magic)?;

    if magic != *MAGIC {
        return Err(anyhow!("Invalid file format"));
    }

    let mut version = [0u8; 1];
    infile.read_exact(&mut version)?;

    if version[0] != VERSION {
        return Err(anyhow!("Unsupported AIX8 file version"));
    }

    let mut salt = vec![0u8; SALT_LEN];
    infile.read_exact(&mut salt)?;

    let key = derive_key(password, &salt)?;

    let mut header = [0u8; secretstream::HEADERBYTES];
    infile.read_exact(&mut header)?;

    let mut pull_state =
        secretstream::PullState::init_pull(&header, &key)
            .map_err(|e| anyhow!("Decryption init failed: {}", e))?;

    let mut reader = BufReader::new(infile);

    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let meta_len = u32::from_le_bytes(len_buf) as usize;

    let mut meta_cipher = vec![0u8; meta_len];
    reader.read_exact(&mut meta_cipher)?;

    let (meta_plain, _) = pull_state
        .pull(&meta_cipher, None)
        .map_err(|e| anyhow!("Metadata decrypt failed: {}", e))?;

    let ext_len = meta_plain[0] as usize;

    let stored_ext =
        String::from_utf8(meta_plain[1..1 + ext_len].to_vec())
            .map_err(|_| anyhow!("Invalid extension"))?;

    let mut outfile = BufWriter::new(File::create(temp_path)?);

    loop {
        match reader.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let chunk_len = u32::from_le_bytes(len_buf) as usize;

        let mut cipher = vec![0u8; chunk_len];
        reader.read_exact(&mut cipher)?;

        let (plain, tag) = pull_state
            .pull(&cipher, None)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        outfile.write_all(&plain)?;

        if tag == TAG_FINAL {
            break;
        }
    }

    outfile.flush()?;

    Ok(stored_ext)
}