// src/lib.rs
use anyhow::{anyhow, Result};
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{self as secretstream, Key, TAG_FINAL, TAG_MESSAGE};
use libsodium_rs::random;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::Path;

pub const MAGIC: &[u8] = b"AIX8";
pub const SALT_LEN: usize = 16;
const CHUNK_SIZE: usize = 1 << 20; // 1MB
const ARGON2_MEM_KIB: u32 = 65536; // 64MiB
const ARGON2_ITER: u32 = 4;
const ARGON2_PAR: u32 = 4;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
    let params = argon2::Params::new(ARGON2_MEM_KIB, ARGON2_ITER, ARGON2_PAR, Some(secretstream::KEYBYTES))
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
    Key::from_bytes(&key_bytes).map_err(|e| anyhow!("Invalid key: {}", e))
}

pub fn encrypt(input_path: &Path, temp_path: &Path, password: &str) -> Result<()> {
    let original_ext = input_path.extension().map_or("".to_string(), |e| e.to_string_lossy().to_string());
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
    outfile.write_all(&[ext_len])?;
    outfile.write_all(ext_bytes)?;
    outfile.write_all(&salt)?;

    let (mut push_state, header) = secretstream::PushState::init_push(&key).map_err(|e| anyhow!("Encryption init failed: {}", e))?;
    outfile.write_all(&header)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut done = false;
    while !done {
        let n = infile.read(&mut buffer)?;
        let tag = if n == 0 { TAG_FINAL } else if n < CHUNK_SIZE { TAG_FINAL } else { TAG_MESSAGE };
        let ciphertext = push_state.push(&buffer[..n], Some(&[]), tag).map_err(|e| anyhow!("Encryption failed: {}", e))?;
        outfile.write_all(&ciphertext)?;
        done = tag == TAG_FINAL;
    }

    outfile.flush()?;
    Ok(())
}

pub fn decrypt(input_path: &Path, temp_path: &Path, password: &str) -> Result<String> {
    let mut infile = File::open(input_path)?;
    let mut magic = [0u8; MAGIC.len()];
    infile.read_exact(&mut magic)?;
    if magic != *MAGIC {
        return Err(anyhow!("Invalid file format (magic mismatch)"));
    }

    let mut ext_len_buf = [0u8; 1];
    infile.read_exact(&mut ext_len_buf)?;
    let ext_len = ext_len_buf[0] as usize;
    let mut ext_bytes = vec![0u8; ext_len];
    infile.read_exact(&mut ext_bytes)?;
    let stored_ext = String::from_utf8(ext_bytes).map_err(|_| anyhow!("Invalid stored extension"))?;

    let mut salt = vec![0u8; SALT_LEN];
    infile.read_exact(&mut salt)?;

    let key = derive_key(password, &salt)?;

    let mut header = [0u8; secretstream::HEADERBYTES];
    infile.read_exact(&mut header)?;

    let mut pull_state = secretstream::PullState::init_pull(&header, &key).map_err(|e| anyhow!("Decryption init failed (wrong password?): {}", e))?;

    let mut outfile = BufWriter::new(File::create(temp_path)?);
    let mut reader = BufReader::new(infile);

    let mut buffer = vec![0u8; CHUNK_SIZE + secretstream::ABYTES];
    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(anyhow::Error::from(e)),
        };

        let (plaintext, tag) = pull_state.pull(&buffer[..bytes_read], Some(&[])).map_err(|e| anyhow!("Decryption failed (corrupt or wrong password): {}", e))?;
        outfile.write_all(&plaintext)?;

        if tag == TAG_FINAL {
            break;
        }
    }

    outfile.flush()?;
    Ok(stored_ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempdir::TempDir;

    fn create_test_file(path: &Path, content: &[u8]) -> Result<()> {
        let mut file = File::create(path)?;
        file.write_all(content)?;
        Ok(())
    }

    #[test]
    fn test_derive_key_consistency() -> Result<()> {
        let pw = "testpass";
        let salt = vec![0u8; SALT_LEN];
        let key1 = derive_key(pw, &salt)?;
        let key2 = derive_key(pw, &salt)?;
        assert_eq!(key1.as_ref(), key2.as_ref());
        Ok(())
    }

    #[test]
    fn test_derive_key_different_salts() -> Result<()> {
        let pw = "testpass";
        let salt1 = vec![0u8; SALT_LEN];
        let salt2 = vec![1u8; SALT_LEN];
        let key1 = derive_key(pw, &salt1)?;
        let key2 = derive_key(pw, &salt2)?;
        assert_ne!(key1.as_ref(), key2.as_ref());
        Ok(())
    }

    #[test]
    fn test_roundtrip_empty_file() -> Result<()> {
        let dir = TempDir::new("aix8_test")?;
        let input_path = dir.path().join("empty.txt");
        create_test_file(&input_path, b"")?;

        let temp_path = input_path.with_extension("tmp");
        encrypt(&input_path, &temp_path, "testpass")?;
        let encrypted_path = input_path.with_extension("ai");
        fs::rename(&temp_path, &encrypted_path)?;

        let temp_path = encrypted_path.with_extension("tmp");
        let stored_ext = decrypt(&encrypted_path, &temp_path, "testpass")?;
        assert_eq!(stored_ext, "txt");
        let decrypted_path = encrypted_path.with_extension("txt");
        fs::rename(&temp_path, &decrypted_path)?;

        let decrypted_content = fs::read(&decrypted_path)?;
        assert_eq!(decrypted_content, b"".to_vec());
        Ok(())
    }

    #[test]
    fn test_roundtrip_small_file() -> Result<()> {
        let dir = TempDir::new("aix8_test")?;
        let input_path = dir.path().join("small.txt");
        let content = b"Hello, world!";
        create_test_file(&input_path, content)?;

        let temp_path = input_path.with_extension("tmp");
        encrypt(&input_path, &temp_path, "testpass")?;
        let encrypted_path = input_path.with_extension("ai");
        fs::rename(&temp_path, &encrypted_path)?;

        let temp_path = encrypted_path.with_extension("tmp");
        let stored_ext = decrypt(&encrypted_path, &temp_path, "testpass")?;
        assert_eq!(stored_ext, "txt");
        let decrypted_path = encrypted_path.with_extension("txt");
        fs::rename(&temp_path, &decrypted_path)?;

        let decrypted_content = fs::read(&decrypted_path)?;
        assert_eq!(&decrypted_content, content);
        Ok(())
    }

    #[test]
    fn test_roundtrip_no_extension() -> Result<()> {
        let dir = TempDir::new("aix8_test")?;
        let input_path = dir.path().join("no_ext");
        let content = b"Data without ext";
        create_test_file(&input_path, content)?;

        let temp_path = input_path.with_extension("tmp");
        encrypt(&input_path, &temp_path, "testpass")?;
        let encrypted_path = input_path.with_extension("ai");
        fs::rename(&temp_path, &encrypted_path)?;

        let temp_path = encrypted_path.with_extension("tmp");
        let stored_ext = decrypt(&encrypted_path, &temp_path, "testpass")?;
        assert_eq!(stored_ext, "");
        let decrypted_path = encrypted_path.with_extension("");
        fs::rename(&temp_path, &decrypted_path)?;

        let decrypted_content = fs::read(&decrypted_path)?;
        assert_eq!(&decrypted_content, content);
        Ok(())
    }

    #[test]
    fn test_decrypt_wrong_password() -> Result<()> {
        let dir = TempDir::new("aix8_test")?;
        let input_path = dir.path().join("test.txt");
        create_test_file(&input_path, b"data")?;

        let temp_path = input_path.with_extension("tmp");
        encrypt(&input_path, &temp_path, "correctpass")?;
        let encrypted_path = input_path.with_extension("ai");
        fs::rename(&temp_path, &encrypted_path)?;

        let temp_path = encrypted_path.with_extension("tmp");
        let result = decrypt(&encrypted_path, &temp_path, "wrongpass");
        assert!(result.is_err() && result.as_ref().unwrap_err().to_string().contains("wrong password"));
        Ok(())
    }

    #[test]
    fn test_encrypt_long_extension_fails() -> Result<()> {
        let dir = TempDir::new("aix8_test")?;
        let long_ext = "a.".to_owned() + &"a".repeat(256);
        let input_path = dir.path().join(long_ext);

        let temp_path = input_path.with_extension("tmp");
        let result = encrypt(&input_path, &temp_path, "testpass");
        assert!(result.is_err() && result.as_ref().unwrap_err().to_string().contains("too long"));
        Ok(())
    }

    #[test]
    fn test_decrypt_invalid_magic() -> Result<()> {
        let dir = TempDir::new("aix8_test")?;
        let input_path = dir.path().join("invalid.ai");
        let mut file = File::create(&input_path)?;
        file.write_all(b"BADX")?;  // Wrong magic
        drop(file);

        let temp_path = input_path.with_extension("tmp");
        let result = decrypt(&input_path, &temp_path, "testpass");
        assert!(result.is_err() && result.as_ref().unwrap_err().to_string().contains("magic mismatch"));
        Ok(())
    }
}