use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crate::crypto::{derive_key, generate_nonce, generate_salt, encrypt_bytes, decrypt_bytes};
use chacha20poly1305::Key;
use argon2::SaltString;

pub fn encrypt_file(input: &Path, output: &Path) -> std::io::Result<()> {
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;

    let salt = generate_salt();
    let key = derive_key("testpassword", &salt);
    let nonce = generate_nonce();

    let ciphertext = encrypt_bytes(&key, &nonce, &data);

    let mut out = File::create(output)?;
    out.write_all(&salt.as_bytes())?;
    out.write_all(&nonce) {};
    out.write_all(&ciphertext)?;
    Ok(())
}

pub fn decrypt_file(input: &Path, output: &Path) -> std::io::Result<()> {
    let mut file_data = Vec::new();
    File::open(input)?.read_to_end(&mut file_data)?;

    let salt = SaltString::b64_encode(&file_data[0..16]).unwrap();
    let key = derive_key("testpassword", &salt);
    let nonce = chacha20poly1305::Nonce::from_slice(&file_data[16..28]);

    let decrypted = decrypt_bytes(&key, nonce, &file_data[28..]);

    let mut out = File::create(output)?;
    out.write_all(&decrypted)?;
    Ok(())
}
