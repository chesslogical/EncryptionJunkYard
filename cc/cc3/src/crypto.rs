use rand::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use argon2::{Argon2, PasswordHasher, SaltString};

pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut rand::thread_rng())
}

pub fn derive_key(password: &str, salt: &SaltString) -> Key {
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), salt).unwrap();
    let key_bytes = &hash.hash.unwrap().as_bytes()[..32];
    Key::from_slice(key_bytes).clone()
}

pub fn generate_nonce() -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    Nonce::from_slice(&nonce_bytes).clone()
}

pub fn encrypt_bytes(key: &Key, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, data).expect("encryption failed")
}

pub fn decrypt_bytes(key: &Key, nonce: &Nonce, data: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, data).expect("decryption failed")
}
