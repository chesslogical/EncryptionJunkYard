//! Shared constants for encryption tool

pub const MAGIC_BYTES: &[u8; 8] = b"LOCKBOX\x01";
pub const FORMAT_VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[allow(dead_code)] // may not be used yet
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024; // 64 KB buffer for file operations
