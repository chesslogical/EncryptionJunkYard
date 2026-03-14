//! Shared constants for encryption tool
pub const MAGIC_BYTES: &[u8; 8] = b"LOCKBOX\x01";
pub const FORMAT_VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024; // 64 KB
