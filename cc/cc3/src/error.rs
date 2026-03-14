// src/error.rs
use thiserror::Error;
use std::io;

/// Lockbox errors
#[derive(Error, Debug)]
#[allow(dead_code)] // suppress warnings for variants not used yet
pub enum LockboxError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: incorrect password or file tampered with")]
    DecryptionFailed,

    #[error("Invalid file format")]
    InvalidFileFormat,

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("Operation cancelled by user")]
    Cancelled,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Convenient alias for results using LockboxError
pub type Result<T> = std::result::Result<T, LockboxError>;
