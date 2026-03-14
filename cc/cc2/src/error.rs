use thiserror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum LockboxError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: incorrect password or file tampered with")]
    DecryptionFailed,

    #[error("Invalid file format")]
    InvalidFileFormat, // used when decrypting non-.lb files

    #[error("File not found: {0}")]
    FileNotFound(String), // used when file cannot be opened

    #[error("Passwords do not match")]
    PasswordMismatch, // used in prompt_password_with_confirm

    #[error("Password cannot be empty")]
    EmptyPassword, // used in prompt_password_with_confirm

    #[error("Operation cancelled by user")]
    Cancelled, // could be used for future cancel handling

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, LockboxError>;
