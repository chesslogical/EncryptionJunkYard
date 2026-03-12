use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::Parser;
use rpassword::prompt_password;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};

const CHUNK_SIZE: usize = 1024 * 1024;           // 1 MiB
const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024;   // 20 GiB

#[derive(Parser)]
#[command(
    name = "stardust-keygen",
    version = "0.1.0",
    about = "Deterministic key generator: password → non-repeating key up to 20GB",
    author = "Mark"
)]
struct Cli {
    /// Key size in bytes (1 to 20GB)
    #[arg(index = 1)]
    size: u64,

    /// Output file path (default: key.key next to executable)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Salt for Argon2 key derivation (default: ultimate-salt-v1-2026)
    #[arg(long, value_name = "SALT")]
    salt: Option<String>,

    /// Pepper secret for Argon2 (default: secret-pepper-masterkey)
    #[arg(long, value_name = "PEPPER")]
    pepper: Option<String>,

    /// 12-character nonce for ChaCha20 (default: JohnDoeXYZ12)
    #[arg(long, value_name = "NONCE")]
    nonce: Option<String>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    if cli.size == 0 || cli.size > MAX_SIZE {
        eprintln!("Size must be between 1 and 20GB ({MAX_SIZE} bytes)");
        std::process::exit(1);
    }

    // Output path: CLI → default next to exe
    let output_path = cli.output.unwrap_or_else(|| {
        let mut exe = env::current_exe().expect("Cannot get exe path");
        exe.pop(); // remove exe name
        exe.push("key.key");
        exe
    });

    if output_path.exists() {
        eprintln!("File {output_path:?} already exists. Exiting to avoid overwrite.");
        std::process::exit(1);
    }

    // Config: CLI > env var > default
    let salt = cli.salt
        .or_else(|| env::var("STARDUST_SALT").ok())
        .unwrap_or_else(|| "ultimate-salt-v1-2026".into())
        .into_bytes();

    let pepper = cli.pepper
        .or_else(|| env::var("STARDUST_PEPPER").ok())
        .unwrap_or_else(|| "secret-pepper-masterkey".into())
        .into_bytes();

    let nonce_str = cli.nonce
        .or_else(|| env::var("STARDUST_NONCE").ok())
        .unwrap_or_else(|| "JohnDoeXYZ12".into());

    if nonce_str.len() != 12 {
        eprintln!("Nonce must be exactly 12 characters long");
        std::process::exit(1);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_str.as_bytes());

    // Prompt password (twice)
    let pw1 = prompt_password("Enter password: ")?;
    let pw2 = prompt_password("Confirm password: ")?;
    if pw1 != pw2 {
        eprintln!("Passwords do not match!");
        std::process::exit(1);
    }
    let password = pw1.into_bytes();

    // Argon2id key derivation
    let mut master_key = [0u8; 32];
    let params = Params::new(131_072, 4, 8, None).expect("Invalid Argon2 params"); // ~128 MiB, moderate

    let argon2 = Argon2::new_with_secret(
        &pepper,
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    ).expect("Failed to init Argon2");

    argon2
        .hash_password_into(&password, &salt, &mut master_key)
        .expect("Argon2 hash failed");

    // ChaCha20 setup - use slice-based new() to satisfy KeyIvInit bounds in cipher 0.5
    let key_slice: &[u8; 32] = &master_key;
    let nonce_slice: &[u8; 12] = &nonce;
    let mut cipher = ChaCha20::new(key_slice.into(), nonce_slice.into());

    // Write file in chunks
    let mut output = File::create(&output_path)?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut remaining = cli.size;

    while remaining > 0 {
        let chunk = std::cmp::min(CHUNK_SIZE as u64, remaining) as usize;
        cipher.apply_keystream(&mut buffer[..chunk]);
        output.write_all(&buffer[..chunk])?;
        remaining -= chunk as u64;
    }

    output.flush()?;
    println!("Key file created: {output_path:?}");

    Ok(())
}