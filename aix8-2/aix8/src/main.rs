use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rpassword::prompt_password;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{self as secretstream, Key, TAG_FINAL, TAG_MESSAGE};
use libsodium_rs::{ensure_init, random};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(not(target_os = "linux"))]
compile_error!("This application is for Linux only.");

const MAGIC: &[u8] = b"AIX8";
const SALT_LEN: usize = 16;
const CHUNK_SIZE: usize = 1 << 20; // 1MB - reliable for most systems, low overhead
const ARGON2_MEM_KIB: u32 = 65536; // 64MiB
const ARGON2_ITER: u32 = 4;
const ARGON2_PAR: u32 = 4;

#[derive(Parser)]
#[command(version, about = "Reliable file encryption CLI for Linux using XChaCha20-Poly1305")]
struct Args {
    /// The file to encrypt or decrypt
    file: String,
}

fn main() -> Result<()> {
    ensure_init().map_err(|_| anyhow!("Failed to initialize libsodium-rs"))?;

    let args = Args::parse();
    let input_path = PathBuf::from(&args.file);

    if !input_path.exists() || !input_path.is_file() {
        return Err(anyhow!("Input '{}' is not a valid file", args.file));
    }

    // Detect if encrypt or decrypt by peeking at magic bytes
    let is_encrypt = {
        let mut file = File::open(&input_path)?;
        let mut magic_buf = [0u8; MAGIC.len()];
        if file.read_exact(&mut magic_buf).is_ok() && magic_buf == *MAGIC {
            false  // Has MAGIC, so decrypt
        } else {
            true   // No MAGIC, so encrypt
        }
    };

    let temp_path = input_path.with_extension("tmp");

    let (output_path, op_desc) = if is_encrypt {
        encrypt(&input_path, &temp_path)?;
        (input_path.with_extension("ai"), "Encrypted")
    } else {
        let stored_ext = decrypt(&input_path, &temp_path)?;
        let mut path = input_path.clone();
        path.set_extension(stored_ext);
        (path, "Decrypted")
    };

    if output_path.exists() {
        fs::remove_file(&temp_path).ok();  // Clean up temp
        return Err(anyhow!("Output file '{}' already exists; won't overwrite for safety", output_path.display()));
    }

    fs::rename(&temp_path, &output_path).context("Failed to rename temp file")?;
    let mut perms = fs::metadata(&output_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&output_path, perms).context("Failed to set file permissions")?;

    // Remove the original input file for "in-place" feel (only one file remains)
    fs::remove_file(&input_path).context("Failed to remove original file")?;

    println!("Success: {} {} -> {}", op_desc, args.file, output_path.display());
    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
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

fn encrypt(input_path: &Path, temp_path: &Path) -> Result<()> {
    let pw1 = prompt_password("Enter password: ")?;
    let pw2 = prompt_password("Confirm password: ")?;
    if pw1 != pw2 {
        return Err(anyhow!("Passwords do not match"));
    }

    let original_ext = input_path.extension().map_or("".to_string(), |e| e.to_string_lossy().to_string());
    let ext_bytes = original_ext.as_bytes();
    if ext_bytes.len() > 255 {
        return Err(anyhow!("File extension too long"));
    }
    let ext_len = ext_bytes.len() as u8;

    let salt = random::bytes(SALT_LEN);

    let key = derive_key(&pw1, &salt)?;

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

fn decrypt(input_path: &Path, temp_path: &Path) -> Result<String> {
    let pw = prompt_password("Enter password: ")?;

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

    let key = derive_key(&pw, &salt)?;

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
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
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