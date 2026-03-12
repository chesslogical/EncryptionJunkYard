use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use tempfile::NamedTempFile;

const BUFFER_SIZE: usize = 64 * 1024; // 64 KiB

#[derive(Parser)]
#[command(
    name = "xor",
    version = "0.1.0",
    about = "XOR-obfuscate a file using a repeating key file",
    author = "Mark"
)]
struct Cli {
    /// Input file to transform (will be overwritten atomically)
    #[arg(index = 1)]
    file: PathBuf,

    /// Path to key file (default: key.key next to executable)
    #[arg(short, long, value_name = "KEY_FILE")]
    key: Option<PathBuf>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let key_path = cli.key.unwrap_or_else(|| {
        default_key_path().expect("Failed to determine default key path")
    });

    println!("XOR-transforming file: {:?}", cli.file);
    println!("Using key file:     {:?}", key_path);

    if !cli.file.exists() {
        eprintln!("Error: Input file does not exist: {:?}", cli.file);
        std::process::exit(1);
    }

    if !key_path.exists() {
        eprintln!("Error: Key file does not exist: {:?}", key_path);
        std::process::exit(1);
    }

    run(&cli.file, &key_path)?;

    println!("File successfully XOR-obfuscated (overwritten in place).");

    Ok(())
}

/// Default key path: key.key next to the executable
fn default_key_path() -> io::Result<PathBuf> {
    let exe_path = env::current_exe()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Cannot determine exe directory"))?;
    Ok(exe_dir.join("key.key"))
}

/// Main XOR transform: reads input + key, writes to temp file, then atomically replaces
fn run(input_path: &Path, key_path: &Path) -> io::Result<()> {
    let mut input = BufReader::new(File::open(input_path)?);

    let key_file = File::open(key_path)?;
    let key_len = key_file.metadata()?.len();
    if key_len == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "Key file is empty"));
    }

    let mut key_reader = BufReader::new(key_file);

    // Create temp file in same directory for atomic move
    let parent_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)?;
    let mut output = BufWriter::new(temp_file.as_file_mut());

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut key_byte = [0u8; 1];
    let mut key_pos: u64 = 0;

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        for i in 0..n {
            // Loop key if we've reached the end
            if key_pos == key_len {
                key_pos = 0;
                key_reader.seek(SeekFrom::Start(0))?;
            }

            key_reader.read_exact(&mut key_byte)?;
            buffer[i] ^= key_byte[0];
            key_pos += 1;
        }

        output.write_all(&buffer[..n])?;
    }

    output.flush()?;

    // Drop writer to release file handle before persisting
    drop(output);

    // Atomically replace original file
    temp_file.persist(input_path)?;

    Ok(())
}