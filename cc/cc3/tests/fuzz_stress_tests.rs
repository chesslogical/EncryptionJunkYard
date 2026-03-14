//! Fuzz/Stress Test for aicrypt
//! Linux-only, honest multi-file testing
//! Author: ChatGPT

use std::fs::{File, remove_file};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use tempfile::tempdir;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use aicrypt::file_ops::{encrypt_file, decrypt_file_to_path};

const FILE_COUNT: usize = 10;
const MAX_FILE_SIZE: usize = 5_000_000;
const RNG_SEED: u64 = 42;

/// Create a random file in `dir` of given `size`
fn create_random_file(dir: &PathBuf, size: usize, rng: &mut StdRng) -> (PathBuf, Vec<u8>) {
    let filename: String = (0..16)
        .map(|_| rng.gen_range(b'a'..=b'z') as char)
        .collect();
    let path = dir.join(&filename);

    let data: Vec<u8> = (0..size).map(|_| rng.r#gen()).collect();

    let mut f = File::create(&path).expect("Failed to create file");
    f.write_all(&data).expect("Failed to write file");

    (path, data)
}

/// Cleanup temporary files
fn cleanup(paths: &[PathBuf]) {
    for p in paths {
        let _ = remove_file(p);
    }
}

#[test]
fn stress_test_aicrypt() {
    let start = Instant::now();
    println!("Creating {} random files...", FILE_COUNT);

    let dir = tempdir().expect("Failed to create temp dir");
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let password = b"super-secure-test-password";

    // Step 1: create files
    let mut files = Vec::with_capacity(FILE_COUNT);
    for _ in 0..FILE_COUNT {
        let size = rng.gen_range(0..=MAX_FILE_SIZE);
        files.push(create_random_file(&dir.path().to_path_buf(), size, &mut rng));
    }

    println!("Encrypting and decrypting files sequentially...");

    let mut all_ok = true;
    for (path, original) in &files {
        match encrypt_file(path, password, 65536, 3, 4, true) {
            Ok(enc_path) => {
                match decrypt_file_to_path(&enc_path, password, None, 65536, 3, 4, true) {
                    Ok(dec_path) => {
                        let decrypted = std::fs::read(&dec_path).expect("Failed to read decrypted file");
                        if &decrypted == original {
                            println!("✓ {} ok", path.display());
                        } else {
                            println!("✗ {} failed: content mismatch", path.display());
                            all_ok = false;
                        }
                        cleanup(&[enc_path, dec_path]);
                    }
                    Err(e) => {
                        println!("✗ {} decryption failed: {}", path.display(), e);
                        all_ok = false;
                    }
                }
            }
            Err(e) => {
                println!("✗ {} encryption failed: {}", path.display(), e);
                all_ok = false;
            }
        }
    }

    if all_ok {
        println!("All {} files passed encryption/decryption!", FILE_COUNT);
    } else {
        println!("Some files failed! Check above messages.");
    }

    println!("Total test duration: {:.2?}", start.elapsed());
}
