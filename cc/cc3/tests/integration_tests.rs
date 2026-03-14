//! Integration + Stress Tests for aicrypt
//! Author: ChatGPT, 2026
//! Tests multiple files and reports per-file success

use std::fs::{File, remove_file};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use tempfile::tempdir;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use aicrypt::file_ops::{encrypt_file, decrypt_file_to_path};

const RNG_SEED: u64 = 42;
const FILE_COUNT: usize = 10;
const MAX_FILE_SIZE: usize = 2_000_000; // 2 MB max per file

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

fn cleanup(paths: &[PathBuf]) {
    for p in paths {
        let _ = remove_file(p);
    }
}

#[test]
fn integration_stress_test() {
    let start = Instant::now();
    println!("Starting integration + stress test for {} files...", FILE_COUNT);

    let dir = tempdir().expect("Failed to create temp dir");
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let password = b"super-secure-test-password";

    let mut files = Vec::with_capacity(FILE_COUNT);

    // Step 1: Create random files
    for _ in 0..FILE_COUNT {
        let size = rng.gen_range(0..=MAX_FILE_SIZE);
        files.push(create_random_file(&dir.path().to_path_buf(), size, &mut rng));
    }

    // Step 2: Encrypt, decrypt, and verify each file
    let mut all_passed = true;
    for (i, (path, original)) in files.iter().enumerate() {
        let enc_path = match encrypt_file(path, password, 65536, 3, 4, true) {
            Ok(p) => p,
            Err(e) => {
                println!("✗ [{}] Encryption failed: {:?}", i, e);
                all_passed = false;
                continue;
            }
        };

        let dec_path = match decrypt_file_to_path(&enc_path, password, None, 65536, 3, 4, true) {
            Ok(p) => p,
            Err(e) => {
                println!("✗ [{}] Decryption failed: {:?}", i, e);
                all_passed = false;
                cleanup(&[enc_path]);
                continue;
            }
        };

        let decrypted = match std::fs::read(&dec_path) {
            Ok(data) => data,
            Err(e) => {
                println!("✗ [{}] Failed reading decrypted file: {:?}", i, e);
                all_passed = false;
                cleanup(&[enc_path, dec_path]);
                continue;
            }
        };

        if &decrypted == original {
            println!("✓ [{}] File roundtrip success: {:?}", i, path.file_name().unwrap());
        } else {
            println!("✗ [{}] File mismatch after roundtrip: {:?}", i, path.file_name().unwrap());
            all_passed = false;
        }

        cleanup(&[enc_path, dec_path]);
    }

    if all_passed {
        println!("All {} files passed successfully!", FILE_COUNT);
    } else {
        println!("Some files failed. Check above output for details.");
        panic!("Integration/Stress test failed.");
    }

    println!("Total test duration: {:.2?}", start.elapsed());
}
