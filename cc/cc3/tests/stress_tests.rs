// tests/stress_tests.rs

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::thread;

use rand::{Rng, thread_rng};
use aicrypt::{encrypt_file, decrypt_file};

fn generate_random_file(path: &PathBuf, size: usize) -> std::io::Result<()> {
    let mut rng = thread_rng();
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);

    let mut file = File::create(path)?;
    file.write_all(&data)?;
    Ok(())
}

#[test]
fn ultra_heavy_stress_test() {
    // Create a temp folder
    let temp_dir = PathBuf::from("stress_temp");
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).unwrap();
    }
    fs::create_dir(&temp_dir).unwrap();

    let num_files = 120; // number of files
    let file_size = 1024 * 1024; // 1 MB per file
    let cycles = 5;

    println!("Generating {} large random files...", num_files);

    let mut files = Vec::new();
    for i in 0..num_files {
        let path = temp_dir.join(format!("file_{i}.bin"));
        generate_random_file(&path, file_size).unwrap();
        files.push(path);
    }

    println!("Running {cycles} encryption/decryption cycles on {} files", num_files);

    for cycle in 1..=cycles {
        println!("Cycle {cycle}");
        let mut handles = Vec::new();

        for file_path in &files {
            let file_path = file_path.clone();
            let temp_dir = temp_dir.clone();
            handles.push(thread::spawn(move || {
                let enc_path = temp_dir.join(format!("{}.enc", file_path.file_name().unwrap().to_string_lossy()));
                let dec_path = temp_dir.join(format!("{}.dec", file_path.file_name().unwrap().to_string_lossy()));

                encrypt_file(&file_path, &enc_path)
                    .expect("encryption failed");
                decrypt_file(&enc_path, &dec_path)
                    .expect("decryption failed");

                // Optionally, verify content matches original
                let original = fs::read(&file_path).unwrap();
                let decrypted = fs::read(&dec_path).unwrap();
                assert_eq!(original, decrypted, "decrypted content does not match original");
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    // Cleanup temp files
    fs::remove_dir_all(&temp_dir).unwrap();
    println!("Ultra-heavy stress test completed successfully!");
}
