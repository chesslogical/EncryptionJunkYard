// src/main.rs
//! AICrypt CLI - Linux-only
//! Original code by Mark Snow & ChatGPT 2026

mod cli;
mod constants;
mod crypto;
mod file_ops;
mod error;

use clap::Parser;
use colored::Colorize;
use cli::{Cli, Commands};
use file_ops::{encrypt_file, decrypt_file_to_path};
use error::{LockboxError, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

fn prompt_password_with_confirm() -> Result<Zeroizing<String>> {
    loop {
        let password = Zeroizing::new(prompt_password("Enter password: ")?);
        if password.is_empty() {
            println!("{}", "Password cannot be empty".red());
            continue;
        }
        let confirm_pw = Zeroizing::new(prompt_password("Confirm password: ")?);
        if password != confirm_pw {
            println!("{}", "Passwords do not match. Try again.".red());
            continue;
        }
        return Ok(password);
    }
}

fn prompt_password_decrypt() -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(prompt_password("Enter password: ")?);
    if password.is_empty() {
        return Err(LockboxError::EmptyPassword);
    }
    Ok(password)
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { files, force } => {
            println!("{}", "🔐 Lockbox Encryption".cyan().bold());
            println!();

            let password = prompt_password_with_confirm()?;
            println!();

            for file_path in &files {
                match encrypt_file(
                    file_path,
                    password.as_bytes(),
                    cli.memory,
                    cli.iterations,
                    cli.parallelism,
                    force,
                ) {
                    Ok(output_path) => println!("{} → {:?}", "✓".green(), output_path),
                    Err(e) => println!("{} {}", "✗".red(), e),
                }
            }
        }
        Commands::Decrypt { files, output, force } => {
            println!("{}", "🔓 Lockbox Decryption".cyan().bold());
            println!();

            let password = prompt_password_decrypt()?;
            println!();

            for file_path in &files {
                match decrypt_file_to_path(
                    file_path,
                    password.as_bytes(),
                    output.as_deref(),
                    cli.memory,
                    cli.iterations,
                    cli.parallelism,
                    force,
                ) {
                    Ok(output_path) => println!("{} → {:?}", "✓".green(), output_path),
                    Err(e) => println!("{} {}", "✗".red(), e),
                }
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}
