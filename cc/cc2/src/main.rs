mod cli;
mod constants;
mod crypto;
mod file_ops;
mod error;

use clap::Parser;
use colored::Colorize;
use cli::{Cli, Commands};
use file_ops::{decrypt_file_to_path, encrypt_file};
use error::{LockboxError, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;
use std::process;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Prompt password with confirmation
fn prompt_password_with_confirm(cancelled: Arc<AtomicBool>) -> Result<Zeroizing<String>> {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err(LockboxError::Cancelled); // ✅ actually use Cancelled
        }

        let password = Zeroizing::new(prompt_password("Enter password: ")?);
        if password.is_empty() {
            println!("{}", "Password cannot be empty".red());
            continue;
        }

        let confirm_pw = Zeroizing::new(prompt_password("Confirm password: ")?);
        if password != confirm_pw {
            println!("{}", "Passwords do not match. Try again.".red());
            return Err(LockboxError::PasswordMismatch);
        }

        return Ok(password);
    }
}

/// Prompt password for decryption
fn prompt_password_decrypt(cancelled: Arc<AtomicBool>) -> Result<Zeroizing<String>> {
    if cancelled.load(Ordering::SeqCst) {
        return Err(LockboxError::Cancelled);
    }

    let password = Zeroizing::new(prompt_password("Enter password: ")?);
    if password.is_empty() {
        return Err(LockboxError::EmptyPassword);
    }
    Ok(password)
}

/// Main program logic
fn run() -> Result<()> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let r = cancelled.clone();
    ctrlc::set_handler(move || {
        r.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { files, force } => {
            println!("{}", "🔐 Lockbox Encryption".cyan().bold());
            println!();

            let password = prompt_password_with_confirm(cancelled.clone())?;
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

            let password = prompt_password_decrypt(cancelled.clone())?;
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
        match e {
            LockboxError::Cancelled => {
                eprintln!("{}", "Operation cancelled by user".yellow().bold());
                process::exit(2);
            }
            _ => {
                eprintln!("{} {}", "Error".red().bold(), e);
                process::exit(1);
            }
        }
    }
}
