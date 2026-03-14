use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "Modern Lockbox 2024 Edition", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Argon2 memory in KiB
    #[arg(long, default_value_t = 65536)]
    pub memory: u32,

    /// Argon2 iterations
    #[arg(long, default_value_t = 3)]
    pub iterations: u32,

    /// Argon2 parallelism
    #[arg(long, default_value_t = 4)]
    pub parallelism: u32,
}

#[derive(Subcommand)]
pub enum Commands {
    Encrypt { files: Vec<PathBuf>, force: bool },
    Decrypt { files: Vec<PathBuf>, output: Option<PathBuf>, force: bool },
}
