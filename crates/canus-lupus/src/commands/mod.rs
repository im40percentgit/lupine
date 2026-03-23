//! Command routing for canus-lupus.
//!
//! Defines the top-level `Cli` struct and `Command` enum, and dispatches to
//! the appropriate command handler. All subcommands are in sibling modules.

pub mod decrypt;
pub mod encrypt;
pub mod keygen;
pub mod keys;
pub mod sign;
pub mod vault;
pub mod verify;

use clap::{Parser, Subcommand};

/// canus-lupus — Post-quantum encryption, signing, and key management.
#[derive(Debug, Parser)]
#[command(name = "canus-lupus", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a new keypair.
    Keygen(keygen::KeygenArgs),
    /// Encrypt a file.
    Encrypt(encrypt::EncryptArgs),
    /// Decrypt an encrypted file.
    Decrypt(decrypt::DecryptArgs),
    /// Sign a file (produces `<file>.sig`).
    Sign(sign::SignArgs),
    /// Verify a file's signature.
    Verify(verify::VerifyArgs),
    /// Manage known keys (list, import, export).
    Keys(keys::KeysArgs),
    /// Manage encrypted secrets (init, set, get, list, rm).
    Vault(vault::VaultArgs),
}

/// Dispatch the parsed CLI to the appropriate command handler.
pub fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Keygen(ref a) => keygen::run(a),
        Command::Encrypt(ref a) => encrypt::run(a),
        Command::Decrypt(ref a) => decrypt::run(a),
        Command::Sign(ref a) => sign::run(a),
        Command::Verify(ref a) => verify::run(a),
        Command::Keys(ref a) => keys::run(a),
        Command::Vault(ref a) => vault::run(a),
    }
}
