//! `canus-lupus keys` — Key management subcommands.
//!
//! Provides three operations:
//! - `keys list` — List all known keys in the keystore.
//! - `keys import <file>` — Import a public key bundle from a file.
//! - `keys export` — Export own public key bundle to stdout.
//!
//! @decision DEC-CLI-025
//! @title Public key bundle format: two PEM blocks concatenated
//! @status accepted
//! @rationale A recipient needs both the KEM public key and the signing
//!   verifying key to receive encrypted files and have their signatures
//!   checked. Exporting / importing both as a single concatenated PEM file
//!   (two PEM blocks one after the other) keeps the exchange to a single
//!   file while remaining human-readable. The import command splits on PEM
//!   boundaries by reading the file twice with the two decode functions;
//!   RFC 7468 parsers stop at the first END boundary so the first call
//!   returns the KEM block and the second needs a trimmed string.
//!   An alternative (JSON envelope) would be more structured but adds a
//!   serde dependency and is harder to inspect with standard tools.

use std::fs;
use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::keystore;

/// Arguments for the `keys` subcommand group.
#[derive(Debug, Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub command: KeysCommand,
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// List all keys in the keystore.
    List,
    /// Import a public key bundle from a file.
    Import(ImportArgs),
    /// Export own public key bundle (prints to stdout).
    Export(ExportArgs),
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Public key bundle file (produced by `keys export`).
    pub file: PathBuf,

    /// Name to store the key under.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Name of the keypair to export (default: "default").
    #[arg(long, default_value = "default")]
    pub name: String,
}

pub fn run(args: &KeysArgs) -> anyhow::Result<()> {
    match &args.command {
        KeysCommand::List => run_list(),
        KeysCommand::Import(a) => run_import(a),
        KeysCommand::Export(a) => run_export(a),
    }
}

fn run_list() -> anyhow::Result<()> {
    let entries = keystore::list_keys()?;
    if entries.is_empty() {
        eprintln!("No keys found. Run `canus-lupus keygen` to create a keypair.");
        return Ok(());
    }
    for e in &entries {
        let kind = if e.has_secret {
            "keypair"
        } else {
            "public key"
        };
        println!("{:<20} {}", e.name, kind);
    }
    Ok(())
}

fn run_import(args: &ImportArgs) -> anyhow::Result<()> {
    let bundle = fs::read_to_string(&args.file)
        .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", args.file.display()))?;

    // Derive the key name from --name flag or from the filename stem.
    let name = match &args.name {
        Some(n) => n.clone(),
        None => args
            .file
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "imported".to_string()),
    };

    // A bundle contains two PEM blocks: KEM pk first, then sign pk.
    // Split on the second "-----BEGIN" boundary.
    let kem_block_end = bundle
        .find("-----END PUBLIC KEY-----")
        .ok_or_else(|| anyhow::anyhow!("bundle missing KEM public key PEM block"))?;
    let after_kem = &bundle[kem_block_end..];
    let second_begin = after_kem
        .find("-----BEGIN PUBLIC KEY-----")
        .ok_or_else(|| anyhow::anyhow!("bundle missing sign public key PEM block"))?;

    let kem_pem = &bundle[..kem_block_end + "-----END PUBLIC KEY-----".len() + 1];
    let sign_pem = &after_kem[second_begin..];

    let kem_bytes = lupine_serial::pem::decode_public_key_pem(kem_pem)
        .map_err(|e| anyhow::anyhow!("cannot decode KEM public key PEM: {e}"))?;
    let sign_bytes = lupine_serial::pem::decode_public_key_pem(sign_pem)
        .map_err(|e| anyhow::anyhow!("cannot decode sign public key PEM: {e}"))?;

    let kem_pk = keystore::HybridKemPublicKey768::from_bytes(&kem_bytes)
        .map_err(|e| anyhow::anyhow!("invalid KEM public key: {e}"))?;
    let sign_pk = keystore::HybridVerifyingKey65::from_bytes(&sign_bytes)
        .map_err(|e| anyhow::anyhow!("invalid sign public key: {e}"))?;

    keystore::save_kem_pk(&name, &kem_pk)?;
    keystore::save_sign_pk(&name, &sign_pk)?;

    eprintln!("Imported public key bundle as '{name}'.");
    Ok(())
}

fn run_export(args: &ExportArgs) -> anyhow::Result<()> {
    let kem_pk = keystore::load_kem_pk(&args.name)
        .map_err(|e| anyhow::anyhow!("cannot load KEM key '{}': {e}", args.name))?;
    let sign_pk = keystore::load_sign_pk(&args.name)
        .map_err(|e| anyhow::anyhow!("cannot load sign key '{}': {e}", args.name))?;

    let kem_pem = lupine_serial::pem::encode_public_key_pem(&kem_pk.to_bytes())
        .map_err(|e| anyhow::anyhow!("PEM encode KEM pk: {e}"))?;
    let sign_pem = lupine_serial::pem::encode_public_key_pem(&sign_pk.to_bytes())
        .map_err(|e| anyhow::anyhow!("PEM encode sign pk: {e}"))?;

    // Print both blocks to stdout — the caller can redirect to a file.
    print!("{kem_pem}{sign_pem}");
    Ok(())
}
