//! CLI argument structures for the Lupine PQC tool.
//!
//! Defines the top-level `Cli` struct and per-subcommand argument types using
//! clap's derive macro. Each subcommand corresponds to a crypto operation:
//! keygen, encapsulate, decapsulate, sign, and verify.
//!
//! @decision DEC-CLI-002
//! @title Unified --format flag with pem default across all subcommands
//! @status accepted
//! @rationale All five subcommands share the same Format enum (raw/der/pem)
//!   with PEM as the default. PEM is the most human-readable and interoperable
//!   format, and defaulting to it means users can inspect keys with standard
//!   tools. Raw format is available for piping between commands or embedding
//!   in scripts. DER is available for binary interoperability. A single shared
//!   enum keeps the interface consistent and reduces cognitive load.

use clap::{Parser, Subcommand, ValueEnum};

use crate::algorithm::CliAlgorithm;

/// Lupine post-quantum cryptography CLI.
#[derive(Parser)]
#[command(
    name = "lupine",
    about = "Lupine post-quantum cryptography CLI",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Subcommand)]
pub enum Command {
    /// Generate a keypair for the specified algorithm.
    Keygen(KeygenArgs),

    /// Encapsulate a shared secret to a KEM public key.
    Encapsulate(EncapsulateArgs),

    /// Decapsulate a shared secret from a KEM ciphertext using a secret key.
    Decapsulate(DecapsulateArgs),

    /// Sign a message using a signing secret key.
    Sign(SignArgs),

    /// Verify a signature over a message using a verifying public key.
    Verify(VerifyArgs),
}

/// Key format for file I/O.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    /// Raw key bytes with no framing.
    Raw,
    /// DER-encoded (ASN.1 binary).
    Der,
    /// PEM-encoded (base64-wrapped DER). Default.
    #[default]
    Pem,
}

// ---------------------------------------------------------------------------
// Per-subcommand argument structs
// ---------------------------------------------------------------------------

/// Arguments for `lupine keygen`.
#[derive(clap::Args)]
pub struct KeygenArgs {
    /// Algorithm to use (e.g. ml-kem-768, ml-dsa-65, slh-dsa-sha2-128s).
    #[arg(short = 'a', long, value_parser = parse_algorithm)]
    pub algorithm: CliAlgorithm,

    /// Output format: raw, der, or pem (default).
    #[arg(short = 'f', long, default_value = "pem")]
    pub format: Format,

    /// Output filename prefix (default: algorithm name).
    /// Generates `<prefix>.pub` and `<prefix>.sec` unless overridden.
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    /// Path for the public key output file (overrides --output prefix).
    #[arg(long)]
    pub out_pub: Option<String>,

    /// Path for the secret key output file (overrides --output prefix).
    #[arg(long)]
    pub out_sec: Option<String>,
}

/// Arguments for `lupine encapsulate`.
#[derive(clap::Args)]
pub struct EncapsulateArgs {
    /// Path to the KEM public key file.
    #[arg(long)]
    pub pub_key: String,

    /// Algorithm hint (auto-detected from PEM/DER if omitted).
    #[arg(short = 'a', long, value_parser = parse_algorithm)]
    pub algorithm: Option<CliAlgorithm>,

    /// Key format: raw, der, or pem (default).
    #[arg(short = 'f', long, default_value = "pem")]
    pub format: Format,

    /// Path to write the ciphertext (raw bytes). Prints to stdout if omitted.
    #[arg(long)]
    pub out_ct: Option<String>,

    /// Path to write the shared secret (raw hex). Prints to stdout if omitted.
    #[arg(long)]
    pub out_ss: Option<String>,
}

/// Arguments for `lupine decapsulate`.
#[derive(clap::Args)]
pub struct DecapsulateArgs {
    /// Path to the KEM secret key file.
    #[arg(long)]
    pub sec_key: String,

    /// Path to the ciphertext file (raw bytes).
    #[arg(long)]
    pub ciphertext: String,

    /// Algorithm hint (auto-detected from PEM/DER if omitted).
    #[arg(short = 'a', long, value_parser = parse_algorithm)]
    pub algorithm: Option<CliAlgorithm>,

    /// Key format: raw, der, or pem (default).
    #[arg(short = 'f', long, default_value = "pem")]
    pub format: Format,

    /// For hybrid KEM in raw format: path to the public key file (required
    /// to supply the ML-KEM pk bytes for the KitchenSink combiner).
    #[arg(long)]
    pub pub_key: Option<String>,

    /// Path to write the shared secret (raw hex). Prints to stdout if omitted.
    #[arg(long)]
    pub out_ss: Option<String>,
}

/// Arguments for `lupine sign`.
#[derive(clap::Args)]
pub struct SignArgs {
    /// Path to the signing secret key file.
    #[arg(long)]
    pub sec_key: String,

    /// Path to the message file. Reads from stdin if omitted.
    #[arg(long)]
    pub message: Option<String>,

    /// Algorithm hint (auto-detected from PEM/DER if omitted).
    #[arg(short = 'a', long, value_parser = parse_algorithm)]
    pub algorithm: Option<CliAlgorithm>,

    /// Key format: raw, der, or pem (default).
    #[arg(short = 'f', long, default_value = "pem")]
    pub format: Format,

    /// Path to write the signature. Prints to stdout if omitted.
    #[arg(long)]
    pub out_sig: Option<String>,
}

/// Arguments for `lupine verify`.
#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Path to the verifying public key file.
    #[arg(long)]
    pub pub_key: String,

    /// Path to the signature file.
    #[arg(long)]
    pub signature: String,

    /// Path to the message file. Reads from stdin if omitted.
    #[arg(long)]
    pub message: Option<String>,

    /// Algorithm hint (auto-detected from PEM/DER if omitted).
    #[arg(short = 'a', long, value_parser = parse_algorithm)]
    pub algorithm: Option<CliAlgorithm>,

    /// Key format: raw, der, or pem (default).
    #[arg(short = 'f', long, default_value = "pem")]
    pub format: Format,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_algorithm(s: &str) -> Result<CliAlgorithm, String> {
    s.parse::<CliAlgorithm>()
}
