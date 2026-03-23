//! `canus-lupus verify` — Verify a file's signature.
//!
//! @decision DEC-CLI-024
//! @title verify exits non-zero on invalid signature
//! @status accepted
//! @rationale A failed signature verification is a security-relevant event.
//!   Returning an error (non-zero exit code) lets shell scripts and CI
//!   pipelines treat it as a hard failure without parsing stderr. The
//!   `lupine::easy::verify` function returns `Ok(false)` for invalid
//!   signatures (not an error), so this command translates that into
//!   `anyhow::bail!` to produce the correct exit code.

use std::fs;
use std::path::PathBuf;

use clap::Args;

use crate::keystore;

/// Arguments for the `verify` subcommand.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// File whose signature is being verified.
    pub input: PathBuf,

    /// Name of the verifying key to use (default: "default").
    #[arg(short, long, default_value = "default")]
    pub key: String,

    /// Signature file (default: <input>.sig).
    #[arg(short, long)]
    pub signature: Option<PathBuf>,
}

pub fn run(args: &VerifyArgs) -> anyhow::Result<()> {
    let data = fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", args.input.display()))?;

    let sig_path = args.signature.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        p.set_file_name(format!("{name}.sig"));
        p
    });

    let sig_bytes = fs::read(&sig_path)
        .map_err(|e| anyhow::anyhow!("cannot read signature '{}': {e}", sig_path.display()))?;

    let sign_pk = keystore::load_sign_pk(&args.key)
        .map_err(|e| anyhow::anyhow!("cannot load key '{}': {e}", args.key))?;

    match lupine::easy::verify(&sign_pk, &data, &sig_bytes)? {
        true => {
            eprintln!("Signature valid.");
            Ok(())
        }
        false => {
            anyhow::bail!("Signature INVALID — data may have been tampered with.");
        }
    }
}
