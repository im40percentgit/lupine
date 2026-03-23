//! `canus-lupus encrypt` — Encrypt a file.
//!
//! Encrypts a file using the hybrid KEM-DEM construction from `lupine::easy`.
//! The output is written to `<input>.enc`.
//!
//! By default, the file is encrypted for the caller's own public key
//! (encrypt-for-self). Use `-r`/`--recipient` to encrypt for a different key.
//!
//! @decision DEC-CLI-021
//! @title Encrypt-for-self as default behavior
//! @status accepted
//! @rationale When no `-r` recipient is given, `encrypt` looks up the
//!   caller's own KEM public key ("default" name). This mirrors the `age`
//!   tool's self-encryption default and avoids forcing the user to know their
//!   own key path. The recipient name defaults to "default" and can be
//!   overridden with `-r <name>` when encrypting for someone else.

use std::fs;
use std::path::PathBuf;

use clap::Args;

use crate::keystore;

/// Arguments for the `encrypt` subcommand.
#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// File to encrypt.
    pub input: PathBuf,

    /// Recipient key name (default: encrypt for self using "default" keypair).
    #[arg(short, long, default_value = "default")]
    pub recipient: String,

    /// Output file (default: <input>.enc).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: &EncryptArgs) -> anyhow::Result<()> {
    let plaintext = fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", args.input.display()))?;

    let recipient_pk = keystore::load_kem_pk(&args.recipient).map_err(|e| {
        anyhow::anyhow!(
            "cannot load recipient key '{}': {e}\n\
             Run `canus-lupus keys import` to add a recipient, or \
             `canus-lupus keygen` to create your own keypair.",
            args.recipient
        )
    })?;

    let sealed = lupine::easy::encrypt(&recipient_pk, &plaintext)?;

    let out_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        p.set_file_name(format!("{name}.enc"));
        p
    });

    fs::write(&out_path, &sealed)
        .map_err(|e| anyhow::anyhow!("cannot write '{}': {e}", out_path.display()))?;

    eprintln!(
        "Encrypted {} bytes → {} ({} bytes sealed)",
        plaintext.len(),
        out_path.display(),
        sealed.len()
    );
    Ok(())
}
