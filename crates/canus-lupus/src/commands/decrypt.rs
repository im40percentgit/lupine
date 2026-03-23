//! `canus-lupus decrypt` — Decrypt a `.enc` file.
//!
//! @decision DEC-CLI-022
//! @title Decrypt requires full keypair load (SK + PK together)
//! @status accepted
//! @rationale `HybridKemSecretKey::from_bytes()` leaves the internal
//!   `mlkem_pk_bytes` field empty after deserialization. The KitchenSink
//!   combiner used during decapsulation requires those bytes to reproduce the
//!   combined shared secret. The keystore's `load_kem_sk()` always loads the
//!   matching public key file in parallel and calls `set_mlkem_pk_bytes()`,
//!   so callers of this command do not need to be aware of the constraint.
//!   See DEC-KEYSTORE-002 for the keystore-level rationale.

use std::fs;
use std::path::PathBuf;

use clap::Args;

use crate::keystore;

/// Arguments for the `decrypt` subcommand.
#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// Encrypted file to decrypt (typically with a `.enc` extension).
    pub input: PathBuf,

    /// Name of the keypair to decrypt with (default: "default").
    #[arg(short, long, default_value = "default")]
    pub key: String,

    /// Output file (default: strips `.enc` extension, or appends `.dec`).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: &DecryptArgs) -> anyhow::Result<()> {
    let sealed = fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", args.input.display()))?;

    // load_kem_sk also loads the matching pk and restores mlkem_pk_bytes.
    let kem_sk = keystore::load_kem_sk(&args.key).map_err(|e| {
        anyhow::anyhow!(
            "cannot load key '{}': {e}\n\
             Run `canus-lupus keygen` to create a keypair.",
            args.key
        )
    })?;

    let plaintext = lupine::easy::decrypt(&kem_sk, &sealed)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

    let out_path = args.output.clone().unwrap_or_else(|| {
        let input_str = args.input.to_string_lossy();
        if let Some(stripped) = input_str.strip_suffix(".enc") {
            PathBuf::from(stripped)
        } else {
            let mut p = args.input.clone();
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            p.set_file_name(format!("{name}.dec"));
            p
        }
    });

    fs::write(&out_path, &plaintext)
        .map_err(|e| anyhow::anyhow!("cannot write '{}': {e}", out_path.display()))?;

    eprintln!(
        "Decrypted {} bytes → {}",
        plaintext.len(),
        out_path.display()
    );
    Ok(())
}
