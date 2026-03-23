//! `canus-lupus sign` — Sign a file, producing `<file>.sig`.
//!
//! @decision DEC-CLI-023
//! @title Raw signature bytes stored directly (no PEM wrapper on .sig files)
//! @status accepted
//! @rationale Signature files (.sig) are binary blobs read by `canus-lupus
//!   verify` — not by external tools. Skipping the PEM wrapper keeps the
//!   file simpler and avoids an encode/decode round-trip. If interop with
//!   external PEM parsers becomes necessary, a future `--pem` flag can be
//!   added without breaking the default binary format.

use std::fs;
use std::path::PathBuf;

use clap::Args;

use crate::keystore;

/// Arguments for the `sign` subcommand.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// File to sign.
    pub input: PathBuf,

    /// Name of the signing keypair (default: "default").
    #[arg(short, long, default_value = "default")]
    pub key: String,

    /// Output signature file (default: <input>.sig).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: &SignArgs) -> anyhow::Result<()> {
    let data = fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", args.input.display()))?;

    let sign_sk = keystore::load_sign_sk(&args.key).map_err(|e| {
        anyhow::anyhow!(
            "cannot load signing key '{}': {e}\n\
             Run `canus-lupus keygen` to create a keypair.",
            args.key
        )
    })?;

    let sig_bytes =
        lupine::easy::sign(&sign_sk, &data).map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;

    let out_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        p.set_file_name(format!("{name}.sig"));
        p
    });

    fs::write(&out_path, &sig_bytes)
        .map_err(|e| anyhow::anyhow!("cannot write '{}': {e}", out_path.display()))?;

    eprintln!(
        "Signed {} bytes → {} ({} bytes signature)",
        data.len(),
        out_path.display(),
        sig_bytes.len()
    );
    Ok(())
}
