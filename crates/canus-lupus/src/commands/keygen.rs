//! `canus-lupus keygen` — Generate a new keypair.
//!
//! Generates a hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65 keypair and
//! writes it to the key store as four PEM files.

use clap::Args;

use crate::keystore;

/// Arguments for the `keygen` subcommand.
#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Name for the keypair (default: "default").
    #[arg(long, default_value = "default")]
    pub name: String,

    /// Overwrite an existing keypair with this name without prompting.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: &KeygenArgs) -> anyhow::Result<()> {
    // Check if a keypair already exists and --force was not given.
    if !args.force && keystore::keypair_exists(&args.name)? {
        anyhow::bail!(
            "keypair '{}' already exists; use --force to overwrite",
            args.name
        );
    }

    eprintln!("Generating keypair '{}'...", args.name);
    let kp = lupine::easy::generate_keys()?;

    let dir = keystore::keys_dir()?;
    keystore::save_keypair(&args.name, &kp)?;

    eprintln!("Keypair '{}' written to {}", args.name, dir.display());
    eprintln!("  {}.kem_sk.pem  (keep secret)", args.name);
    eprintln!("  {}.kem_pk.pem", args.name);
    eprintln!("  {}.sign_sk.pem (keep secret)", args.name);
    eprintln!("  {}.sign_pk.pem", args.name);

    Ok(())
}
