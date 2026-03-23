//! `canus-lupus vault` — Encrypted secret management subcommands.
//!
//! Provides five operations:
//! - `vault init`  — Initialize the vault directory.
//! - `vault set <path> [value]` — Store a secret (reads stdin if value omitted).
//! - `vault get <path>` — Retrieve and decrypt a secret to stdout.
//! - `vault list`  — List all stored secret paths.
//! - `vault rm <path>` — Remove a secret.
//!
//! @decision DEC-VAULT-003
//! @title vault get writes plaintext without trailing newline
//! @status accepted
//! @rationale `vault get` is designed for shell composition: the caller may
//!   pipe the output directly to another command (e.g. `export API_KEY=$(canus-lupus vault get api/openai)`).
//!   Adding a trailing newline would contaminate secrets that end in whitespace
//!   and would change the byte count, making byte-exact verification harder.
//!   Since `print!` already omits the newline, this is the natural default.
//!
//! @decision DEC-VAULT-004
//! @title vault set reads value from stdin when no argument is given
//! @status accepted
//! @rationale Passing secrets on the command line exposes them in shell history
//!   and `ps` output. Reading from stdin when the value argument is absent lets
//!   the caller pipe the secret in (e.g. `echo "sk-..." | canus-lupus vault set api/openai`)
//!   or type it interactively without leaving a trace. When a value argument is
//!   provided, it is accepted for convenience (scripts, tests).

use std::io::Read;

use clap::{Args, Subcommand};

use crate::vault;

// ── Clap types ────────────────────────────────────────────────────────────────

/// Arguments for the `vault` subcommand group.
#[derive(Debug, Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub command: VaultCommand,
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Initialize the vault (creates ~/.canus-lupus/vault/ with mode 0700).
    Init,
    /// Store a secret at <path>. Reads from stdin if VALUE is omitted.
    Set(SetArgs),
    /// Retrieve a secret at <path> and print it to stdout (no trailing newline).
    Get(GetArgs),
    /// List all secret paths stored in the vault.
    List,
    /// Remove a secret from the vault.
    Rm(RmArgs),
}

#[derive(Debug, Args)]
pub struct SetArgs {
    /// Hierarchical path of the secret (e.g. `api/openai`).
    pub path: String,
    /// Secret value. If omitted, the value is read from stdin.
    pub value: Option<String>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Hierarchical path of the secret (e.g. `api/openai`).
    pub path: String,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    /// Hierarchical path of the secret to remove (e.g. `api/openai`).
    pub path: String,
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub fn run(args: &VaultArgs) -> anyhow::Result<()> {
    match &args.command {
        VaultCommand::Init => run_init(),
        VaultCommand::Set(a) => run_set(a),
        VaultCommand::Get(a) => run_get(a),
        VaultCommand::List => run_list(),
        VaultCommand::Rm(a) => run_rm(a),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

fn run_init() -> anyhow::Result<()> {
    vault::init()?;
    let dir = vault::vault_dir()?;
    eprintln!("Vault initialized at {}.", dir.display());
    Ok(())
}

fn run_set(args: &SetArgs) -> anyhow::Result<()> {
    let plaintext: Vec<u8> = match &args.value {
        Some(v) => v.as_bytes().to_vec(),
        None => {
            // Read the entire stdin as the secret value.
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| anyhow::anyhow!("failed to read secret from stdin: {e}"))?;
            buf
        }
    };

    vault::set(&args.path, &plaintext)?;
    eprintln!("Stored secret '{}'.", args.path);
    Ok(())
}

fn run_get(args: &GetArgs) -> anyhow::Result<()> {
    let plaintext = vault::get(&args.path)?;
    // Write raw bytes without a trailing newline — piping-friendly.
    // Use write! to stdout directly so binary secrets are not mangled by
    // the println! macro's string formatting.
    use std::io::Write;
    std::io::stdout()
        .write_all(&plaintext)
        .map_err(|e| anyhow::anyhow!("failed to write secret to stdout: {e}"))?;
    Ok(())
}

fn run_list() -> anyhow::Result<()> {
    let paths = vault::list()?;
    if paths.is_empty() {
        eprintln!("Vault is empty. Use `canus-lupus vault set <path> <value>` to add a secret.");
        return Ok(());
    }
    for p in &paths {
        println!("{p}");
    }
    Ok(())
}

fn run_rm(args: &RmArgs) -> anyhow::Result<()> {
    vault::rm(&args.path)?;
    eprintln!("Removed secret '{}'.", args.path);
    Ok(())
}
