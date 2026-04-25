//! `canus-lupus age` — age-compatible keypair management and encryption.
//!
//! Provides three subcommands that use the age key format from
//! `age-plugin-lupine` together with the existing `lupine::easy` KEM-DEM
//! construction for actual encryption:
//!
//! - `age keygen`   — generate a hybrid KEM keypair, print in age format
//! - `age encrypt`  — decrypt stdin with a recipient string (`age1lupine1…`)
//! - `age decrypt`  — decrypt stdin with an identity file (`AGE-PLUGIN-LUPINE-1…`)
//!
//! # Wire format
//!
//! `age encrypt` / `age decrypt` use the `lupine::easy` v1 sealed format
//! (same as `canus-lupus encrypt` / `canus-lupus decrypt`). The age key
//! strings are purely a key-encoding layer on top; the ciphertext is
//! identical to what the keystore-based commands produce.
//!
//! @decision DEC-CLI-030
//! @title age subcommand reuses lupine::easy wire format
//! @status accepted
//! @rationale The age plugin protocol (stdin/stdout state-machine) is a full
//!   implementation concern orthogonal to this CLI. For `canus-lupus age`,
//!   we provide age-*format* key management (bech32 encoded, compatible with
//!   age tool conventions) while reusing the existing `lupine::easy` v1 KEM-DEM
//!   construction for the actual encryption. This gives users a simple
//!   self-contained encrypt/decrypt path with keys they can share in age
//!   recipient format, without pulling in the full age plugin machinery.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use age_plugin_lupine::keys::{
    decode_identity, decode_recipient, encode_identity, encode_recipient,
};
use clap::{Args, Subcommand};
use lupine_kem::hybrid::generate_keypair;
use ml_kem::MlKem768;
use rand::rngs::OsRng;

/// Arguments for the `age` subcommand group.
#[derive(Debug, Args)]
pub struct AgeArgs {
    #[command(subcommand)]
    pub command: AgeCommand,
}

/// Subcommands available under `canus-lupus age`.
#[derive(Debug, Subcommand)]
pub enum AgeCommand {
    /// Generate an age-compatible hybrid KEM keypair.
    Keygen(KeygenArgs),
    /// Encrypt stdin to stdout using an age recipient string.
    Encrypt(EncryptArgs),
    /// Decrypt stdin to stdout using an age identity file.
    Decrypt(DecryptArgs),
}

// ── keygen ────────────────────────────────────────────────────────────────────

/// Arguments for `age keygen`.
#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Write the identity (secret key) to this file instead of stdout.
    ///
    /// The recipient (public key) is always printed as a comment on stderr.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

fn run_keygen(args: &KeygenArgs) -> anyhow::Result<()> {
    let (sk, pk) = generate_keypair::<MlKem768>(&mut OsRng)
        .map_err(|e| anyhow::anyhow!("key generation failed: {e}"))?;

    let identity = encode_identity(&sk, &pk);
    let recipient = encode_recipient(&pk);

    // Always print recipient on stderr so the user can share it.
    eprintln!("# Recipient: {recipient}");

    // Write identity to file or stdout.
    match &args.output {
        Some(path) => {
            let mut content = String::new();
            content.push_str(&format!("# Recipient: {recipient}\n"));
            content.push_str(&format!("{identity}\n"));
            std::fs::write(path, &content).map_err(|e| {
                anyhow::anyhow!("cannot write identity to '{}': {e}", path.display())
            })?;
            eprintln!("Identity written to {}", path.display());
        }
        None => {
            println!("# Recipient: {recipient}");
            println!("{identity}");
        }
    }

    Ok(())
}

// ── encrypt ───────────────────────────────────────────────────────────────────

/// Arguments for `age encrypt`.
#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// Recipient string (age1lupine1…).
    #[arg(short, long)]
    pub recipient: String,

    /// Write ciphertext to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

fn run_encrypt(args: &EncryptArgs) -> anyhow::Result<()> {
    // Decode the age recipient string to a hybrid public key.
    let pk = decode_recipient(&args.recipient)
        .map_err(|e| anyhow::anyhow!("invalid recipient '{}': {e}", args.recipient))?;

    // Read plaintext from stdin.
    let mut plaintext = Vec::new();
    io::stdin()
        .read_to_end(&mut plaintext)
        .map_err(|e| anyhow::anyhow!("cannot read stdin: {e}"))?;

    // Encrypt using the lupine::easy v1 KEM-DEM construction.
    let sealed = lupine::easy::encrypt(&pk, &plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    // Write sealed message to file or stdout.
    match &args.output {
        Some(path) => {
            std::fs::write(path, &sealed)
                .map_err(|e| anyhow::anyhow!("cannot write '{}': {e}", path.display()))?;
            eprintln!(
                "Encrypted {} bytes → {} ({} bytes sealed)",
                plaintext.len(),
                path.display(),
                sealed.len()
            );
        }
        None => {
            io::stdout()
                .write_all(&sealed)
                .map_err(|e| anyhow::anyhow!("cannot write to stdout: {e}"))?;
        }
    }

    Ok(())
}

// ── decrypt ───────────────────────────────────────────────────────────────────

/// Arguments for `age decrypt`.
#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// Identity file containing an AGE-PLUGIN-LUPINE-1… string.
    #[arg(short = 'i', long)]
    pub identity: PathBuf,

    /// Write plaintext to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

fn run_decrypt(args: &DecryptArgs) -> anyhow::Result<()> {
    // Read and parse the identity file.
    let identity_str = std::fs::read_to_string(&args.identity).map_err(|e| {
        anyhow::anyhow!(
            "cannot read identity file '{}': {e}",
            args.identity.display()
        )
    })?;

    // Extract the identity line: the first non-comment, non-empty line.
    let identity_line = identity_str
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .ok_or_else(|| anyhow::anyhow!("identity file contains no identity line"))?;

    let sk = decode_identity(identity_line.trim())
        .map_err(|e| anyhow::anyhow!("invalid identity in '{}': {e}", args.identity.display()))?;

    // Read sealed message from stdin.
    let mut sealed = Vec::new();
    io::stdin()
        .read_to_end(&mut sealed)
        .map_err(|e| anyhow::anyhow!("cannot read stdin: {e}"))?;

    // Decrypt using the lupine::easy v1 KEM-DEM construction.
    let plaintext = lupine::easy::decrypt(&sk, &sealed)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

    // Write plaintext to file or stdout.
    match &args.output {
        Some(path) => {
            std::fs::write(path, &plaintext)
                .map_err(|e| anyhow::anyhow!("cannot write '{}': {e}", path.display()))?;
            eprintln!("Decrypted {} bytes → {}", plaintext.len(), path.display());
        }
        None => {
            io::stdout()
                .write_all(&plaintext)
                .map_err(|e| anyhow::anyhow!("cannot write to stdout: {e}"))?;
        }
    }

    Ok(())
}

// ── dispatch ──────────────────────────────────────────────────────────────────

/// Dispatch the parsed `age` subcommand to the appropriate handler.
pub fn run(args: &AgeArgs) -> anyhow::Result<()> {
    match &args.command {
        AgeCommand::Keygen(a) => run_keygen(a),
        AgeCommand::Encrypt(a) => run_encrypt(a),
        AgeCommand::Decrypt(a) => run_decrypt(a),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Spawn the given closure on a thread with a 32 MB stack.
    ///
    /// ML-KEM-768 key generation allocates large on-stack intermediates in
    /// debug builds that can exceed the default 8 MB stack on some platforms.
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    /// keygen → encrypt → decrypt round-trip using file I/O.
    ///
    /// 1. Generate a keypair via keygen and write the identity to a temp file.
    /// 2. Extract the recipient string from the identity file.
    /// 3. Encrypt a known plaintext using that recipient.
    /// 4. Decrypt the ciphertext using the identity file.
    /// 5. Assert the recovered plaintext matches the original.
    #[test]
    fn age_keygen_encrypt_decrypt_roundtrip() {
        with_large_stack(|| {
            // ── Step 1: keygen ────────────────────────────────────────────────
            let identity_file = NamedTempFile::new().expect("tempfile");
            let keygen_args = KeygenArgs {
                output: Some(identity_file.path().to_path_buf()),
            };
            run_keygen(&keygen_args).expect("keygen must succeed");

            // ── Step 2: extract recipient from identity file ──────────────────
            let contents = std::fs::read_to_string(identity_file.path()).expect("read identity");
            let recipient = contents
                .lines()
                .find(|l| l.starts_with("# Recipient:"))
                .expect("identity file must contain recipient comment")
                .trim_start_matches("# Recipient:")
                .trim()
                .to_string();
            assert!(
                recipient.starts_with("age1lupine1"),
                "recipient must start with age1lupine1, got: {recipient}"
            );

            // ── Step 3: encrypt ───────────────────────────────────────────────
            let plaintext = b"lupine age round-trip test payload";

            let pk = decode_recipient(&recipient).expect("decode recipient");
            let sealed = lupine::easy::encrypt(&pk, plaintext).expect("encrypt");

            // ── Step 4: decrypt ───────────────────────────────────────────────
            let identity_str =
                std::fs::read_to_string(identity_file.path()).expect("read identity");
            let identity_line = identity_str
                .lines()
                .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                .expect("identity line must exist");

            let sk = decode_identity(identity_line.trim()).expect("decode identity");
            let recovered = lupine::easy::decrypt(&sk, &sealed).expect("decrypt");

            // ── Step 5: assert ────────────────────────────────────────────────
            assert_eq!(
                recovered.as_slice(),
                plaintext.as_slice(),
                "recovered plaintext must match original"
            );
        });
    }

    /// Verify that decoding a recipient string and re-encoding it is stable.
    #[test]
    fn recipient_encode_decode_stable() {
        with_large_stack(|| {
            let (_, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
            let encoded = encode_recipient(&pk);
            let pk2 = decode_recipient(&encoded).expect("decode");
            assert_eq!(pk.to_bytes(), pk2.to_bytes());
        });
    }

    /// Encrypting with one key and decrypting with a different key must fail.
    #[test]
    fn decrypt_wrong_identity_fails() {
        with_large_stack(|| {
            let (_, pk_alice) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen alice");
            let (sk_bob, pk_bob) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen bob");

            // Encrypt for Alice.
            let sealed = lupine::easy::encrypt(&pk_alice, b"for alice only").expect("encrypt");

            // Restore Bob's sk with mlkem_pk_bytes so decapsulation can proceed.
            let bob_identity = encode_identity(&sk_bob, &pk_bob);
            let sk_bob_restored = decode_identity(&bob_identity).expect("decode bob identity");

            // Bob cannot decrypt Alice's message.
            let result = lupine::easy::decrypt(&sk_bob_restored, &sealed);
            assert!(result.is_err(), "decrypting with the wrong key must fail");
        });
    }
}
