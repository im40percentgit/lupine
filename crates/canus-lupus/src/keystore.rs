//! Local key storage engine for canus-lupus.
//!
//! Keys are stored in a directory (default `~/.canus-lupus/keys/`) as PEM
//! files, one file per key component:
//!
//! ```text
//! ~/.canus-lupus/keys/
//!   default.kem_sk.pem    — KEM decapsulation (secret) key
//!   default.kem_pk.pem    — KEM encapsulation (public) key
//!   default.sign_sk.pem   — signing (secret) key
//!   default.sign_pk.pem   — verifying (public) key
//!   alice.kem_pk.pem      — imported public key (KEM component)
//!   alice.sign_pk.pem     — imported public key (sign component)
//! ```
//!
//! Imported / exported keys are named by the `--name` argument. The default
//! keypair is named `"default"`.
//!
//! # Security note
//!
//! Secret key files are written with mode 0600 (Unix). The keystore directory
//! is created with mode 0700. Private key bytes are not passphrase-protected
//! in this MVP; that is deferred to a future layer.
//!
//! @decision DEC-KEYSTORE-001
//! @title PEM storage with raw key bytes (no DER wrapper)
//! @status accepted
//! @rationale The keystore owns both ends of the serialization contract, so it
//!   does not need the DER algorithm-identifier wrapper that lupine-serial adds
//!   for interop with external tools. Storing raw `to_bytes()` output inside
//!   PEM envelopes is simpler and produces smaller files. The PEM label still
//!   encodes the key type ("PUBLIC KEY" / "PRIVATE KEY"), giving human readers
//!   enough context. If DER interop becomes necessary in a future phase, the
//!   keystore can migrate by re-encoding existing files on load.
//!
//! @decision DEC-KEYSTORE-002
//! @title Always load KEM SK and KEM PK together
//! @status accepted
//! @rationale `HybridKemSecretKey::from_bytes()` leaves `mlkem_pk_bytes` empty
//!   after deserialization, which causes `decapsulate()` to fail with
//!   `Error::InvalidKey`. The keystore's `load_keypair()` and `load_kem_sk()`
//!   functions always load the matching public key alongside the secret key
//!   and call `set_mlkem_pk_bytes()` to restore the cached bytes. This is an
//!   inherent constraint of the hybrid KEM design and is documented here so
//!   callers don't need to know about it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use lupine::easy::{self, Keypair};
use lupine_serial::pem;
use zeroize::Zeroize;

// Re-export the key types so callers can use them without importing lupine directly.
pub use lupine_kem::hybrid::{HybridKemPublicKey768, HybridKemSecretKey768};
pub use lupine_sign::hybrid::{HybridSigningKey65, HybridVerifyingKey65};

// ── Directory helpers ─────────────────────────────────────────────────────────

/// Returns the canus-lupus home directory.
///
/// Respects the `CANUS_LUPUS_HOME` environment variable (used in tests).
/// Falls back to `~/.canus-lupus/`.
pub fn home_dir() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("CANUS_LUPUS_HOME") {
        return Ok(PathBuf::from(custom));
    }
    let home =
        dirs_next::home_dir().context("cannot determine home directory (set CANUS_LUPUS_HOME)")?;
    Ok(home.join(".canus-lupus"))
}

/// Returns the keys subdirectory, creating it (mode 0700) if absent.
pub fn keys_dir() -> Result<PathBuf> {
    let dir = home_dir()?.join("keys");
    ensure_dir_private(&dir)?;
    Ok(dir)
}

/// Creates a directory (and all parents) with mode 0700 on Unix.
#[cfg(unix)]
fn ensure_dir_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("cannot create directory {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_dir_private(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("cannot create directory {}", path.display()))?;
    Ok(())
}

// ── File paths ────────────────────────────────────────────────────────────────

/// Returns the path to a key file for `name` and `suffix` (e.g. `"kem_sk.pem"`).
pub fn key_path(name: &str, suffix: &str) -> Result<PathBuf> {
    Ok(keys_dir()?.join(format!("{name}.{suffix}")))
}

// ── Write helpers ─────────────────────────────────────────────────────────────

/// Write `content` to `path` with mode 0600 on Unix, replacing any existing file.
#[cfg(unix)]
fn write_private_file(path: &Path, content: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    std::io::Write::write_all(&mut f, content.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

// ── Keypair persistence ───────────────────────────────────────────────────────

/// Save a full `Keypair` under `name` in the keys directory.
///
/// Writes four PEM files:
/// - `{name}.kem_sk.pem` (PRIVATE KEY)
/// - `{name}.kem_pk.pem` (PUBLIC KEY)
/// - `{name}.sign_sk.pem` (PRIVATE KEY)
/// - `{name}.sign_pk.pem` (PUBLIC KEY)
pub fn save_keypair(name: &str, kp: &Keypair) -> Result<()> {
    let kem_sk_pem =
        pem::encode_private_key_pem(&kp.kem_sk.to_bytes()).context("PEM encode kem_sk")?;
    let kem_pk_pem =
        pem::encode_public_key_pem(&kp.kem_pk.to_bytes()).context("PEM encode kem_pk")?;
    let sign_sk_pem =
        pem::encode_private_key_pem(&kp.sign_sk.to_bytes()).context("PEM encode sign_sk")?;
    let sign_pk_pem =
        pem::encode_public_key_pem(&kp.sign_pk.to_bytes()).context("PEM encode sign_pk")?;

    write_private_file(&key_path(name, "kem_sk.pem")?, &kem_sk_pem)?;
    write_private_file(&key_path(name, "kem_pk.pem")?, &kem_pk_pem)?;
    write_private_file(&key_path(name, "sign_sk.pem")?, &sign_sk_pem)?;
    write_private_file(&key_path(name, "sign_pk.pem")?, &sign_pk_pem)?;
    Ok(())
}

/// Load a full `Keypair` by name.
///
/// All four PEM files must exist. The KEM secret key is loaded together with
/// its public key so that `set_mlkem_pk_bytes()` can be called (see
/// DEC-KEYSTORE-002).
///
/// Currently used by integration tests and reserved for future vault commands.
#[allow(dead_code)]
pub fn load_keypair(name: &str) -> Result<easy::Keypair> {
    let kem_sk = load_kem_sk(name)?;
    let kem_pk = load_kem_pk(name)?;
    let sign_sk = load_sign_sk(name)?;
    let sign_pk = load_sign_pk(name)?;
    Ok(Keypair {
        kem_sk,
        kem_pk,
        sign_sk,
        sign_pk,
    })
}

// ── Individual key loaders ────────────────────────────────────────────────────

/// Load and deserialize the KEM secret key for `name`.
///
/// Also loads the matching KEM public key to restore `mlkem_pk_bytes`
/// (required for decapsulation — see DEC-KEYSTORE-002).
pub fn load_kem_sk(name: &str) -> Result<HybridKemSecretKey768> {
    let sk_path = key_path(name, "kem_sk.pem")?;
    let pk_path = key_path(name, "kem_pk.pem")?;

    let sk_pem = fs::read_to_string(&sk_path)
        .with_context(|| format!("cannot read {}", sk_path.display()))?;
    let pk_pem = fs::read_to_string(&pk_path).with_context(|| {
        format!(
            "cannot read {} (needed to restore KEM pk bytes)",
            pk_path.display()
        )
    })?;

    let mut sk_bytes = pem::decode_private_key_pem(&sk_pem)
        .map_err(|e| anyhow::anyhow!("PEM decode kem_sk: {e}"))?;
    let pk_bytes = pem::decode_public_key_pem(&pk_pem)
        .map_err(|e| anyhow::anyhow!("PEM decode kem_pk: {e}"))?;

    let sk_result = HybridKemSecretKey768::from_bytes(&sk_bytes)
        .map_err(|e| anyhow::anyhow!("deserialize kem_sk: {e}"));

    // Zeroize the raw secret key bytes now that they have been consumed by
    // HybridKemSecretKey768::from_bytes(). The deserialized key owns its own
    // copy; this Vec no longer needs to hold sensitive material.
    sk_bytes.zeroize();

    let mut sk = sk_result?;

    // Restore mlkem_pk_bytes from the public key file so decapsulation works.
    // The ML-KEM pk bytes are the X25519-pk-stripped suffix of the full pk bytes.
    // HybridKemPublicKey768 stores: 32 bytes X25519 pk || ML-KEM pk bytes.
    if pk_bytes.len() < 32 {
        bail!("kem_pk.pem is too short to extract ML-KEM component");
    }
    let mlkem_pk_bytes = pk_bytes[32..].to_vec();
    sk.set_mlkem_pk_bytes(mlkem_pk_bytes);

    Ok(sk)
}

/// Load and deserialize the KEM public key for `name`.
pub fn load_kem_pk(name: &str) -> Result<HybridKemPublicKey768> {
    let path = key_path(name, "kem_pk.pem")?;
    let pem_str =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let bytes = pem::decode_public_key_pem(&pem_str)
        .map_err(|e| anyhow::anyhow!("PEM decode kem_pk: {e}"))?;
    HybridKemPublicKey768::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("deserialize kem_pk: {e}"))
}

/// Load and deserialize the signing secret key for `name`.
pub fn load_sign_sk(name: &str) -> Result<HybridSigningKey65> {
    let path = key_path(name, "sign_sk.pem")?;
    let pem_str =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut bytes = pem::decode_private_key_pem(&pem_str)
        .map_err(|e| anyhow::anyhow!("PEM decode sign_sk: {e}"))?;
    let sk_result =
        HybridSigningKey65::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("deserialize sign_sk: {e}"));
    // Zeroize the raw secret key bytes now that they have been consumed by
    // HybridSigningKey65::from_bytes(). The deserialized key holds its own copy.
    bytes.zeroize();
    sk_result
}

/// Load and deserialize the signing verifying key for `name`.
pub fn load_sign_pk(name: &str) -> Result<HybridVerifyingKey65> {
    let path = key_path(name, "sign_pk.pem")?;
    let pem_str =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let bytes = pem::decode_public_key_pem(&pem_str)
        .map_err(|e| anyhow::anyhow!("PEM decode sign_pk: {e}"))?;
    HybridVerifyingKey65::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("deserialize sign_pk: {e}"))
}

/// Save a `HybridKemPublicKey768` as `{name}.kem_pk.pem`.
///
/// Used when importing a recipient's KEM public key.
pub fn save_kem_pk(name: &str, pk: &HybridKemPublicKey768) -> Result<()> {
    let pem_str = pem::encode_public_key_pem(&pk.to_bytes()).context("PEM encode kem_pk")?;
    // Public keys are not secret, but we write them with the same helper for
    // simplicity. We use a regular write on non-Unix since mode is irrelevant.
    let path = key_path(name, "kem_pk.pem")?;
    fs::write(&path, &pem_str).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Save a `HybridVerifyingKey65` as `{name}.sign_pk.pem`.
///
/// Used when importing a recipient's sign public key.
pub fn save_sign_pk(name: &str, pk: &HybridVerifyingKey65) -> Result<()> {
    let pem_str = pem::encode_public_key_pem(&pk.to_bytes()).context("PEM encode sign_pk")?;
    let path = key_path(name, "sign_pk.pem")?;
    fs::write(&path, &pem_str).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

// ── Key listing ───────────────────────────────────────────────────────────────

/// A summary of one key entry in the keystore.
#[derive(Debug)]
pub struct KeyEntry {
    /// The keypair or key name (e.g. `"default"`, `"alice"`).
    pub name: String,
    /// True if a full keypair (both sk and pk) is present.
    pub has_secret: bool,
}

/// List all named key entries in the keystore.
///
/// An entry is any name `N` for which at least `{N}.kem_pk.pem` exists.
pub fn list_keys() -> Result<Vec<KeyEntry>> {
    let dir = keys_dir()?;
    let mut entries: Vec<KeyEntry> = Vec::new();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    let read_dir = fs::read_dir(&dir).with_context(|| format!("cannot list {}", dir.display()))?;

    for entry in read_dir {
        let entry = entry.context("directory entry error")?;
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        // We look for *.kem_pk.pem to identify entries (every entry has a pk).
        if let Some(name) = fname_str.strip_suffix(".kem_pk.pem") {
            if seen_names.insert(name.to_string()) {
                let sk_path = dir.join(format!("{name}.kem_sk.pem"));
                let has_secret = sk_path.exists();
                entries.push(KeyEntry {
                    name: name.to_string(),
                    has_secret,
                });
            }
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

// ── Key existence check ───────────────────────────────────────────────────────

/// Returns true if all four key files for `name` exist.
pub fn keypair_exists(name: &str) -> Result<bool> {
    Ok(key_path(name, "kem_sk.pem")?.exists()
        && key_path(name, "kem_pk.pem")?.exists()
        && key_path(name, "sign_sk.pem")?.exists()
        && key_path(name, "sign_pk.pem")?.exists())
}
