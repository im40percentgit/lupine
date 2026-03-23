//! Vault storage engine for canus-lupus.
//!
//! Secrets are stored in `~/.canus-lupus/vault/` (or `$CANUS_LUPUS_HOME/vault/`)
//! as encrypted files. Each secret's logical path (e.g. `api/openai`) maps to
//! a file at `vault/api/openai.enc` containing the `lupine::easy` sealed output
//! encrypted to the "default" KEM public key.
//!
//! # Directory layout
//!
//! ```text
//! ~/.canus-lupus/
//!   keys/
//!     default.kem_sk.pem
//!     default.kem_pk.pem
//!     ...
//!   vault/               ← mode 0700
//!     api/
//!       openai.enc       ← sealed secret bytes
//!       github.enc
//!     db/
//!       prod.enc
//! ```
//!
//! # Wire format
//!
//! Each `.enc` file contains the raw output of `lupine::easy::encrypt()` — a
//! self-describing v1 sealed message (version byte + KEM ciphertext + nonce +
//! AEAD ciphertext). No additional framing is added.
//!
//! # Path rules
//!
//! Secret paths are slash-separated identifiers, e.g. `api/openai`. The
//! following constraints are enforced to prevent path traversal:
//! - Components must not be empty.
//! - No component may be `.` or `..`.
//! - Components must not contain null bytes or filesystem-reserved characters.
//!
//! @decision DEC-VAULT-001
//! @title Encrypt vault entries to the default KEM public key
//! @status accepted
//! @rationale Vault secrets must be decryptable by the key owner without
//!   requiring a passphrase at access time (the KEM secret key is already on
//!   disk). Encrypting each entry to the "default" KEM public key means
//!   `vault get` only needs `default.kem_sk.pem` — the same key used by
//!   `decrypt`. This ties vault access to KEM key possession, consistent with
//!   the overall canus-lupus security model.
//!
//! @decision DEC-VAULT-002
//! @title Hierarchical paths stored as directory trees
//! @status accepted
//! @rationale Logical paths like `api/openai` map directly to filesystem paths
//!   (`vault/api/openai.enc`). This makes `vault list` a simple recursive
//!   directory walk and allows OS-level permissions on subdirectories. An
//!   alternative (flat namespace with encoded names) would be simpler to
//!   implement but loses the natural grouping that hierarchical paths provide.
//!   Path traversal is prevented by component validation (no `..`, no empty
//!   components) rather than sandboxing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keystore;

// ── Directory helpers ─────────────────────────────────────────────────────────

/// Returns the vault directory path (does NOT create it).
pub fn vault_dir() -> Result<PathBuf> {
    Ok(keystore::home_dir()?.join("vault"))
}

/// Creates `path` (and all parents) with mode 0700 on Unix.
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

/// Write `data` to `path` with mode 0600 on Unix (creates parent dirs first).
#[cfg(unix)]
fn write_private_bytes(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        ensure_dir_private(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot open {} for writing", path.display()))?;
    std::io::Write::write_all(&mut f, data)
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_bytes(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create directory {}", parent.display()))?;
    }
    fs::write(path, data).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

// ── Path validation ───────────────────────────────────────────────────────────

/// Validates a user-supplied secret path and returns the corresponding `.enc`
/// file path within the vault directory.
///
/// Rejects paths that contain `..`, empty components, or null bytes. The vault
/// directory itself need not exist at this point.
///
/// # Errors
///
/// Returns an error if any path component is unsafe or if the vault directory
/// cannot be determined.
pub fn resolve_secret_path(vault_root: &Path, secret_path: &str) -> Result<PathBuf> {
    if secret_path.is_empty() {
        bail!("secret path must not be empty");
    }

    // Split on '/' and validate each component.
    let components: Vec<&str> = secret_path.split('/').collect();
    for component in &components {
        if component.is_empty() {
            bail!("secret path must not contain empty components (double slash or leading/trailing slash): '{secret_path}'");
        }
        if *component == ".." || *component == "." {
            bail!("secret path must not contain '.' or '..' components: '{secret_path}'");
        }
        if component.contains('\0') {
            bail!("secret path must not contain null bytes: '{secret_path}'");
        }
        // Reject Windows-style reserved characters and backslash for portability.
        if component.contains('\\') {
            bail!("secret path must not contain backslashes: '{secret_path}'");
        }
    }

    // Build the on-disk path: vault_root / component1 / component2 / ... .enc
    let mut path = vault_root.to_path_buf();
    for component in &components {
        path.push(component);
    }
    // Append .enc extension to the leaf.
    let leaf_name = format!(
        "{}.enc",
        path.file_name()
            .expect("path always has a file name after component push")
            .to_string_lossy()
    );
    path.set_file_name(leaf_name);

    Ok(path)
}

// ── Public vault operations ───────────────────────────────────────────────────

/// Initialize the vault directory.
///
/// Creates `$CANUS_LUPUS_HOME/vault/` with mode 0700. Checks that the default
/// KEM secret key exists (the vault cannot function without it).
///
/// Returns an error if the default keypair is absent. The vault directory is
/// created regardless — subsequent `keygen` + `vault init` will succeed.
pub fn init() -> Result<()> {
    let dir = vault_dir()?;
    ensure_dir_private(&dir)?;

    // Verify the default KEM secret key is accessible. We don't load it — that
    // would be slow — just check that the file exists.
    let kem_sk_path = keystore::key_path("default", "kem_sk.pem")?;
    if !kem_sk_path.exists() {
        bail!(
            "default keypair not found at {}.\n\
             Run `canus-lupus keygen` first to create a keypair.",
            kem_sk_path.display()
        );
    }

    Ok(())
}

/// Store a secret in the vault.
///
/// Encrypts `plaintext` to the default KEM public key and writes the sealed
/// output to `<vault_dir>/<secret_path>.enc`. Creates parent directories as
/// needed. Overwrites any existing entry silently.
///
/// The vault directory must exist (run `vault init` first). The default
/// keypair must be present.
pub fn set(secret_path: &str, plaintext: &[u8]) -> Result<()> {
    let dir = vault_dir()?;
    if !dir.exists() {
        bail!(
            "vault directory {} not found — run `canus-lupus vault init` first",
            dir.display()
        );
    }

    let enc_path = resolve_secret_path(&dir, secret_path)?;

    // Load the default KEM public key for encryption.
    let kem_pk = keystore::load_kem_pk("default")
        .context("cannot load default KEM public key for vault encryption")?;

    let sealed = lupine::easy::encrypt(&kem_pk, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    write_private_bytes(&enc_path, &sealed)?;
    Ok(())
}

/// Retrieve a secret from the vault, returning the plaintext bytes.
///
/// Loads the default KEM secret key, reads the `.enc` file at
/// `<vault_dir>/<secret_path>.enc`, and decrypts it.
pub fn get(secret_path: &str) -> Result<Vec<u8>> {
    let dir = vault_dir()?;
    let enc_path = resolve_secret_path(&dir, secret_path)?;

    if !enc_path.exists() {
        bail!(
            "no vault entry for '{}' (expected {})",
            secret_path,
            enc_path.display()
        );
    }

    let sealed = fs::read(&enc_path)
        .with_context(|| format!("cannot read vault entry {}", enc_path.display()))?;

    let kem_sk = keystore::load_kem_sk("default")
        .context("cannot load default KEM secret key for vault decryption")?;

    let plaintext = lupine::easy::decrypt(&kem_sk, &sealed)
        .map_err(|e| anyhow::anyhow!("vault decryption failed: {e}"))?;

    Ok(plaintext)
}

/// List all secret paths stored in the vault.
///
/// Walks the vault directory recursively, returning sorted logical paths
/// (e.g. `api/openai`, `db/prod`) with the `.enc` suffix stripped and the
/// vault root prefix removed.
///
/// Returns an empty `Vec` if the vault directory does not exist.
pub fn list() -> Result<Vec<String>> {
    let dir = vault_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    collect_entries(&dir, &dir, &mut paths)?;
    paths.sort();
    Ok(paths)
}

/// Recursively collect `.enc` file paths relative to `root` into `out`.
fn collect_entries(root: &Path, current: &Path, out: &mut Vec<String>) -> Result<()> {
    let read_dir = match fs::read_dir(current) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot list {}", current.display())),
    };

    for entry in read_dir {
        let entry = entry.context("directory entry error")?;
        let file_type = entry.file_type().context("cannot get file type")?;
        let path = entry.path();

        if file_type.is_dir() {
            collect_entries(root, &path, out)?;
        } else if file_type.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(stem) = name.strip_suffix(".enc") {
                    // Compute path relative to vault root, then replace OS
                    // separators with '/' for a portable display format.
                    let rel = path
                        .parent()
                        .and_then(|p| p.strip_prefix(root).ok())
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();

                    let logical = if rel.is_empty() {
                        stem.to_string()
                    } else {
                        // On Windows, rel may use backslashes; normalize.
                        let rel_normalized = rel.replace('\\', "/");
                        format!("{rel_normalized}/{stem}")
                    };
                    out.push(logical);
                }
            }
        }
    }
    Ok(())
}

/// Remove a secret from the vault.
///
/// Deletes the `.enc` file at `<vault_dir>/<secret_path>.enc`. Removes any
/// parent directories that become empty after deletion (up to but not including
/// the vault root). Returns an error if the entry does not exist.
pub fn rm(secret_path: &str) -> Result<()> {
    let dir = vault_dir()?;
    let enc_path = resolve_secret_path(&dir, secret_path)?;

    if !enc_path.exists() {
        bail!(
            "no vault entry for '{}' (expected {})",
            secret_path,
            enc_path.display()
        );
    }

    fs::remove_file(&enc_path).with_context(|| format!("cannot remove {}", enc_path.display()))?;

    // Clean up empty parent directories up to (but not including) the vault root.
    prune_empty_dirs(enc_path.parent().unwrap_or(&dir), &dir);

    Ok(())
}

/// Walk up from `dir` toward `stop`, removing each directory that is empty.
///
/// Stops at `stop` — the vault root is never removed.
fn prune_empty_dirs(mut dir: &Path, stop: &Path) {
    while dir != stop {
        match fs::remove_dir(dir) {
            Ok(()) => {}
            Err(_) => break, // not empty or permission error — stop climbing
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_secret_path_simple() {
        let root = Path::new("/tmp/vault");
        let p = resolve_secret_path(root, "api/openai").unwrap();
        assert_eq!(p, Path::new("/tmp/vault/api/openai.enc"));
    }

    #[test]
    fn resolve_secret_path_top_level() {
        let root = Path::new("/tmp/vault");
        let p = resolve_secret_path(root, "mykey").unwrap();
        assert_eq!(p, Path::new("/tmp/vault/mykey.enc"));
    }

    #[test]
    fn resolve_secret_path_deep() {
        let root = Path::new("/tmp/vault");
        let p = resolve_secret_path(root, "a/b/c").unwrap();
        assert_eq!(p, Path::new("/tmp/vault/a/b/c.enc"));
    }

    #[test]
    fn resolve_secret_path_rejects_dotdot() {
        let root = Path::new("/tmp/vault");
        assert!(resolve_secret_path(root, "../escape").is_err());
        assert!(resolve_secret_path(root, "api/../etc/passwd").is_err());
    }

    #[test]
    fn resolve_secret_path_rejects_dot() {
        let root = Path::new("/tmp/vault");
        assert!(resolve_secret_path(root, "./local").is_err());
    }

    #[test]
    fn resolve_secret_path_rejects_empty_component() {
        let root = Path::new("/tmp/vault");
        assert!(resolve_secret_path(root, "api//openai").is_err());
        assert!(resolve_secret_path(root, "/leading").is_err());
        assert!(resolve_secret_path(root, "trailing/").is_err());
    }

    #[test]
    fn resolve_secret_path_rejects_empty_path() {
        let root = Path::new("/tmp/vault");
        assert!(resolve_secret_path(root, "").is_err());
    }

    #[test]
    fn prune_empty_dirs_stops_at_vault_root() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let deep = vault.join("a").join("b");
        fs::create_dir_all(&deep).unwrap();

        // prune starting from b — should remove b and a, stop at vault.
        prune_empty_dirs(&deep, &vault);
        assert!(!vault.join("a").exists(), "empty 'a' should be pruned");
        assert!(vault.exists(), "vault root must not be removed");
    }
}
