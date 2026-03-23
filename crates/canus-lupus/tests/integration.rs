//! Integration tests for canus-lupus CLI.
//!
//! Each test spawns the `canus-lupus` binary via `std::process::Command` with
//! a temporary home directory (`CANUS_LUPUS_HOME`) so tests are isolated from
//! the real `~/.canus-lupus/` and from each other.
//!
//! # Stack note
//!
//! ML-DSA-65 requires a large stack in debug builds. The CLI itself spawns a
//! 32 MiB thread for all work, so the test process stack size is irrelevant.
//!
//! @decision DEC-TEST-001
//! @title Use CANUS_LUPUS_HOME env var for test isolation
//! @status accepted
//! @rationale Tests must not read or write `~/.canus-lupus/`. Setting
//!   `CANUS_LUPUS_HOME` to a `tempfile::tempdir()` path routes all keystore
//!   I/O to an ephemeral directory that is cleaned up after each test.
//!   This is lighter-weight than mocking the filesystem and tests the real
//!   code path end-to-end. The env var is documented in `keystore::home_dir()`.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Returns the path to the `canus-lupus` binary built for integration tests.
///
/// Cargo sets `CARGO_BIN_EXE_<name>` for binaries in the same package, where
/// `<name>` matches the binary name exactly (hyphens preserved). Falls back to
/// locating the binary relative to the test executable via `CARGO_TARGET_TMPDIR`
/// or by walking up from the test binary path.
fn canus_lupus_bin() -> std::path::PathBuf {
    // Cargo 1.72+ sets this reliably. Try both hyphen and underscore variants
    // since the exact key format has varied across Cargo versions.
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_canus-lupus") {
        return std::path::PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_canus_lupus") {
        return std::path::PathBuf::from(p);
    }

    // Fallback: locate via the test binary path. The test binary lives at
    // target/debug/deps/integration-<hash>; the canus-lupus binary is at
    // target/debug/canus-lupus.
    let test_exe = std::env::current_exe().expect("cannot get test exe path");
    // Walk up: .../target/debug/deps → .../target/debug
    let debug_dir = test_exe
        .parent() // deps/
        .and_then(|p| p.parent()) // debug/
        .expect("unexpected test binary path structure");

    let bin = debug_dir.join("canus-lupus");
    if bin.exists() {
        return bin;
    }

    panic!(
        "Cannot find canus-lupus binary. Tried:\n\
         - CARGO_BIN_EXE_canus-lupus env var\n\
         - CARGO_BIN_EXE_canus_lupus env var\n\
         - {}\n\
         Run `cargo test -p canus-lupus --test integration`",
        bin.display()
    );
}

/// Run canus-lupus with the given args and a custom CANUS_LUPUS_HOME.
/// Returns (exit_code, stdout, stderr).
fn run(home: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(canus_lupus_bin())
        .args(args)
        .env("CANUS_LUPUS_HOME", home)
        .output()
        .expect("failed to spawn canus-lupus");

    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

// ── keygen ────────────────────────────────────────────────────────────────────

#[test]
fn keygen_creates_four_pem_files() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run(dir.path(), &["keygen"]);
    assert_eq!(code, 0, "keygen must exit 0; stderr: {stderr}");

    let keys_dir = dir.path().join("keys");
    assert!(
        keys_dir.join("default.kem_sk.pem").exists(),
        "kem_sk.pem missing"
    );
    assert!(
        keys_dir.join("default.kem_pk.pem").exists(),
        "kem_pk.pem missing"
    );
    assert!(
        keys_dir.join("default.sign_sk.pem").exists(),
        "sign_sk.pem missing"
    );
    assert!(
        keys_dir.join("default.sign_pk.pem").exists(),
        "sign_pk.pem missing"
    );
}

#[test]
fn keygen_named_keypair() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run(dir.path(), &["keygen", "--name", "alice"]);
    assert_eq!(code, 0, "keygen --name alice must exit 0; stderr: {stderr}");

    let keys_dir = dir.path().join("keys");
    assert!(keys_dir.join("alice.kem_sk.pem").exists());
    assert!(keys_dir.join("alice.kem_pk.pem").exists());
}

#[test]
fn keygen_refuses_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    let (code, _stdout, _stderr) = run(dir.path(), &["keygen"]);
    assert_ne!(code, 0, "second keygen without --force must fail");
}

#[test]
fn keygen_force_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    let (code, _stdout, stderr) = run(dir.path(), &["keygen", "--force"]);
    assert_eq!(code, 0, "keygen --force must exit 0; stderr: {stderr}");
}

#[test]
fn pem_files_have_correct_labels() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    let keys_dir = dir.path().join("keys");
    let kem_sk = fs::read_to_string(keys_dir.join("default.kem_sk.pem")).unwrap();
    let kem_pk = fs::read_to_string(keys_dir.join("default.kem_pk.pem")).unwrap();
    let sign_sk = fs::read_to_string(keys_dir.join("default.sign_sk.pem")).unwrap();
    let sign_pk = fs::read_to_string(keys_dir.join("default.sign_pk.pem")).unwrap();

    assert!(
        kem_sk.starts_with("-----BEGIN PRIVATE KEY-----"),
        "kem_sk label wrong"
    );
    assert!(
        kem_pk.starts_with("-----BEGIN PUBLIC KEY-----"),
        "kem_pk label wrong"
    );
    assert!(
        sign_sk.starts_with("-----BEGIN PRIVATE KEY-----"),
        "sign_sk label wrong"
    );
    assert!(
        sign_pk.starts_with("-----BEGIN PUBLIC KEY-----"),
        "sign_pk label wrong"
    );
}

// ── encrypt / decrypt round-trip ─────────────────────────────────────────────

#[test]
fn encrypt_decrypt_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    // Write a plaintext file.
    let plain_path = dir.path().join("secret.txt");
    fs::write(&plain_path, b"hello post-quantum world").unwrap();

    // Encrypt.
    let (code, _stdout, stderr) = run(dir.path(), &["encrypt", plain_path.to_str().unwrap()]);
    assert_eq!(code, 0, "encrypt must exit 0; stderr: {stderr}");

    let enc_path = dir.path().join("secret.txt.enc");
    assert!(enc_path.exists(), "encrypted file must be created");

    // Decrypt.
    let dec_path = dir.path().join("secret.txt.dec");
    let (code, _stdout, stderr) = run(
        dir.path(),
        &[
            "decrypt",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "decrypt must exit 0; stderr: {stderr}");
    assert!(dec_path.exists(), "decrypted file must be created");

    let recovered = fs::read(&dec_path).unwrap();
    assert_eq!(recovered, b"hello post-quantum world");
}

#[test]
fn decrypt_strips_enc_extension_by_default() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    let plain_path = dir.path().join("notes.txt");
    fs::write(&plain_path, b"top secret notes").unwrap();

    run(dir.path(), &["encrypt", plain_path.to_str().unwrap()]);

    let enc_path = dir.path().join("notes.txt.enc");

    // Remove original so there's no conflict and default output path is clean.
    fs::remove_file(&plain_path).unwrap();

    let (code, _stdout, stderr) = run(dir.path(), &["decrypt", enc_path.to_str().unwrap()]);
    assert_eq!(code, 0, "decrypt must exit 0; stderr: {stderr}");

    // Default output should strip .enc → notes.txt.
    let recovered = fs::read(&plain_path).unwrap();
    assert_eq!(recovered, b"top secret notes");
}

#[test]
fn encrypt_for_named_recipient() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    // Generate Alice's and Bob's keypairs in separate home dirs.
    run(alice_dir.path(), &["keygen"]);
    run(bob_dir.path(), &["keygen"]);

    // Export Bob's public key bundle.
    let (code, bob_bundle, stderr) = run(bob_dir.path(), &["keys", "export"]);
    assert_eq!(code, 0, "keys export must exit 0; stderr: {stderr}");
    let bob_pub_path = alice_dir.path().join("bob.pub");
    fs::write(&bob_pub_path, &bob_bundle).unwrap();

    // Alice imports Bob's public key.
    let (code, _stdout, stderr) = run(
        alice_dir.path(),
        &[
            "keys",
            "import",
            bob_pub_path.to_str().unwrap(),
            "--name",
            "bob",
        ],
    );
    assert_eq!(code, 0, "keys import must exit 0; stderr: {stderr}");

    // Alice encrypts for Bob.
    let plain_path = alice_dir.path().join("for_bob.txt");
    fs::write(&plain_path, b"message for bob").unwrap();
    let (code, _stdout, stderr) = run(
        alice_dir.path(),
        &["encrypt", plain_path.to_str().unwrap(), "-r", "bob"],
    );
    assert_eq!(code, 0, "encrypt for bob must exit 0; stderr: {stderr}");

    // Copy the encrypted file to Bob's world.
    let enc_path = alice_dir.path().join("for_bob.txt.enc");
    let bob_enc_path = bob_dir.path().join("for_bob.txt.enc");
    fs::copy(&enc_path, &bob_enc_path).unwrap();

    // Bob decrypts.
    let dec_path = bob_dir.path().join("for_bob.txt");
    let (code, _stdout, stderr) = run(
        bob_dir.path(),
        &[
            "decrypt",
            bob_enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "bob decrypt must exit 0; stderr: {stderr}");

    let recovered = fs::read(&dec_path).unwrap();
    assert_eq!(recovered, b"message for bob");
}

// ── sign / verify round-trip ──────────────────────────────────────────────────

#[test]
fn sign_verify_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    let data_path = dir.path().join("release.tar.gz");
    fs::write(&data_path, b"fake release tarball").unwrap();

    // Sign.
    let (code, _stdout, stderr) = run(dir.path(), &["sign", data_path.to_str().unwrap()]);
    assert_eq!(code, 0, "sign must exit 0; stderr: {stderr}");

    let sig_path = dir.path().join("release.tar.gz.sig");
    assert!(sig_path.exists(), "signature file must be created");

    // Verify.
    let (code, _stdout, stderr) = run(dir.path(), &["verify", data_path.to_str().unwrap()]);
    assert_eq!(code, 0, "verify must exit 0; stderr: {stderr}");
}

#[test]
fn verify_detects_tampered_data() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    let data_path = dir.path().join("data.bin");
    fs::write(&data_path, b"original data").unwrap();
    run(dir.path(), &["sign", data_path.to_str().unwrap()]);

    // Tamper with the data.
    fs::write(&data_path, b"tampered data").unwrap();

    let (code, _stdout, _stderr) = run(dir.path(), &["verify", data_path.to_str().unwrap()]);
    assert_ne!(code, 0, "verify must fail on tampered data");
}

#[test]
fn verify_detects_tampered_signature() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    let data_path = dir.path().join("data.bin");
    fs::write(&data_path, b"some data").unwrap();
    run(dir.path(), &["sign", data_path.to_str().unwrap()]);

    // Tamper with the signature.
    let sig_path = dir.path().join("data.bin.sig");
    let mut sig = fs::read(&sig_path).unwrap();
    sig[0] ^= 0xFF;
    fs::write(&sig_path, &sig).unwrap();

    let (code, _stdout, _stderr) = run(dir.path(), &["verify", data_path.to_str().unwrap()]);
    assert_ne!(code, 0, "verify must fail on tampered signature");
}

// ── keys list / import / export ───────────────────────────────────────────────

#[test]
fn keys_list_shows_generated_keypairs() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["keygen", "--name", "alice"]);

    let (code, stdout, stderr) = run(dir.path(), &["keys", "list"]);
    assert_eq!(code, 0, "keys list must exit 0; stderr: {stderr}");

    assert!(stdout.contains("alice"), "keys list must show 'alice'");
    assert!(stdout.contains("default"), "keys list must show 'default'");
}

#[test]
fn keys_export_import_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    // Export public key bundle.
    let (code, bundle, stderr) = run(dir.path(), &["keys", "export"]);
    assert_eq!(code, 0, "keys export must exit 0; stderr: {stderr}");
    assert!(
        bundle.contains("-----BEGIN PUBLIC KEY-----"),
        "export must contain PEM"
    );

    // Write bundle to file and import it under a different name.
    let bundle_path = dir.path().join("default.pub");
    fs::write(&bundle_path, &bundle).unwrap();

    let (code, _stdout, stderr) = run(
        dir.path(),
        &[
            "keys",
            "import",
            bundle_path.to_str().unwrap(),
            "--name",
            "self-copy",
        ],
    );
    assert_eq!(code, 0, "keys import must exit 0; stderr: {stderr}");

    // The imported key should appear in `keys list`.
    let (code, stdout, _) = run(dir.path(), &["keys", "list"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("self-copy"),
        "imported key must appear in list"
    );
}

// ── error cases ───────────────────────────────────────────────────────────────

#[test]
fn decrypt_with_wrong_key_fails() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    run(alice_dir.path(), &["keygen"]);
    run(bob_dir.path(), &["keygen"]);

    // Alice encrypts for herself.
    let plain = alice_dir.path().join("secret.txt");
    fs::write(&plain, b"alice's secret").unwrap();
    run(alice_dir.path(), &["encrypt", plain.to_str().unwrap()]);

    // Copy Alice's encrypted file to Bob's world.
    let enc = alice_dir.path().join("secret.txt.enc");
    let bob_enc = bob_dir.path().join("secret.txt.enc");
    fs::copy(&enc, &bob_enc).unwrap();

    // Bob tries to decrypt — must fail.
    let dec = bob_dir.path().join("out.txt");
    let (code, _stdout, _stderr) = run(
        bob_dir.path(),
        &[
            "decrypt",
            bob_enc.to_str().unwrap(),
            "-o",
            dec.to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0, "decryption with wrong key must fail");
}

#[test]
fn encrypt_missing_key_gives_helpful_error() {
    let dir = tempfile::tempdir().unwrap();
    // No keygen — no keys exist.
    let plain = dir.path().join("f.txt");
    fs::write(&plain, b"data").unwrap();

    let (code, _stdout, stderr) = run(dir.path(), &["encrypt", plain.to_str().unwrap()]);
    assert_ne!(code, 0, "must fail when key is missing");
    assert!(
        stderr.contains("cannot load") || stderr.contains("cannot read"),
        "error must mention loading failure; stderr: {stderr}"
    );
}

// ── vault ─────────────────────────────────────────────────────────────────────

#[test]
fn vault_init_creates_vault_dir() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);

    let (code, _stdout, stderr) = run(dir.path(), &["vault", "init"]);
    assert_eq!(code, 0, "vault init must exit 0; stderr: {stderr}");

    let vault_dir = dir.path().join("vault");
    assert!(vault_dir.exists(), "vault directory must be created");
    assert!(vault_dir.is_dir(), "vault path must be a directory");
}

#[test]
fn vault_init_without_keypair_fails() {
    let dir = tempfile::tempdir().unwrap();
    // No keygen — no default keypair exists.
    let (code, _stdout, _stderr) = run(dir.path(), &["vault", "init"]);
    assert_ne!(code, 0, "vault init must fail when no keypair exists");
}

#[test]
fn vault_set_get_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["vault", "init"]);

    let (code, _stdout, stderr) = run(
        dir.path(),
        &["vault", "set", "api/openai", "sk-testvalue123"],
    );
    assert_eq!(code, 0, "vault set must exit 0; stderr: {stderr}");

    let enc_file = dir.path().join("vault").join("api").join("openai.enc");
    assert!(
        enc_file.exists(),
        "encrypted file must exist at vault/api/openai.enc"
    );

    let (code, stdout, stderr) = run(dir.path(), &["vault", "get", "api/openai"]);
    assert_eq!(code, 0, "vault get must exit 0; stderr: {stderr}");
    assert_eq!(
        stdout, "sk-testvalue123",
        "vault get must return exact plaintext"
    );
}

#[test]
fn vault_get_no_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["vault", "init"]);
    run(dir.path(), &["vault", "set", "tok", "abc"]);

    let (code, stdout, _stderr) = run(dir.path(), &["vault", "get", "tok"]);
    assert_eq!(code, 0);
    // stdout must be exactly "abc" with no trailing newline.
    assert_eq!(
        stdout.as_bytes(),
        b"abc",
        "vault get must produce no trailing newline"
    );
}

#[test]
fn vault_list_shows_stored_paths() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["vault", "init"]);
    run(dir.path(), &["vault", "set", "api/openai", "v1"]);
    run(dir.path(), &["vault", "set", "api/github", "v2"]);
    run(dir.path(), &["vault", "set", "db/prod", "v3"]);

    let (code, stdout, stderr) = run(dir.path(), &["vault", "list"]);
    assert_eq!(code, 0, "vault list must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("api/openai"),
        "list must contain api/openai; got: {stdout}"
    );
    assert!(
        stdout.contains("api/github"),
        "list must contain api/github; got: {stdout}"
    );
    assert!(
        stdout.contains("db/prod"),
        "list must contain db/prod; got: {stdout}"
    );
}

#[test]
fn vault_rm_removes_entry() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["vault", "init"]);
    run(dir.path(), &["vault", "set", "api/openai", "sk-val"]);

    let (code, _stdout, stderr) = run(dir.path(), &["vault", "rm", "api/openai"]);
    assert_eq!(code, 0, "vault rm must exit 0; stderr: {stderr}");

    // The encrypted file must be gone.
    let enc_file = dir.path().join("vault").join("api").join("openai.enc");
    assert!(!enc_file.exists(), "vault rm must delete the .enc file");

    // vault get must now fail.
    let (code, _stdout, _stderr) = run(dir.path(), &["vault", "get", "api/openai"]);
    assert_ne!(code, 0, "vault get must fail after rm");
}

#[test]
fn vault_rm_prunes_empty_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["vault", "init"]);
    run(dir.path(), &["vault", "set", "group/only-entry", "v"]);

    run(dir.path(), &["vault", "rm", "group/only-entry"]);

    // The now-empty 'group' subdirectory should be pruned.
    let group_dir = dir.path().join("vault").join("group");
    assert!(
        !group_dir.exists(),
        "empty parent dir must be pruned after rm"
    );
}

#[test]
fn vault_set_overwrites_existing_entry() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["vault", "init"]);

    run(dir.path(), &["vault", "set", "key", "original"]);
    run(dir.path(), &["vault", "set", "key", "updated"]);

    let (code, stdout, stderr) = run(dir.path(), &["vault", "get", "key"]);
    assert_eq!(code, 0, "vault get must exit 0; stderr: {stderr}");
    assert_eq!(stdout, "updated", "second set must overwrite the first");
}

#[test]
fn vault_get_missing_entry_fails() {
    let dir = tempfile::tempdir().unwrap();
    run(dir.path(), &["keygen"]);
    run(dir.path(), &["vault", "init"]);

    let (code, _stdout, _stderr) = run(dir.path(), &["vault", "get", "no/such/key"]);
    assert_ne!(code, 0, "vault get on missing entry must fail");
}
