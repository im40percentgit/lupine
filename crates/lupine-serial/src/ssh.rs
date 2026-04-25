//! OpenSSH-format key serialization for Lupine PQC key types.
//!
//! Provides encoding and decoding for PQC keys in the OpenSSH wire format
//! (`openssh-key-v1`), enabling use of post-quantum keys in SSH tooling.
//!
//! ## Public key format
//!
//! OpenSSH public keys are a single line:
//!
//! ```text
//! <algo-name> <base64(ssh_string(algo_name) || ssh_string(key_bytes))>
//! ```
//!
//! This matches what `ssh-keygen` produces for classical key types, just with
//! Lupine-specific algorithm names like `mlkem768@lupine.dev`.
//!
//! ## Private key format
//!
//! Private keys use the `openssh-key-v1` format, PEM-wrapped with the header
//! `-----BEGIN OPENSSH PRIVATE KEY-----`. The binary structure is:
//!
//! ```text
//! "openssh-key-v1\0"       magic
//! ssh_string("none")       cipher
//! ssh_string("none")       kdf
//! ssh_string("")           kdf options
//! u32(1)                   num keys
//! ssh_string(pubkey_blob)  public key blob
//! ssh_string(priv_section) private section (unencrypted, cipher=none)
//! ```
//!
//! @decision DEC-SERIAL-006
//! @title SSH algorithm names: IANA registry vs lupine.dev namespace
//! @status accepted
//! @rationale IANA has not yet assigned SSH algorithm names for FIPS 203/204
//!   parameter sets. We use the `@lupine.dev` namespace (following the SSH
//!   extension naming convention from RFC 4251 §6) rather than a bare name
//!   or a pre-standard guess. SLH-DSA is not supported in SSH format because
//!   its signature sizes (8–51 KB) are incompatible with the SSH transport
//!   layer's typical message-size expectations. Hybrid variants use the
//!   `<classical>-<pqc>@lupine.dev` naming pattern for clarity.
//!
//! @decision DEC-SERIAL-007
//! @title SLH-DSA not supported in SSH format
//! @status accepted
//! @rationale SLH-DSA signatures range from 7 856 to 49 856 bytes. The SSH
//!   transport layer has a 256 KB per-packet limit but in practice many
//!   implementations choke on large auth packets. Rather than silently
//!   producing keys that may not interoperate, we return an explicit error
//!   for SLH-DSA and document the restriction. ML-DSA signatures are at most
//!   4 627 bytes, which is well within practical limits.
//!
//! @decision DEC-SERIAL-008
//! @title Check value 0x12345678 for deterministic unencrypted openssh-key-v1 output
//! @status accepted
//! @rationale The openssh-key-v1 format uses a pair of identical 32-bit check
//!   values (check1 == check2) as a decryption-verification mechanism. For
//!   unencrypted keys (cipher=none) any constant satisfies this. Using a
//!   fixed sentinel (0x12345678) produces deterministic output, which
//!   simplifies tests and avoids requiring a CSPRNG for serialization.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use lupine_core::{Error, KemAlgorithm, Result, SerializationError, SignAlgorithm};

// ---------------------------------------------------------------------------
// Algorithm name constants
// ---------------------------------------------------------------------------

const NAME_MLKEM512: &str = "mlkem512@lupine.dev";
const NAME_MLKEM768: &str = "mlkem768@lupine.dev";
const NAME_MLKEM1024: &str = "mlkem1024@lupine.dev";
const NAME_X25519_MLKEM512: &str = "x25519-mlkem512@lupine.dev";
const NAME_X25519_MLKEM768: &str = "x25519-mlkem768@lupine.dev";
const NAME_X25519_MLKEM1024: &str = "x25519-mlkem1024@lupine.dev";

const NAME_MLDSA44: &str = "mldsa44@lupine.dev";
const NAME_MLDSA65: &str = "mldsa65@lupine.dev";
const NAME_MLDSA87: &str = "mldsa87@lupine.dev";
const NAME_ED25519_MLDSA44: &str = "ed25519-mldsa44@lupine.dev";
const NAME_ED25519_MLDSA65: &str = "ed25519-mldsa65@lupine.dev";
const NAME_ED25519_MLDSA87: &str = "ed25519-mldsa87@lupine.dev";

/// Returned for SLH-DSA variants, which are not supported in SSH format.
const NAME_UNKNOWN: &str = "unknown@lupine.dev";

// ---------------------------------------------------------------------------
// Algorithm name dispatch
// ---------------------------------------------------------------------------

/// Return the OpenSSH algorithm name string for a KEM algorithm.
///
/// Pure ML-KEM variants use `mlkem<N>@lupine.dev`.
/// Hybrid variants (for documentation/reverse-lookup) use
/// `x25519-mlkem<N>@lupine.dev`.
pub fn ssh_name_for_kem(alg: KemAlgorithm) -> &'static str {
    match alg {
        KemAlgorithm::MlKem512 => NAME_MLKEM512,
        KemAlgorithm::MlKem768 => NAME_MLKEM768,
        KemAlgorithm::MlKem1024 => NAME_MLKEM1024,
    }
}

/// Return the `KemAlgorithm` for an SSH algorithm name string, or `None` if
/// the name is not recognized.
///
/// Both the pure ML-KEM names and the hybrid `x25519-mlkem*` names are
/// accepted, mapping to the underlying ML-KEM parameter set.
pub fn kem_from_ssh_name(name: &str) -> Option<KemAlgorithm> {
    match name {
        NAME_MLKEM512 | NAME_X25519_MLKEM512 => Some(KemAlgorithm::MlKem512),
        NAME_MLKEM768 | NAME_X25519_MLKEM768 => Some(KemAlgorithm::MlKem768),
        NAME_MLKEM1024 | NAME_X25519_MLKEM1024 => Some(KemAlgorithm::MlKem1024),
        _ => None,
    }
}

/// Return the OpenSSH algorithm name string for a signature algorithm.
///
/// ML-DSA variants use `mldsa<N>@lupine.dev`. SLH-DSA variants return
/// `"unknown@lupine.dev"` — they are not supported in SSH format because
/// their signature sizes are incompatible with SSH transport layer
/// expectations (see DEC-SERIAL-007).
pub fn ssh_name_for_sign(alg: SignAlgorithm) -> &'static str {
    match alg {
        SignAlgorithm::MlDsa44 => NAME_MLDSA44,
        SignAlgorithm::MlDsa65 => NAME_MLDSA65,
        SignAlgorithm::MlDsa87 => NAME_MLDSA87,
        // SLH-DSA not supported in SSH format (DEC-SERIAL-007)
        SignAlgorithm::SlhDsaSha2128s
        | SignAlgorithm::SlhDsaSha2128f
        | SignAlgorithm::SlhDsaSha2192s
        | SignAlgorithm::SlhDsaSha2192f
        | SignAlgorithm::SlhDsaSha2256s
        | SignAlgorithm::SlhDsaSha2256f
        | SignAlgorithm::SlhDsaShake128s
        | SignAlgorithm::SlhDsaShake128f
        | SignAlgorithm::SlhDsaShake192s
        | SignAlgorithm::SlhDsaShake192f
        | SignAlgorithm::SlhDsaShake256s
        | SignAlgorithm::SlhDsaShake256f => NAME_UNKNOWN,
    }
}

/// Return the `SignAlgorithm` for an SSH algorithm name string, or `None` if
/// the name is not recognized.
///
/// Both the pure ML-DSA names and the hybrid `ed25519-mldsa*` names are
/// accepted, mapping to the underlying ML-DSA parameter set.
pub fn sign_from_ssh_name(name: &str) -> Option<SignAlgorithm> {
    match name {
        NAME_MLDSA44 | NAME_ED25519_MLDSA44 => Some(SignAlgorithm::MlDsa44),
        NAME_MLDSA65 | NAME_ED25519_MLDSA65 => Some(SignAlgorithm::MlDsa65),
        NAME_MLDSA87 | NAME_ED25519_MLDSA87 => Some(SignAlgorithm::MlDsa87),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SSH wire format helpers
// ---------------------------------------------------------------------------

/// Build a serialization error with a static message.
///
/// Mirrors the `ser_err` helper in `der.rs` and `composite.rs`.
pub(crate) fn ser_err(message: &'static str) -> Error {
    Error::Serialization(SerializationError { message })
}

/// Append a big-endian 32-bit unsigned integer to `buf`.
pub fn write_ssh_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Append an SSH length-prefixed string (`u32-BE length || bytes`) to `buf`.
pub fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    write_ssh_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

/// Read a big-endian 32-bit unsigned integer from the front of `data`.
///
/// Returns `(value, remaining)` or an error if `data` is shorter than 4 bytes.
pub fn read_ssh_u32(data: &[u8]) -> Result<(u32, &[u8])> {
    if data.len() < 4 {
        return Err(ser_err("truncated SSH u32"));
    }
    let value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Ok((value, &data[4..]))
}

/// Read an SSH length-prefixed string from the front of `data`.
///
/// Returns `(string_bytes, remaining)` or an error if the input is truncated.
pub fn read_ssh_string(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, rest) = read_ssh_u32(data)?;
    let len = len as usize;
    if rest.len() < len {
        return Err(ser_err("truncated SSH string"));
    }
    Ok((&rest[..len], &rest[len..]))
}

// ---------------------------------------------------------------------------
// Public key encoding/decoding
// ---------------------------------------------------------------------------

/// Encode a KEM public key as an OpenSSH public key line.
///
/// Format: `<algo-name> <base64(ssh_string(algo_name) || ssh_string(key_bytes))>`
pub fn encode_kem_public_key_openssh(algo: KemAlgorithm, key_bytes: &[u8]) -> Result<String> {
    encode_public_key_line(ssh_name_for_kem(algo), key_bytes)
}

/// Decode an OpenSSH public key line for a KEM algorithm.
///
/// Returns `(algorithm, key_bytes)`.
pub fn decode_kem_public_key_openssh(openssh: &str) -> Result<(KemAlgorithm, Vec<u8>)> {
    let (name, key_bytes) = decode_public_key_blob_from_line(openssh)?;
    let algo = kem_from_ssh_name(&name).ok_or_else(|| ser_err("unknown KEM SSH algorithm name"))?;
    Ok((algo, key_bytes))
}

/// Encode a signature verifying key as an OpenSSH public key line.
///
/// Returns an error if the algorithm is SLH-DSA (not supported in SSH format).
pub fn encode_sign_public_key_openssh(algo: SignAlgorithm, key_bytes: &[u8]) -> Result<String> {
    let name = ssh_name_for_sign(algo);
    if name == NAME_UNKNOWN {
        return Err(ser_err("SLH-DSA is not supported in SSH format"));
    }
    encode_public_key_line(name, key_bytes)
}

/// Decode an OpenSSH public key line for a signature algorithm.
///
/// Returns `(algorithm, key_bytes)`.
pub fn decode_sign_public_key_openssh(openssh: &str) -> Result<(SignAlgorithm, Vec<u8>)> {
    let (name, key_bytes) = decode_public_key_blob_from_line(openssh)?;
    let algo =
        sign_from_ssh_name(&name).ok_or_else(|| ser_err("unknown sign SSH algorithm name"))?;
    Ok((algo, key_bytes))
}

// ---------------------------------------------------------------------------
// Internal public key helpers
// ---------------------------------------------------------------------------

/// Build the wire-format public key blob: `ssh_string(name) || ssh_string(key_bytes)`.
fn encode_public_key_blob(name: &str, key_bytes: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + name.len() + 4 + key_bytes.len());
    write_ssh_string(&mut blob, name.as_bytes());
    write_ssh_string(&mut blob, key_bytes);
    blob
}

/// Format a complete OpenSSH public key line: `<name> <base64(blob)>`.
fn encode_public_key_line(name: &str, key_bytes: &[u8]) -> Result<String> {
    let blob = encode_public_key_blob(name, key_bytes);
    let b64 = Base64::encode_string(&blob);
    let mut out = String::with_capacity(name.len() + 1 + b64.len());
    out.push_str(name);
    out.push(' ');
    out.push_str(&b64);
    Ok(out)
}

/// Parse an OpenSSH public key line, returning `(algo_name, key_bytes)`.
///
/// Accepts lines with an optional trailing comment (3 whitespace-delimited
/// tokens), as produced by `ssh-keygen -y`.
fn decode_public_key_blob_from_line(line: &str) -> Result<(String, Vec<u8>)> {
    let mut parts = line.splitn(3, ' ');
    let _ = parts
        .next()
        .ok_or_else(|| ser_err("empty SSH public key line"))?;
    let b64_field = parts
        .next()
        .ok_or_else(|| ser_err("missing base64 field in SSH public key"))?;

    let blob = Base64::decode_vec(b64_field.trim())
        .map_err(|_| ser_err("invalid base64 in SSH public key"))?;

    let (algo_name_bytes, rest) = read_ssh_string(&blob)?;
    let algo_name = core::str::from_utf8(algo_name_bytes)
        .map_err(|_| ser_err("SSH algorithm name is not valid UTF-8"))?;
    let (key_bytes, _) = read_ssh_string(rest)?;

    Ok((
        alloc::string::ToString::to_string(algo_name),
        key_bytes.to_vec(),
    ))
}

// ---------------------------------------------------------------------------
// Secret key encoding/decoding
// ---------------------------------------------------------------------------

/// Encode a KEM key pair as an `openssh-key-v1` PEM private key.
///
/// `sk_bytes` is the secret (decapsulation) key; `pk_bytes` is the public
/// (encapsulation) key. Both are embedded in the openssh-key-v1 envelope.
pub fn encode_kem_secret_key_openssh(
    algo: KemAlgorithm,
    sk_bytes: &[u8],
    pk_bytes: &[u8],
) -> Result<String> {
    encode_openssh_private_key(ssh_name_for_kem(algo), sk_bytes, pk_bytes)
}

/// Decode an `openssh-key-v1` PEM private key for a KEM algorithm.
///
/// Returns `(algorithm, sk_bytes, pk_bytes)`.
pub fn decode_kem_secret_key_openssh(pem: &str) -> Result<(KemAlgorithm, Vec<u8>, Vec<u8>)> {
    let (name, sk, pk) = decode_openssh_private_key(pem)?;
    let algo = kem_from_ssh_name(&name).ok_or_else(|| ser_err("unknown KEM SSH algorithm name"))?;
    Ok((algo, sk, pk))
}

/// Encode a signature key pair as an `openssh-key-v1` PEM private key.
///
/// Returns an error if the algorithm is SLH-DSA (not supported in SSH format).
pub fn encode_sign_secret_key_openssh(
    algo: SignAlgorithm,
    sk_bytes: &[u8],
    pk_bytes: &[u8],
) -> Result<String> {
    let name = ssh_name_for_sign(algo);
    if name == NAME_UNKNOWN {
        return Err(ser_err("SLH-DSA is not supported in SSH format"));
    }
    encode_openssh_private_key(name, sk_bytes, pk_bytes)
}

/// Decode an `openssh-key-v1` PEM private key for a signature algorithm.
///
/// Returns `(algorithm, sk_bytes, pk_bytes)`.
pub fn decode_sign_secret_key_openssh(pem: &str) -> Result<(SignAlgorithm, Vec<u8>, Vec<u8>)> {
    let (name, sk, pk) = decode_openssh_private_key(pem)?;
    let algo =
        sign_from_ssh_name(&name).ok_or_else(|| ser_err("unknown sign SSH algorithm name"))?;
    Ok((algo, sk, pk))
}

// ---------------------------------------------------------------------------
// Internal private key helpers
// ---------------------------------------------------------------------------

/// Magic bytes required at the start of every openssh-key-v1 binary blob.
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// Deterministic check value used in the unencrypted private section.
///
/// The openssh-key-v1 format requires `check1 == check2` to detect
/// decryption failures. For `cipher=none` any constant pair works.
/// Using a fixed sentinel produces deterministic output and avoids
/// requiring a CSPRNG at serialization time (DEC-SERIAL-008).
const CHECK_VALUE: u32 = 0x1234_5678;

/// PEM label for the openssh private key format.
const OPENSSH_PRIVATE_LABEL: &str = "OPENSSH PRIVATE KEY";

/// Build the binary envelope for an unencrypted `openssh-key-v1` private key.
fn build_openssh_binary(name: &str, sk_bytes: &[u8], pk_bytes: &[u8]) -> Vec<u8> {
    // Public key blob: ssh_string(name) || ssh_string(pk_bytes)
    let pub_blob = encode_public_key_blob(name, pk_bytes);

    // Private section:
    //   u32(check1) u32(check2)
    //   ssh_string(algo_name)
    //   ssh_string(sk_bytes)
    //   ssh_string(pk_bytes)   -- public key repeated inside private section
    //   ssh_string("")         -- comment
    //   padding bytes 1,2,3,... to reach 8-byte alignment
    let mut priv_section: Vec<u8> = Vec::new();
    write_ssh_u32(&mut priv_section, CHECK_VALUE);
    write_ssh_u32(&mut priv_section, CHECK_VALUE);
    write_ssh_string(&mut priv_section, name.as_bytes());
    write_ssh_string(&mut priv_section, sk_bytes);
    write_ssh_string(&mut priv_section, pk_bytes);
    write_ssh_string(&mut priv_section, b""); // empty comment
    let mut pad: u8 = 1;
    // `is_multiple_of` was stabilised in Rust 1.87; workspace MSRV is 1.85.
    #[allow(clippy::manual_is_multiple_of)]
    while priv_section.len() % 8 != 0 {
        priv_section.push(pad);
        pad = pad.wrapping_add(1);
    }

    // Outer envelope
    let mut out: Vec<u8> =
        Vec::with_capacity(OPENSSH_MAGIC.len() + 64 + pub_blob.len() + priv_section.len());
    out.extend_from_slice(OPENSSH_MAGIC);
    write_ssh_string(&mut out, b"none"); // cipher name
    write_ssh_string(&mut out, b"none"); // kdf name
    write_ssh_string(&mut out, b""); // kdf options (empty)
    write_ssh_u32(&mut out, 1); // number of keys
    write_ssh_string(&mut out, &pub_blob);
    write_ssh_string(&mut out, &priv_section);
    out
}

/// Encode an openssh-key-v1 PEM private key string from raw components.
fn encode_openssh_private_key(name: &str, sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<String> {
    let binary = build_openssh_binary(name, sk_bytes, pk_bytes);
    let b64 = Base64::encode_string(&binary);
    let wrapped = wrap_base64_70(&b64);

    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(OPENSSH_PRIVATE_LABEL);
    out.push_str("-----\n");
    out.push_str(&wrapped);
    out.push_str("-----END ");
    out.push_str(OPENSSH_PRIVATE_LABEL);
    out.push_str("-----\n");
    Ok(out)
}

/// Decode an openssh-key-v1 PEM private key string.
///
/// Returns `(algo_name, sk_bytes, pk_bytes)`.
fn decode_openssh_private_key(pem: &str) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let begin_marker = "-----BEGIN OPENSSH PRIVATE KEY-----";
    let end_marker = "-----END OPENSSH PRIVATE KEY-----";

    let body_start = pem
        .find(begin_marker)
        .ok_or_else(|| ser_err("missing openssh private key PEM header"))?
        + begin_marker.len();
    let body_end = pem
        .find(end_marker)
        .ok_or_else(|| ser_err("missing openssh private key PEM footer"))?;

    // Collect base64 body, stripping whitespace between PEM header and footer
    let b64_body: String = pem[body_start..body_end]
        .lines()
        .flat_map(|l| l.trim().chars())
        .collect();

    let data = Base64::decode_vec(&b64_body)
        .map_err(|_| ser_err("invalid base64 in openssh private key"))?;

    if !data.starts_with(OPENSSH_MAGIC) {
        return Err(ser_err("missing openssh-key-v1 magic"));
    }
    let mut rest = &data[OPENSSH_MAGIC.len()..];

    // cipher name — must be "none" (encrypted keys not supported)
    let (cipher, r) = read_ssh_string(rest)?;
    if cipher != b"none" {
        return Err(ser_err("encrypted openssh keys are not supported"));
    }
    rest = r;

    // kdf name (skip)
    let (_, r) = read_ssh_string(rest)?;
    rest = r;

    // kdf options (skip)
    let (_, r) = read_ssh_string(rest)?;
    rest = r;

    // number of keys — must be 1
    let (nkeys, r) = read_ssh_u32(rest)?;
    if nkeys != 1 {
        return Err(ser_err("openssh key with num_keys != 1 is not supported"));
    }
    rest = r;

    // public key blob (skip — we recover pk from the private section)
    let (_, r) = read_ssh_string(rest)?;
    rest = r;

    // private section
    let (priv_section, _) = read_ssh_string(rest)?;
    let mut ps = priv_section;

    // check1 and check2 must match
    let (check1, r) = read_ssh_u32(ps)?;
    let (check2, r) = read_ssh_u32(r)?;
    if check1 != check2 {
        return Err(ser_err("openssh check values do not match"));
    }
    ps = r;

    // algorithm name
    let (algo_name_bytes, r) = read_ssh_string(ps)?;
    let algo_name = core::str::from_utf8(algo_name_bytes)
        .map_err(|_| ser_err("SSH algorithm name is not valid UTF-8"))?;
    ps = r;

    // secret key
    let (sk_bytes, r) = read_ssh_string(ps)?;
    ps = r;

    // public key (embedded in private section)
    let (pk_bytes, _) = read_ssh_string(ps)?;
    // Remaining bytes are comment + padding — ignored

    Ok((
        alloc::string::ToString::to_string(algo_name),
        sk_bytes.to_vec(),
        pk_bytes.to_vec(),
    ))
}

/// Wrap a base64 string at 70 characters per line (OpenSSH convention).
fn wrap_base64_70(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / 70 + 2);
    let mut pos = 0;
    while pos < b64.len() {
        let end = core::cmp::min(pos + 70, b64.len());
        out.push_str(&b64[pos..end]);
        out.push('\n');
        pos = end;
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Task 1: Algorithm name constants and dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn kem_ssh_name_roundtrip_all_pure_variants() {
        let variants = [
            KemAlgorithm::MlKem512,
            KemAlgorithm::MlKem768,
            KemAlgorithm::MlKem1024,
        ];
        for alg in variants {
            let name = ssh_name_for_kem(alg);
            assert!(!name.is_empty(), "name empty for {alg:?}");
            let decoded =
                kem_from_ssh_name(name).unwrap_or_else(|| panic!("round-trip failed for {alg:?}"));
            assert_eq!(decoded, alg, "round-trip mismatch for {alg:?}");
        }
    }

    #[test]
    fn kem_hybrid_names_decode() {
        assert_eq!(
            kem_from_ssh_name("x25519-mlkem512@lupine.dev"),
            Some(KemAlgorithm::MlKem512)
        );
        assert_eq!(
            kem_from_ssh_name("x25519-mlkem768@lupine.dev"),
            Some(KemAlgorithm::MlKem768)
        );
        assert_eq!(
            kem_from_ssh_name("x25519-mlkem1024@lupine.dev"),
            Some(KemAlgorithm::MlKem1024)
        );
    }

    #[test]
    fn kem_unknown_name_returns_none() {
        assert!(kem_from_ssh_name("rsa-2048").is_none());
        assert!(kem_from_ssh_name("").is_none());
        assert!(kem_from_ssh_name("unknown@lupine.dev").is_none());
    }

    #[test]
    fn sign_ssh_name_roundtrip_mldsa_variants() {
        let variants = [
            SignAlgorithm::MlDsa44,
            SignAlgorithm::MlDsa65,
            SignAlgorithm::MlDsa87,
        ];
        for alg in variants {
            let name = ssh_name_for_sign(alg);
            assert_ne!(name, NAME_UNKNOWN, "ML-DSA should have a valid SSH name");
            let decoded =
                sign_from_ssh_name(name).unwrap_or_else(|| panic!("round-trip failed for {alg:?}"));
            assert_eq!(decoded, alg);
        }
    }

    #[test]
    fn sign_hybrid_names_decode() {
        assert_eq!(
            sign_from_ssh_name("ed25519-mldsa44@lupine.dev"),
            Some(SignAlgorithm::MlDsa44)
        );
        assert_eq!(
            sign_from_ssh_name("ed25519-mldsa65@lupine.dev"),
            Some(SignAlgorithm::MlDsa65)
        );
        assert_eq!(
            sign_from_ssh_name("ed25519-mldsa87@lupine.dev"),
            Some(SignAlgorithm::MlDsa87)
        );
    }

    #[test]
    fn slhdsa_variants_return_unknown() {
        let slh_variants = [
            SignAlgorithm::SlhDsaSha2128s,
            SignAlgorithm::SlhDsaSha2128f,
            SignAlgorithm::SlhDsaSha2192s,
            SignAlgorithm::SlhDsaSha2192f,
            SignAlgorithm::SlhDsaSha2256s,
            SignAlgorithm::SlhDsaSha2256f,
            SignAlgorithm::SlhDsaShake128s,
            SignAlgorithm::SlhDsaShake128f,
            SignAlgorithm::SlhDsaShake192s,
            SignAlgorithm::SlhDsaShake192f,
            SignAlgorithm::SlhDsaShake256s,
            SignAlgorithm::SlhDsaShake256f,
        ];
        for alg in slh_variants {
            assert_eq!(
                ssh_name_for_sign(alg),
                NAME_UNKNOWN,
                "expected unknown for {alg:?}"
            );
        }
    }

    #[test]
    fn sign_unknown_name_returns_none() {
        assert!(sign_from_ssh_name("ecdsa-sha2-nistp256").is_none());
        assert!(sign_from_ssh_name("").is_none());
        assert!(sign_from_ssh_name("unknown@lupine.dev").is_none());
    }

    // -----------------------------------------------------------------------
    // Task 2: SSH wire format helpers
    // -----------------------------------------------------------------------

    #[test]
    fn u32_write_read_roundtrip() {
        let mut buf = Vec::new();
        write_ssh_u32(&mut buf, 0x0102_0304);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);
        let (val, rest) = read_ssh_u32(&buf).unwrap();
        assert_eq!(val, 0x0102_0304);
        assert!(rest.is_empty());
    }

    #[test]
    fn string_write_read_roundtrip() {
        let data = b"hello, SSH!";
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, data);
        assert_eq!(buf.len(), 4 + data.len());
        let (s, rest) = read_ssh_string(&buf).unwrap();
        assert_eq!(s, data);
        assert!(rest.is_empty());
    }

    #[test]
    fn empty_string_roundtrip() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"");
        assert_eq!(buf, [0, 0, 0, 0]);
        let (s, rest) = read_ssh_string(&buf).unwrap();
        assert!(s.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn read_u32_truncated_returns_error() {
        assert!(read_ssh_u32(&[0x00, 0x00, 0x00]).is_err());
        assert!(read_ssh_u32(&[]).is_err());
    }

    #[test]
    fn read_string_truncated_returns_error() {
        // Length prefix says 10 bytes but only 2 follow
        let mut bad = Vec::new();
        write_ssh_u32(&mut bad, 10);
        bad.extend_from_slice(b"ab");
        assert!(read_ssh_string(&bad).is_err());
    }

    #[test]
    fn sequential_strings_roundtrip() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"first");
        write_ssh_string(&mut buf, b"second");
        let (s1, rest) = read_ssh_string(&buf).unwrap();
        assert_eq!(s1, b"first");
        let (s2, rest2) = read_ssh_string(rest).unwrap();
        assert_eq!(s2, b"second");
        assert!(rest2.is_empty());
    }

    // -----------------------------------------------------------------------
    // Task 3: SSH public key encoding/decoding
    // -----------------------------------------------------------------------

    const FAKE_PK: &[u8] = b"fake_public_key_bytes_for_ssh_test";

    #[test]
    fn kem_public_key_roundtrip_mlkem768() {
        let line = encode_kem_public_key_openssh(KemAlgorithm::MlKem768, FAKE_PK).unwrap();
        assert!(line.starts_with("mlkem768@lupine.dev "));
        let (alg, key) = decode_kem_public_key_openssh(&line).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem768);
        assert_eq!(key, FAKE_PK);
    }

    #[test]
    fn kem_public_key_roundtrip_all_pure_variants() {
        for alg in [
            KemAlgorithm::MlKem512,
            KemAlgorithm::MlKem768,
            KemAlgorithm::MlKem1024,
        ] {
            let line = encode_kem_public_key_openssh(alg, FAKE_PK).unwrap();
            let (decoded_alg, decoded_key) = decode_kem_public_key_openssh(&line).unwrap();
            assert_eq!(decoded_alg, alg);
            assert_eq!(decoded_key, FAKE_PK);
        }
    }

    #[test]
    fn sign_public_key_roundtrip_mldsa65() {
        let line = encode_sign_public_key_openssh(SignAlgorithm::MlDsa65, FAKE_PK).unwrap();
        assert!(line.starts_with("mldsa65@lupine.dev "));
        let (alg, key) = decode_sign_public_key_openssh(&line).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa65);
        assert_eq!(key, FAKE_PK);
    }

    #[test]
    fn sign_public_key_roundtrip_all_mldsa_variants() {
        for alg in [
            SignAlgorithm::MlDsa44,
            SignAlgorithm::MlDsa65,
            SignAlgorithm::MlDsa87,
        ] {
            let line = encode_sign_public_key_openssh(alg, FAKE_PK).unwrap();
            let (decoded_alg, decoded_key) = decode_sign_public_key_openssh(&line).unwrap();
            assert_eq!(decoded_alg, alg);
            assert_eq!(decoded_key, FAKE_PK);
        }
    }

    #[test]
    fn slhdsa_public_key_encode_returns_error() {
        assert!(encode_sign_public_key_openssh(SignAlgorithm::SlhDsaSha2128s, FAKE_PK).is_err());
    }

    #[test]
    fn decode_bad_base64_returns_error() {
        assert!(decode_kem_public_key_openssh("mlkem768@lupine.dev !!!notbase64!!!").is_err());
    }

    #[test]
    fn decode_unknown_algo_returns_error() {
        let line = encode_public_key_line("rsa@openssh.com", FAKE_PK).unwrap();
        assert!(decode_kem_public_key_openssh(&line).is_err());
        assert!(decode_sign_public_key_openssh(&line).is_err());
    }

    #[test]
    fn decode_public_key_with_trailing_comment() {
        let base = encode_kem_public_key_openssh(KemAlgorithm::MlKem768, FAKE_PK).unwrap();
        let with_comment = alloc::format!("{} user@host", base);
        let (alg, key) = decode_kem_public_key_openssh(&with_comment).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem768);
        assert_eq!(key, FAKE_PK);
    }

    // -----------------------------------------------------------------------
    // Task 4: SSH secret key encoding/decoding
    // -----------------------------------------------------------------------

    const FAKE_SK: &[u8] = &[0xAB_u8; 32];
    const FAKE_PK2: &[u8] = &[0xCD_u8; 64];

    #[test]
    fn kem_secret_key_roundtrip_mlkem768() {
        let pem = encode_kem_secret_key_openssh(KemAlgorithm::MlKem768, FAKE_SK, FAKE_PK2).unwrap();
        assert!(pem.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(pem.contains("-----END OPENSSH PRIVATE KEY-----"));
        let (alg, sk, pk) = decode_kem_secret_key_openssh(&pem).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem768);
        assert_eq!(sk, FAKE_SK);
        assert_eq!(pk, FAKE_PK2);
    }

    #[test]
    fn sign_secret_key_roundtrip_mldsa65() {
        let pem =
            encode_sign_secret_key_openssh(SignAlgorithm::MlDsa65, FAKE_SK, FAKE_PK2).unwrap();
        let (alg, sk, pk) = decode_sign_secret_key_openssh(&pem).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa65);
        assert_eq!(sk, FAKE_SK);
        assert_eq!(pk, FAKE_PK2);
    }

    #[test]
    fn kem_secret_key_realistic_sizes_mlkem768() {
        // ML-KEM-768: sk=2400 B, pk=1184 B (FIPS 203 sizes)
        let sk = alloc::vec![0x11u8; 2400];
        let pk = alloc::vec![0x22u8; 1184];
        let pem = encode_kem_secret_key_openssh(KemAlgorithm::MlKem768, &sk, &pk).unwrap();
        let (alg, decoded_sk, decoded_pk) = decode_kem_secret_key_openssh(&pem).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem768);
        assert_eq!(decoded_sk, sk);
        assert_eq!(decoded_pk, pk);
    }

    #[test]
    fn sign_secret_key_realistic_sizes_mldsa65() {
        // ML-DSA-65: sk=32 B seed, vk=1952 B (FIPS 204 sizes)
        let sk = alloc::vec![0xAAu8; 32];
        let vk = alloc::vec![0xBBu8; 1952];
        let pem = encode_sign_secret_key_openssh(SignAlgorithm::MlDsa65, &sk, &vk).unwrap();
        let (alg, decoded_sk, decoded_vk) = decode_sign_secret_key_openssh(&pem).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa65);
        assert_eq!(decoded_sk, sk);
        assert_eq!(decoded_vk, vk);
    }

    #[test]
    fn slhdsa_secret_key_encode_returns_error() {
        assert!(
            encode_sign_secret_key_openssh(SignAlgorithm::SlhDsaSha2128s, FAKE_SK, FAKE_PK2)
                .is_err()
        );
    }

    #[test]
    fn private_section_padding_multiple_of_8_for_varying_key_sizes() {
        // Exercise all padding lengths (0–7 extra bytes) to confirm the
        // padding loop reaches 8-byte alignment for each.
        for extra in 0..8usize {
            let sk = alloc::vec![0x77u8; 10 + extra];
            let pk = alloc::vec![0x88u8; 10];
            let pem = encode_kem_secret_key_openssh(KemAlgorithm::MlKem512, &sk, &pk).unwrap();
            let (_, decoded_sk, decoded_pk) = decode_kem_secret_key_openssh(&pem).unwrap();
            assert_eq!(decoded_sk, sk, "sk mismatch for extra={extra}");
            assert_eq!(decoded_pk, pk, "pk mismatch for extra={extra}");
        }
    }

    #[test]
    fn secret_key_all_mldsa_variants_roundtrip() {
        for alg in [
            SignAlgorithm::MlDsa44,
            SignAlgorithm::MlDsa65,
            SignAlgorithm::MlDsa87,
        ] {
            let pem = encode_sign_secret_key_openssh(alg, FAKE_SK, FAKE_PK2).unwrap();
            let (decoded_alg, decoded_sk, decoded_pk) =
                decode_sign_secret_key_openssh(&pem).unwrap();
            assert_eq!(decoded_alg, alg);
            assert_eq!(decoded_sk, FAKE_SK);
            assert_eq!(decoded_pk, FAKE_PK2);
        }
    }

    #[test]
    fn decode_garbage_pem_returns_error() {
        assert!(decode_kem_secret_key_openssh("not a pem at all").is_err());
        assert!(decode_sign_secret_key_openssh(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        .is_err());
    }
}
