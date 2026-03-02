//! File I/O layer for the Lupine CLI.
//!
//! Maps between `CliAlgorithm`, `Format`, and the serialization routines in
//! `lupine_serial`. Handles reading and writing public keys, secret keys,
//! ciphertexts, and signatures in raw, DER, and PEM formats.
//!
//! # Hybrid KEM secret key layout
//!
//! For hybrid KEM secret keys in DER/PEM format, the composite encoder stores:
//! - classical field: `x25519_sk(32) || x25519_pk(32)` (64 bytes)
//! - pqc field: `mlkem_pk || mlkem_sk` (concatenated)
//!
//! This preserves all bytes needed for decapsulation (including the ML-KEM
//! public key required by the KitchenSink combiner) in a single file.
//!
//! For raw format, hybrid KEM secret keys are stored as
//! `x25519_sk(32) || x25519_pk(32) || mlkem_sk`. The ML-KEM public key is
//! NOT stored — decapsulate in raw mode requires `--pub-key` to supply it.
//!
//! # Hybrid sign key layout
//!
//! - Signing key (secret): composite classical=`ed_seed(32)`, pqc=`mldsa_seed(32)`
//! - Verifying key (public): composite classical=`ed_vk(32)`, pqc=`mldsa_vk`
//! - Signature: composite classical=`ed_sig(64)`, pqc=`mldsa_sig`
//!
//! @decision DEC-CLI-003
//! @title Composite encoder for hybrid keys; standard DER for non-hybrid keys
//! @status accepted
//! @rationale `KemAlgorithm` and `SignAlgorithm` in lupine_core do not include
//!   hybrid variants — the core enums are limited to pure parameter sets. The
//!   composite encoder in lupine_serial handles hybrid types with a variant tag,
//!   making hybrid and non-hybrid paths cleanly separated at the encoder level.
//!   For hybrid KEM secret keys specifically, the composite PQC field stores
//!   both the ML-KEM public key and secret key so that decapsulation works
//!   without requiring a separate `--pub-key` argument in PEM/DER mode.

use std::fs;
use std::io::{self, Read};

use anyhow::{bail, Context, Result};

use lupine_serial::{composite, der, pem};

use crate::algorithm::CliAlgorithm;
use crate::args::Format;

// ---------------------------------------------------------------------------
// Public key I/O
// ---------------------------------------------------------------------------

/// Write a public key to `path` in the requested format.
///
/// For hybrid KEM variants, `raw_bytes` is the full hybrid pk
/// (`x25519_pk(32) || mlkem_pk`); the composite encoder splits it.
/// For hybrid sign variants, `raw_bytes` is `ed_vk(32) || mldsa_vk`.
pub fn write_public_key(
    path: &str,
    raw_bytes: &[u8],
    alg: CliAlgorithm,
    format: Format,
) -> Result<()> {
    match format {
        Format::Raw => {
            fs::write(path, raw_bytes)
                .with_context(|| format!("failed to write raw public key to {path}"))?;
        }
        Format::Der => {
            let der_bytes = encode_public_key_der(raw_bytes, alg)?;
            fs::write(path, &der_bytes)
                .with_context(|| format!("failed to write DER public key to {path}"))?;
        }
        Format::Pem => {
            let der_bytes = encode_public_key_der(raw_bytes, alg)?;
            let pem_str = if alg.is_hybrid_kem() || alg.is_hybrid_sign() {
                pem::encode_pem("PUBLIC KEY", &der_bytes)
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?
            } else {
                pem::encode_public_key_pem(&der_bytes)
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?
            };
            fs::write(path, pem_str.as_bytes())
                .with_context(|| format!("failed to write PEM public key to {path}"))?;
        }
    }
    Ok(())
}

/// Read a public key from `path`.
///
/// Returns `(raw_bytes, detected_algorithm)`. For raw format, `alg_hint` is
/// required since there is no embedded algorithm identifier. For DER/PEM, the
/// algorithm is detected from the encoded data (OID or composite variant tag).
pub fn read_public_key(
    path: &str,
    format: Format,
    alg_hint: Option<CliAlgorithm>,
) -> Result<(Vec<u8>, CliAlgorithm)> {
    let file_bytes = fs::read(path)
        .with_context(|| format!("failed to read public key from {path}"))?;

    match format {
        Format::Raw => {
            let alg = alg_hint.ok_or_else(|| {
                anyhow::anyhow!("--algorithm is required when reading raw-format keys")
            })?;
            Ok((file_bytes, alg))
        }
        Format::Der => decode_public_key_der(&file_bytes),
        Format::Pem => {
            // Try composite first (hybrid), then standard public key PEM.
            let (label, der_bytes) = pem::decode_pem(
                std::str::from_utf8(&file_bytes)
                    .with_context(|| format!("public key file {path} is not valid UTF-8"))?,
            )
            .map_err(|e| anyhow::anyhow!("PEM decode failed for {path}: {:?}", e))?;

            // Validate label
            match label.as_str() {
                "PUBLIC KEY" => {}
                other => bail!("unexpected PEM label '{other}' in {path}; expected 'PUBLIC KEY'"),
            }
            decode_public_key_der(&der_bytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Secret key I/O
// ---------------------------------------------------------------------------

/// Write a secret key to `path`.
///
/// For hybrid KEM in DER/PEM: `pk_bytes` must be provided (the full hybrid pk)
/// so the ML-KEM public key can be embedded in the composite PQC field.
/// For all other formats and algorithms, `pk_bytes` is ignored.
pub fn write_secret_key(
    path: &str,
    raw_bytes: &[u8],
    alg: CliAlgorithm,
    format: Format,
    pk_bytes: Option<&[u8]>,
) -> Result<()> {
    match format {
        Format::Raw => {
            fs::write(path, raw_bytes)
                .with_context(|| format!("failed to write raw secret key to {path}"))?;
        }
        Format::Der => {
            let der_bytes = encode_secret_key_der(raw_bytes, alg, pk_bytes)?;
            fs::write(path, &der_bytes)
                .with_context(|| format!("failed to write DER secret key to {path}"))?;
        }
        Format::Pem => {
            let der_bytes = encode_secret_key_der(raw_bytes, alg, pk_bytes)?;
            let pem_str = pem::encode_private_key_pem(&der_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            fs::write(path, pem_str.as_bytes())
                .with_context(|| format!("failed to write PEM secret key to {path}"))?;
        }
    }
    Ok(())
}

/// Read a secret key from `path`.
///
/// Returns `(raw_sk_bytes, detected_algorithm, mlkem_pk_bytes)`.
/// The third element is `Some(mlkem_pk_bytes)` for hybrid KEM keys read from
/// DER/PEM (the composite encoder stores them); `None` otherwise.
pub fn read_secret_key(
    path: &str,
    format: Format,
    alg_hint: Option<CliAlgorithm>,
) -> Result<(Vec<u8>, CliAlgorithm, Option<Vec<u8>>)> {
    let file_bytes = fs::read(path)
        .with_context(|| format!("failed to read secret key from {path}"))?;

    match format {
        Format::Raw => {
            let alg = alg_hint.ok_or_else(|| {
                anyhow::anyhow!("--algorithm is required when reading raw-format keys")
            })?;
            Ok((file_bytes, alg, None))
        }
        Format::Der => decode_secret_key_der(&file_bytes),
        Format::Pem => {
            let pem_str = std::str::from_utf8(&file_bytes)
                .with_context(|| format!("secret key file {path} is not valid UTF-8"))?;
            let (label, der_bytes) = pem::decode_pem(pem_str)
                .map_err(|e| anyhow::anyhow!("PEM decode failed for {path}: {:?}", e))?;
            match label.as_str() {
                "PRIVATE KEY" => {}
                other => bail!("unexpected PEM label '{other}' in {path}; expected 'PRIVATE KEY'"),
            }
            decode_secret_key_der(&der_bytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Ciphertext I/O (always raw bytes)
// ---------------------------------------------------------------------------

/// Write raw ciphertext bytes to `path`.
pub fn write_ciphertext(path: &str, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)
        .with_context(|| format!("failed to write ciphertext to {path}"))
}

/// Read raw ciphertext bytes from `path`.
pub fn read_ciphertext(path: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read ciphertext from {path}"))
}

// ---------------------------------------------------------------------------
// Signature I/O
// ---------------------------------------------------------------------------

/// Write a signature to `path` in the requested format.
pub fn write_signature(
    path: &str,
    sig_bytes: &[u8],
    alg: CliAlgorithm,
    format: Format,
) -> Result<()> {
    match format {
        Format::Raw => {
            fs::write(path, sig_bytes)
                .with_context(|| format!("failed to write raw signature to {path}"))?;
        }
        Format::Der => {
            let der_bytes = encode_signature_der(sig_bytes, alg)?;
            fs::write(path, &der_bytes)
                .with_context(|| format!("failed to write DER signature to {path}"))?;
        }
        Format::Pem => {
            let der_bytes = encode_signature_der(sig_bytes, alg)?;
            let pem_str = pem::encode_signature_pem(&der_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            fs::write(path, pem_str.as_bytes())
                .with_context(|| format!("failed to write PEM signature to {path}"))?;
        }
    }
    Ok(())
}

/// Read a signature from `path`.
///
/// Returns `(raw_sig_bytes, detected_algorithm)`. Raw format requires `alg_hint`.
pub fn read_signature(
    path: &str,
    format: Format,
    alg_hint: Option<CliAlgorithm>,
) -> Result<(Vec<u8>, CliAlgorithm)> {
    let file_bytes = fs::read(path)
        .with_context(|| format!("failed to read signature from {path}"))?;

    match format {
        Format::Raw => {
            let alg = alg_hint.ok_or_else(|| {
                anyhow::anyhow!("--algorithm is required when reading raw-format signatures")
            })?;
            Ok((file_bytes, alg))
        }
        Format::Der => decode_signature_der(&file_bytes),
        Format::Pem => {
            let pem_str = std::str::from_utf8(&file_bytes)
                .with_context(|| format!("signature file {path} is not valid UTF-8"))?;
            let der_bytes = pem::decode_signature_pem(pem_str)
                .map_err(|e| anyhow::anyhow!("PEM decode failed for {path}: {:?}", e))?;
            decode_signature_der(&der_bytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Message I/O
// ---------------------------------------------------------------------------

/// Read a message from `path` (or stdin if `None`).
pub fn read_message(path: Option<&str>) -> Result<Vec<u8>> {
    match path {
        Some(p) => fs::read(p).with_context(|| format!("failed to read message from {p}")),
        None => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .context("failed to read message from stdin")?;
            Ok(buf)
        }
    }
}

// ---------------------------------------------------------------------------
// Shared secret output
// ---------------------------------------------------------------------------

/// Write a shared secret to `path` as hex, or print to stdout if `None`.
pub fn write_shared_secret(path: Option<&str>, ss_bytes: &[u8]) -> Result<()> {
    let hex_str = hex::encode(ss_bytes);
    match path {
        Some(p) => fs::write(p, hex_str.as_bytes())
            .with_context(|| format!("failed to write shared secret to {p}")),
        None => {
            println!("{hex_str}");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Internal encoding helpers
// ---------------------------------------------------------------------------

fn encode_public_key_der(raw_bytes: &[u8], alg: CliAlgorithm) -> Result<Vec<u8>> {
    if let Some(kem_alg) = alg.to_kem_algorithm() {
        // Pure ML-KEM
        der::encode_kem_public_key_der(kem_alg, raw_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else if let Some(sign_alg) = alg.to_sign_algorithm() {
        // Pure sign (ML-DSA or SLH-DSA)
        der::encode_sign_public_key_der(sign_alg, raw_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else if let Some(kem_variant) = alg.to_composite_kem_variant() {
        // Hybrid KEM: split x25519_pk(32) || mlkem_pk
        if raw_bytes.len() < 32 {
            bail!("hybrid KEM public key too short: {} bytes", raw_bytes.len());
        }
        let classical = &raw_bytes[..32];
        let pqc = &raw_bytes[32..];
        composite::encode_composite_kem_key(kem_variant, classical, pqc)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else if let Some(sign_variant) = alg.to_composite_sign_variant() {
        // Hybrid sign: split ed_vk(32) || mldsa_vk
        if raw_bytes.len() < 32 {
            bail!("hybrid sign public key too short: {} bytes", raw_bytes.len());
        }
        let classical = &raw_bytes[..32];
        let pqc = &raw_bytes[32..];
        composite::encode_composite_sign_key(sign_variant, classical, pqc)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else {
        bail!("unsupported algorithm for public key encoding: {alg}")
    }
}

fn decode_public_key_der(der_bytes: &[u8]) -> Result<(Vec<u8>, CliAlgorithm)> {
    // Try KEM first, then sign, then composite KEM, then composite sign.
    if let Ok((kem_alg, raw)) = der::decode_kem_public_key_der(der_bytes) {
        return Ok((raw, CliAlgorithm::from_kem_algorithm(kem_alg)));
    }
    if let Ok((sign_alg, raw)) = der::decode_sign_public_key_der(der_bytes) {
        return Ok((raw, CliAlgorithm::from_sign_algorithm(sign_alg)));
    }
    if let Ok((variant, classical, pqc)) = composite::decode_composite_kem_key(der_bytes) {
        let mut raw = Vec::with_capacity(classical.len() + pqc.len());
        raw.extend_from_slice(&classical);
        raw.extend_from_slice(&pqc);
        return Ok((raw, CliAlgorithm::from_composite_kem_variant(variant)));
    }
    if let Ok((variant, classical, pqc)) = composite::decode_composite_sign_key(der_bytes) {
        let mut raw = Vec::with_capacity(classical.len() + pqc.len());
        raw.extend_from_slice(&classical);
        raw.extend_from_slice(&pqc);
        return Ok((raw, CliAlgorithm::from_composite_sign_variant(variant)));
    }
    bail!("could not decode DER public key: no known format matched")
}

fn encode_secret_key_der(
    raw_bytes: &[u8],
    alg: CliAlgorithm,
    pk_bytes: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if let Some(kem_alg) = alg.to_kem_algorithm() {
        // Pure ML-KEM
        der::encode_kem_secret_key_der(kem_alg, raw_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else if let Some(sign_alg) = alg.to_sign_algorithm() {
        // Pure sign
        der::encode_sign_secret_key_der(sign_alg, raw_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else if let Some(kem_variant) = alg.to_composite_kem_variant() {
        // Hybrid KEM secret key.
        // raw_bytes = x25519_sk(32) || x25519_pk(32) || mlkem_sk
        // We need pk_bytes = x25519_pk(32) || mlkem_pk to extract mlkem_pk.
        if raw_bytes.len() < 64 {
            bail!("hybrid KEM secret key too short: {} bytes", raw_bytes.len());
        }
        let classical = &raw_bytes[..64]; // x25519_sk || x25519_pk
        let mlkem_sk = &raw_bytes[64..];

        // Extract mlkem_pk from pk_bytes if provided, else we can't encode properly.
        let pk = pk_bytes.ok_or_else(|| {
            anyhow::anyhow!("pk_bytes required for hybrid KEM secret key DER encoding")
        })?;
        if pk.len() < 32 {
            bail!("hybrid KEM public key too short for DER encoding");
        }
        let mlkem_pk = &pk[32..]; // skip x25519_pk (32 bytes)

        // pqc = mlkem_pk || mlkem_sk
        let mut pqc = Vec::with_capacity(mlkem_pk.len() + mlkem_sk.len());
        pqc.extend_from_slice(mlkem_pk);
        pqc.extend_from_slice(mlkem_sk);

        composite::encode_composite_kem_key(kem_variant, classical, &pqc)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else if let Some(sign_variant) = alg.to_composite_sign_variant() {
        // Hybrid sign secret key.
        // raw_bytes = ed_seed(32) || mldsa_seed(32) (64 bytes total)
        if raw_bytes.len() < 64 {
            bail!("hybrid sign secret key too short: {} bytes", raw_bytes.len());
        }
        let classical = &raw_bytes[..32]; // ed_seed
        let pqc = &raw_bytes[32..];       // mldsa_seed (32 bytes)
        composite::encode_composite_sign_key(sign_variant, classical, pqc)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else {
        bail!("unsupported algorithm for secret key encoding: {alg}")
    }
}

fn decode_secret_key_der(der_bytes: &[u8]) -> Result<(Vec<u8>, CliAlgorithm, Option<Vec<u8>>)> {
    // Try pure KEM first.
    if let Ok((kem_alg, raw)) = der::decode_kem_secret_key_der(der_bytes) {
        return Ok((raw, CliAlgorithm::from_kem_algorithm(kem_alg), None));
    }
    // Try pure sign.
    if let Ok((sign_alg, raw)) = der::decode_sign_secret_key_der(der_bytes) {
        return Ok((raw, CliAlgorithm::from_sign_algorithm(sign_alg), None));
    }
    // Try composite KEM (hybrid KEM secret key).
    if let Ok((variant, classical, pqc)) = composite::decode_composite_kem_key(der_bytes) {
        let cli_alg = CliAlgorithm::from_composite_kem_variant(variant);
        // classical = x25519_sk(32) || x25519_pk(32)
        // pqc = mlkem_pk || mlkem_sk
        // Reconstruct raw_bytes = x25519_sk(32) || x25519_pk(32) || mlkem_sk
        if classical.len() < 64 {
            bail!("composite KEM classical field too short in DER: {} bytes", classical.len());
        }
        let pk_size = cli_alg
            .hybrid_kem_pk_size()
            .ok_or_else(|| anyhow::anyhow!("internal: no pk size for {cli_alg}"))?;
        // mlkem_pk_size = pk_size - 32 (subtract the x25519_pk part)
        let mlkem_pk_size = pk_size - 32;
        if pqc.len() < mlkem_pk_size {
            bail!(
                "composite KEM PQC field too short: {} bytes, expected at least {mlkem_pk_size}",
                pqc.len()
            );
        }
        let mlkem_pk = pqc[..mlkem_pk_size].to_vec();
        let mlkem_sk = &pqc[mlkem_pk_size..];

        // raw_sk = x25519_sk || x25519_pk || mlkem_sk
        let mut raw_sk = Vec::with_capacity(classical.len() + mlkem_sk.len());
        raw_sk.extend_from_slice(&classical);
        raw_sk.extend_from_slice(mlkem_sk);

        // Reconstruct the full hybrid pk = x25519_pk(32) || mlkem_pk
        let x25519_pk = &classical[32..64];
        let mut full_pk = Vec::with_capacity(32 + mlkem_pk.len());
        full_pk.extend_from_slice(x25519_pk);
        full_pk.extend_from_slice(&mlkem_pk);

        return Ok((raw_sk, cli_alg, Some(full_pk)));
    }
    // Try composite sign (hybrid sign secret key).
    if let Ok((variant, classical, pqc)) = composite::decode_composite_sign_key(der_bytes) {
        let cli_alg = CliAlgorithm::from_composite_sign_variant(variant);
        // classical = ed_seed(32), pqc = mldsa_seed(32)
        // raw_bytes = ed_seed(32) || mldsa_seed(32)
        let mut raw = Vec::with_capacity(classical.len() + pqc.len());
        raw.extend_from_slice(&classical);
        raw.extend_from_slice(&pqc);
        return Ok((raw, cli_alg, None));
    }
    bail!("could not decode DER secret key: no known format matched")
}

fn encode_signature_der(sig_bytes: &[u8], alg: CliAlgorithm) -> Result<Vec<u8>> {
    if let Some(sign_alg) = alg.to_sign_algorithm() {
        der::encode_signature_der(sign_alg, sig_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else if let Some(sign_variant) = alg.to_composite_sign_variant() {
        // Hybrid signature: sig_bytes = [4-byte LE len][ed_sig][4-byte LE len][mldsa_sig]
        // (per lupine-sign hybrid.rs serialization format)
        let (ed_sig, mldsa_sig) = split_hybrid_sig(sig_bytes)?;
        composite::encode_composite_signature(sign_variant, &ed_sig, &mldsa_sig)
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    } else {
        bail!("algorithm {alg} is not a signature algorithm")
    }
}

fn decode_signature_der(der_bytes: &[u8]) -> Result<(Vec<u8>, CliAlgorithm)> {
    if let Ok((sign_alg, raw)) = der::decode_signature_der(der_bytes) {
        return Ok((raw, CliAlgorithm::from_sign_algorithm(sign_alg)));
    }
    if let Ok((variant, ed_sig, mldsa_sig)) = composite::decode_composite_signature(der_bytes) {
        let cli_alg = CliAlgorithm::from_composite_sign_variant(variant);
        // Re-encode in the lupine-sign wire format: 4-byte LE len prefix per component
        let raw = join_hybrid_sig(&ed_sig, &mldsa_sig);
        return Ok((raw, cli_alg));
    }
    bail!("could not decode DER signature: no known format matched")
}

// ---------------------------------------------------------------------------
// Hybrid signature wire format helpers
// ---------------------------------------------------------------------------

/// Split a lupine-sign hybrid signature wire format into (ed_sig, mldsa_sig).
///
/// Wire format: `[4-byte LE len][ed_sig][4-byte LE len][mldsa_sig]`
fn split_hybrid_sig(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if bytes.len() < 4 {
        bail!("hybrid signature too short");
    }
    let ed_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if bytes.len() < 4 + ed_len + 4 {
        bail!("hybrid signature truncated (ed component)");
    }
    let ed_sig = bytes[4..4 + ed_len].to_vec();
    let rest = &bytes[4 + ed_len..];
    let mldsa_len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
    if rest.len() < 4 + mldsa_len {
        bail!("hybrid signature truncated (mldsa component)");
    }
    let mldsa_sig = rest[4..4 + mldsa_len].to_vec();
    Ok((ed_sig, mldsa_sig))
}

/// Join two signature components into the lupine-sign wire format.
fn join_hybrid_sig(ed_sig: &[u8], mldsa_sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ed_sig.len() + 4 + mldsa_sig.len());
    out.extend_from_slice(&(ed_sig.len() as u32).to_le_bytes());
    out.extend_from_slice(ed_sig);
    out.extend_from_slice(&(mldsa_sig.len() as u32).to_le_bytes());
    out.extend_from_slice(mldsa_sig);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_sig_wire_format_roundtrip() {
        let ed = vec![1u8; 64];
        let mldsa = vec![2u8; 100];
        let wire = join_hybrid_sig(&ed, &mldsa);
        let (ed2, mldsa2) = split_hybrid_sig(&wire).unwrap();
        assert_eq!(ed, ed2);
        assert_eq!(mldsa, mldsa2);
    }

    #[test]
    fn hybrid_sig_split_rejects_truncated() {
        assert!(split_hybrid_sig(&[0, 0, 0, 0]).is_err() || split_hybrid_sig(&[1, 0, 0, 0]).is_err());
    }
}
