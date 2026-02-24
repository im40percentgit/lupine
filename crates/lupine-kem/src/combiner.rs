//! KitchenSink KDF combiner for hybrid KEM shared-secret derivation.
//!
//! Implements the KitchenSink construction from the IETF HPKE hybrid PQC
//! draft: a single HKDF-SHA-256 call whose IKM is the ordered concatenation
//! of all secrets, ciphertexts, and public keys from every component KEM.
//! This ensures that the combined shared secret is secure as long as at least
//! one component KEM is secure (classical or post-quantum).
//!
//! # Construction
//!
//! ```text
//! IKM = x25519_ss || mlkem_ss || x25519_ct || mlkem_ct || x25519_pk || mlkem_pk
//! combined = HKDF-SHA-256(salt=b"", ikm=IKM, info=b"lupine-hybrid-kem", L=32)
//! ```
//!
//! @decision DEC-HYBRID-KEM-001
//! @title KitchenSink combiner vs. XOR/concatenation
//! @status accepted
//! @rationale KitchenSink (HKDF over all secrets + ciphertexts + public keys)
//!   provides security under the weakest-link assumption: the combined secret
//!   is secure as long as at least one component KEM is secure. Simple XOR
//!   would fail if either component is all-zeros or if there is algebraic
//!   correlation. Concatenation without a KDF would leak partial information.
//!   HKDF-SHA-256 with a fixed info label also provides domain separation
//!   between different hybrid instantiations.

extern crate alloc;

use hkdf::Hkdf;
use sha2::Sha256;

use lupine_core::SharedSecret;

/// Domain-separation label for the Lupine hybrid KEM KitchenSink combiner.
const INFO: &[u8] = b"lupine-hybrid-kem";

/// Derive a 32-byte combined shared secret using the KitchenSink construction.
///
/// # Parameters
///
/// - `x25519_ss`: 32-byte X25519 shared secret.
/// - `mlkem_ss`: ML-KEM shared secret (32 bytes per FIPS 203).
/// - `x25519_ct`: 32-byte X25519 ephemeral public key (the "ciphertext" in hybrid).
/// - `mlkem_ct`: ML-KEM ciphertext bytes.
/// - `x25519_pk`: 32-byte X25519 static public key.
/// - `mlkem_pk`: ML-KEM encapsulation key bytes.
///
/// Returns a [`SharedSecret`] of exactly 32 bytes.
pub fn kitchen_sink(
    x25519_ss: &[u8],
    mlkem_ss: &[u8],
    x25519_ct: &[u8],
    mlkem_ct: &[u8],
    x25519_pk: &[u8],
    mlkem_pk: &[u8],
) -> SharedSecret {
    // Build IKM as ordered concatenation of all inputs.
    let mut ikm = alloc::vec::Vec::with_capacity(
        x25519_ss.len()
            + mlkem_ss.len()
            + x25519_ct.len()
            + mlkem_ct.len()
            + x25519_pk.len()
            + mlkem_pk.len(),
    );
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ct);
    ikm.extend_from_slice(mlkem_ct);
    ikm.extend_from_slice(x25519_pk);
    ikm.extend_from_slice(mlkem_pk);

    // HKDF-Extract with no salt (treated as all-zeros per RFC 5869),
    // then HKDF-Expand with the domain-separation label.
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(INFO, &mut okm)
        .expect("HKDF expand with 32-byte output always succeeds");

    SharedSecret::new(okm.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The combiner must produce a 32-byte output.
    #[test]
    fn output_is_32_bytes() {
        let ss = kitchen_sink(
            &[0u8; 32], // x25519_ss
            &[1u8; 32], // mlkem_ss
            &[2u8; 32], // x25519_ct (ephemeral pk)
            &[3u8; 64], // mlkem_ct (example size)
            &[4u8; 32], // x25519_pk
            &[5u8; 96], // mlkem_pk (example size)
        );
        assert_eq!(ss.as_bytes().len(), 32, "combined shared secret must be 32 bytes");
    }

    /// The same inputs must always produce the same output (determinism).
    #[test]
    fn deterministic() {
        let inputs = (
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            [3u8; 64],
            [4u8; 32],
            [5u8; 96],
        );
        let ss1 = kitchen_sink(&inputs.0, &inputs.1, &inputs.2, &inputs.3, &inputs.4, &inputs.5);
        let ss2 = kitchen_sink(&inputs.0, &inputs.1, &inputs.2, &inputs.3, &inputs.4, &inputs.5);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "combiner must be deterministic");
    }

    /// Different inputs must produce different outputs (collision resistance).
    #[test]
    fn different_inputs_differ() {
        let ss_a = kitchen_sink(
            &[0u8; 32], &[1u8; 32], &[2u8; 32], &[3u8; 64], &[4u8; 32], &[5u8; 96],
        );
        let ss_b = kitchen_sink(
            &[0u8; 32], &[9u8; 32], &[2u8; 32], &[3u8; 64], &[4u8; 32], &[5u8; 96],
        );
        assert_ne!(
            ss_a.as_bytes(),
            ss_b.as_bytes(),
            "different ML-KEM shared secrets must produce different combined secrets"
        );
    }
}
