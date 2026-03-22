//! ML-DSA (FIPS 204) wrapper for the Lupine PQC suite.
//!
//! Provides `MlDsaSigningKey<P>`, `MlDsaVerifyingKey<P>`, and `MlDsaSignature<P>`
//! types that wrap the RustCrypto `ml-dsa` crate and surface a Lupine-idiomatic
//! API: byte-oriented key serialization, Lupine `Error`/`Result` types, and a
//! consistent interface matching `lupine-kem`'s patterns.
//!
//! # Key serialization
//!
//! Signing keys are stored and serialized as 32-byte **seeds** (the canonical
//! FIPS 204 representation), which is also the preferred form recommended by the
//! `ml-dsa` crate (the expanded ~2–5 KB form is deprecated).  Verifying keys use
//! the standard pkEncode encoding (1312–2592 bytes depending on parameter set).
//!
//! # Parameter sets
//!
//! | Alias                | NIST Level | SK seed | VK     | Sig    |
//! |----------------------|-----------|---------|--------|--------|
//! | `MlDsa44SigningKey`  | 2          | 32 B    | 1312 B | 2420 B |
//! | `MlDsa65SigningKey`  | 3          | 32 B    | 1952 B | 3309 B |
//! | `MlDsa87SigningKey`  | 5          | 32 B    | 2592 B | 4627 B |
//!
//! @decision DEC-SIGN-001
//! @title Seed-based signing key serialization for ML-DSA
//! @status accepted
//! @rationale The ml-dsa crate recommends storing the 32-byte seed rather
//!   than the expanded signing key (~2–5 KB).  The seed is smaller, is the
//!   canonical FIPS 204 representation, and allows the full key to be
//!   reconstructed deterministically.  The expanded form is marked deprecated
//!   in ml-dsa 0.1.0-rc.7 and can panic on malformed input, making the seed
//!   the only safe serialization path.
//!
//! @decision DEC-SIGN-002
//! @title Native-API approach to avoid signature 2.x / 3.x version conflict
//! @status accepted
//! @rationale The ml-dsa RC crates require signature 3.x while lupine-kem
//!   depends on the stable signature 2.x via ml-kem.  Using lupine-sign's own
//!   pinned RC deps (signature 3.x, rand_core 0.10, rand 0.10) declared
//!   directly in lupine-sign/Cargo.toml isolates the two version trees — Cargo
//!   compiles both without conflict.  We expose the Lupine Error/Result types
//!   at the wrapper boundary and do not re-export the signature 3.x traits, so
//!   callers never need to reconcile the two signature crate versions.

extern crate alloc;

use alloc::vec::Vec;

use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsaParams, Signature, SigningKey,
    VerifyingKey,
};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use lupine_core::{Error, Result};

// ── Type aliases ─────────────────────────────────────────────────────────────

/// ML-DSA-44 signing key — NIST security category 2.
pub type MlDsa44SigningKey = MlDsaSigningKey<ml_dsa::MlDsa44>;
/// ML-DSA-44 verifying key — NIST security category 2.
pub type MlDsa44VerifyingKey = MlDsaVerifyingKey<ml_dsa::MlDsa44>;
/// ML-DSA-44 signature — NIST security category 2.
pub type MlDsa44Signature = MlDsaSignature<ml_dsa::MlDsa44>;

/// ML-DSA-65 signing key — NIST security category 3.
pub type MlDsa65SigningKey = MlDsaSigningKey<ml_dsa::MlDsa65>;
/// ML-DSA-65 verifying key — NIST security category 3.
pub type MlDsa65VerifyingKey = MlDsaVerifyingKey<ml_dsa::MlDsa65>;
/// ML-DSA-65 signature — NIST security category 3.
pub type MlDsa65Signature = MlDsaSignature<ml_dsa::MlDsa65>;

/// ML-DSA-87 signing key — NIST security category 5.
pub type MlDsa87SigningKey = MlDsaSigningKey<ml_dsa::MlDsa87>;
/// ML-DSA-87 verifying key — NIST security category 5.
pub type MlDsa87VerifyingKey = MlDsaVerifyingKey<ml_dsa::MlDsa87>;
/// ML-DSA-87 signature — NIST security category 5.
pub type MlDsa87Signature = MlDsaSignature<ml_dsa::MlDsa87>;

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate an ML-DSA keypair for parameter set `P`.
///
/// Returns `(signing_key, verifying_key)`.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if the RNG fails to produce entropy.
pub fn generate_keypair<P: KeyGen + MlDsaParams>(
    rng: &mut impl CryptoRng,
) -> Result<(MlDsaSigningKey<P>, MlDsaVerifyingKey<P>)> {
    // Generate a random 32-byte seed and use the canonical `from_seed` path.
    // This avoids depending on the concrete `KeyPair` associated type from
    // `KeyGen`, which varies across callers and would propagate a complex
    // `KeyGen<KeyPair = KeyPair<P>>` bound everywhere.
    let mut seed_bytes = [0u8; 32];
    rng.fill_bytes(&mut seed_bytes);
    let seed = B32::from(seed_bytes);

    let sk_native = SigningKey::<P>::from_seed(&seed);
    let vk_native = sk_native.verifying_key();
    let vk_bytes = vk_native.encode().to_vec();

    let signing_key = MlDsaSigningKey {
        seed: seed_bytes,
        native: sk_native,
    };
    let verifying_key = MlDsaVerifyingKey {
        bytes: vk_bytes,
        native: vk_native,
    };

    Ok((signing_key, verifying_key))
}

// ── MlDsaSigningKey ───────────────────────────────────────────────────────────

/// An ML-DSA signing key, generic over the parameter set `P`.
///
/// Internally stores the 32-byte seed (the canonical FIPS 204 secret key
/// representation) and the derived expanded signing key for fast signing.
///
/// Use the type aliases [`MlDsa44SigningKey`], [`MlDsa65SigningKey`], or
/// [`MlDsa87SigningKey`] for concrete parameter sets.
///
/// # Memory safety
///
/// `Drop` zeroizes the 32-byte `seed` field. The native `SigningKey<P>`
/// handles its own zeroization via `ZeroizeOnDrop` (activated through the
/// `ml-dsa/zeroize` feature).
#[derive(Clone)]
pub struct MlDsaSigningKey<P: MlDsaParams> {
    /// The 32-byte seed — the serializable form of this key.
    seed: [u8; 32],
    /// Derived expanded signing key (kept for signing without re-expansion).
    native: SigningKey<P>,
}

/// @decision DEC-SIGN-005
/// @title Manual Drop for MlDsaSigningKey instead of ZeroizeOnDrop derive
/// @status accepted
/// @rationale `#[derive(ZeroizeOnDrop)]` requires every field to implement
///   `Zeroize`. `SigningKey<P>` does not expose `Zeroize` as a supertrait of
///   `MlDsaParams`, so the derive cannot verify it at the wrapper level. A
///   manual `Drop` zeroizes the `seed` array owned by the wrapper; the native
///   `SigningKey<P>` is handled by its own `ZeroizeOnDrop` via `ml-dsa/zeroize`.
impl<P: MlDsaParams> Drop for MlDsaSigningKey<P> {
    fn drop(&mut self) {
        self.seed.zeroize();
        // self.native: SigningKey<P> has ZeroizeOnDrop via ml-dsa/zeroize feature.
    }
}

impl<P: MlDsaParams + KeyGen> MlDsaSigningKey<P> {
    /// Deserialize a signing key from a 32-byte seed.
    ///
    /// The seed is the canonical FIPS 204 private key representation.
    /// Passing any 32-byte value is valid — the expanded key is derived
    /// deterministically from the seed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `bytes` is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let seed_arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let seed = ml_dsa::B32::from(seed_arr);
        let native = SigningKey::<P>::from_seed(&seed);
        Ok(Self {
            seed: seed_arr,
            native,
        })
    }

    /// Serialize this signing key to its 32-byte seed representation.
    ///
    /// Treat the result as secret material — store it securely and zeroize
    /// after use.
    pub fn to_bytes(&self) -> &[u8] {
        &self.seed
    }

    /// Sign `message` using the deterministic ML-DSA.Sign variant with an
    /// empty context string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] if signing fails (should not occur under
    /// normal circumstances).
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature<P>> {
        let sig = self
            .native
            .sign_deterministic(message, &[])
            .map_err(|_| Error::Signing)?;
        let encoded = sig.encode();
        Ok(MlDsaSignature {
            bytes: encoded.to_vec(),
            native: sig,
        })
    }

    /// Derive the corresponding [`MlDsaVerifyingKey`] from this signing key.
    ///
    /// This is a moderately expensive operation (matrix expansion); cache the
    /// result if you need to verify repeatedly.
    pub fn verifying_key(&self) -> MlDsaVerifyingKey<P> {
        let vk = self.native.verifying_key();
        let bytes = vk.encode().to_vec();
        MlDsaVerifyingKey { bytes, native: vk }
    }
}

impl<P: MlDsaParams> core::fmt::Debug for MlDsaSigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsaSigningKey")
            .finish_non_exhaustive()
    }
}

// ── MlDsaVerifyingKey ─────────────────────────────────────────────────────────

/// An ML-DSA verifying (public) key, generic over the parameter set `P`.
///
/// Use the type aliases [`MlDsa44VerifyingKey`], [`MlDsa65VerifyingKey`], or
/// [`MlDsa87VerifyingKey`] for concrete parameter sets.
#[derive(Clone, Debug, PartialEq)]
pub struct MlDsaVerifyingKey<P: MlDsaParams> {
    /// Encoded verifying key bytes (pkEncode output).
    bytes: Vec<u8>,
    /// Parsed native key (kept for verification without re-parsing).
    native: VerifyingKey<P>,
}

impl<P: MlDsaParams> MlDsaVerifyingKey<P> {
    /// Deserialize a verifying key from its encoded byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `bytes` is not the correct length for
    /// this parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = EncodedVerifyingKey::<P>::try_from(bytes)
            .map_err(|_| Error::InvalidKey)?;
        let native = VerifyingKey::<P>::decode(&encoded);
        Ok(Self {
            bytes: bytes.to_vec(),
            native,
        })
    }

    /// Serialize this verifying key to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Verify `signature` over `message`.
    ///
    /// Uses the deterministic ML-DSA.Verify path with an empty context string,
    /// matching the signing convention in [`MlDsaSigningKey::sign`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature<P>) -> Result<()> {
        if self.native.verify_with_context(message, &[], &signature.native) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

// Equality on the canonical byte encoding — two VKs with identical bytes are
// identical keys (pkEncode is deterministic).
impl<P: MlDsaParams> Eq for MlDsaVerifyingKey<P> {}

// ── MlDsaSignature ────────────────────────────────────────────────────────────

/// An ML-DSA signature, generic over the parameter set `P`.
///
/// Signatures are 2420–4627 bytes depending on the parameter set.
#[derive(Clone, Debug, PartialEq)]
pub struct MlDsaSignature<P: MlDsaParams> {
    /// Encoded signature bytes.
    bytes: Vec<u8>,
    /// Parsed native signature (kept to avoid re-parsing on verify).
    native: Signature<P>,
}

impl<P: MlDsaParams> MlDsaSignature<P> {
    /// Deserialize a signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if `bytes` cannot be decoded as a valid
    /// signature for this parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = EncodedSignature::<P>::try_from(bytes)
            .map_err(|_| Error::Verification)?;
        let native = Signature::<P>::decode(&encoded)
            .ok_or(Error::Verification)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            native,
        })
    }

    /// Serialize this signature to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Equality on the canonical byte encoding — two signatures with identical
// bytes are identical (sigEncode is deterministic).
impl<P: MlDsaParams> Eq for MlDsaSignature<P> {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rng() -> rand::rngs::ThreadRng {
        rand::rng()
    }

    /// Run `f` on a thread with a 32 MB stack.
    ///
    /// ML-DSA-87 operations allocate large intermediate arrays during signing
    /// and verification. In unoptimized (debug) builds these live on the stack
    /// and overflow the default 8 MB thread stack. Spawning with a larger stack
    /// is the idiomatic workaround until the upstream crate moves to heap
    /// allocation for those intermediates.
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── Round-trip tests (keygen → sign → verify) ────────────────────────────

    fn roundtrip<P>()
    where
        P: KeyGen + MlDsaParams,
    {
        let (sk, vk) = generate_keypair::<P>(&mut make_rng())
            .expect("keygen must succeed");
        let msg = b"lupine phase 2 test message";
        let sig = sk.sign(msg).expect("sign must succeed");
        vk.verify(msg, &sig).expect("verify must succeed");
    }

    #[test]
    fn roundtrip_44() { roundtrip::<ml_dsa::MlDsa44>(); }
    #[test]
    fn roundtrip_65() { roundtrip::<ml_dsa::MlDsa65>(); }
    #[test]
    fn roundtrip_87() { with_large_stack(|| roundtrip::<ml_dsa::MlDsa87>()); }

    // ── Tamper detection ─────────────────────────────────────────────────────

    fn tamper_detection<P>()
    where
        P: KeyGen + MlDsaParams,
    {
        let (sk, vk) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let msg = b"message to sign";
        let sig = sk.sign(msg).unwrap();

        // Flip first byte of the encoded signature
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes[0] ^= 0xFF;
        let tampered = MlDsaSignature::<P>::from_bytes(&sig_bytes);
        // Tampered signature is either un-decodable or verifies as invalid
        match tampered {
            Err(_) => {} // decode failed — tamper detected at decode
            Ok(t) => {
                assert!(
                    vk.verify(msg, &t).is_err(),
                    "tampered signature must not verify"
                );
            }
        }
    }

    #[test]
    fn tamper_detection_44() { tamper_detection::<ml_dsa::MlDsa44>(); }
    #[test]
    fn tamper_detection_65() { tamper_detection::<ml_dsa::MlDsa65>(); }
    #[test]
    fn tamper_detection_87() { with_large_stack(|| tamper_detection::<ml_dsa::MlDsa87>()); }

    // ── Wrong-key detection ──────────────────────────────────────────────────

    fn wrong_key_detection<P>()
    where
        P: KeyGen + MlDsaParams,
    {
        let (sk_a, _vk_a) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let (_sk_b, vk_b) = generate_keypair::<P>(&mut make_rng()).unwrap();

        let msg = b"signed with key A";
        let sig = sk_a.sign(msg).unwrap();

        assert!(
            vk_b.verify(msg, &sig).is_err(),
            "signature from key A must not verify with key B"
        );
    }

    #[test]
    fn wrong_key_detection_44() { wrong_key_detection::<ml_dsa::MlDsa44>(); }
    #[test]
    fn wrong_key_detection_65() { wrong_key_detection::<ml_dsa::MlDsa65>(); }
    #[test]
    fn wrong_key_detection_87() { with_large_stack(|| wrong_key_detection::<ml_dsa::MlDsa87>()); }

    // ── Signing key serialization round-trip ─────────────────────────────────

    fn sk_serialization<P>()
    where
        P: KeyGen + MlDsaParams,
    {
        let (sk, _vk) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let seed_bytes = sk.to_bytes().to_vec();
        let sk2 = MlDsaSigningKey::<P>::from_bytes(&seed_bytes)
            .expect("sk round-trip must succeed");

        // Verify the reconstructed key produces the same signature on the same message.
        // (Deterministic signing means equal seeds => equal signatures.)
        let msg = b"seed round-trip verification";
        let sig1 = sk.sign(msg).unwrap();
        let sig2 = sk2.sign(msg).unwrap();
        assert_eq!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "signing keys reconstructed from same seed must produce identical signatures"
        );
    }

    #[test]
    fn sk_serialization_44() { sk_serialization::<ml_dsa::MlDsa44>(); }
    #[test]
    fn sk_serialization_65() { sk_serialization::<ml_dsa::MlDsa65>(); }
    #[test]
    fn sk_serialization_87() { with_large_stack(|| sk_serialization::<ml_dsa::MlDsa87>()); }

    // ── Verifying key serialization round-trip ───────────────────────────────

    fn vk_serialization<P>()
    where
        P: KeyGen + MlDsaParams,
    {
        let (_sk, vk) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let vk_bytes = vk.to_bytes().to_vec();
        let vk2 = MlDsaVerifyingKey::<P>::from_bytes(&vk_bytes)
            .expect("vk round-trip must succeed");
        assert_eq!(
            vk.to_bytes(),
            vk2.to_bytes(),
            "verifying key round-trip must be identical"
        );
    }

    #[test]
    fn vk_serialization_44() { vk_serialization::<ml_dsa::MlDsa44>(); }
    #[test]
    fn vk_serialization_65() { vk_serialization::<ml_dsa::MlDsa65>(); }
    #[test]
    fn vk_serialization_87() { with_large_stack(|| vk_serialization::<ml_dsa::MlDsa87>()); }

    // ── Signature bytes serialization round-trip ─────────────────────────────

    fn sig_serialization<P>()
    where
        P: KeyGen + MlDsaParams,
    {
        let (sk, vk) = generate_keypair::<P>(&mut make_rng()).unwrap();
        let msg = b"signature bytes round-trip";
        let sig = sk.sign(msg).unwrap();

        let sig_bytes = sig.to_bytes().to_vec();
        let sig2 = MlDsaSignature::<P>::from_bytes(&sig_bytes)
            .expect("sig round-trip must succeed");
        assert_eq!(
            sig.to_bytes(),
            sig2.to_bytes(),
            "signature byte round-trip must be identical"
        );
        vk.verify(msg, &sig2).expect("round-tripped signature must verify");
    }

    #[test]
    fn sig_serialization_44() { sig_serialization::<ml_dsa::MlDsa44>(); }
    #[test]
    fn sig_serialization_65() { sig_serialization::<ml_dsa::MlDsa65>(); }
    #[test]
    fn sig_serialization_87() { with_large_stack(|| sig_serialization::<ml_dsa::MlDsa87>()); }

    // ── Invalid byte rejection ───────────────────────────────────────────────

    #[test]
    fn sk_from_bytes_wrong_length() {
        let result = MlDsaSigningKey::<ml_dsa::MlDsa65>::from_bytes(&[0u8; 31]);
        assert!(result.is_err(), "31-byte seed must be rejected");
        let result = MlDsaSigningKey::<ml_dsa::MlDsa65>::from_bytes(&[0u8; 33]);
        assert!(result.is_err(), "33-byte seed must be rejected");
    }

    #[test]
    fn vk_from_bytes_wrong_length() {
        let result = MlDsaVerifyingKey::<ml_dsa::MlDsa65>::from_bytes(&[0u8; 10]);
        assert!(result.is_err(), "short vk bytes must be rejected");
    }
}
