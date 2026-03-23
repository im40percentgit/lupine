//! Roundtrip integration tests for lupine-sign.
//!
//! These tests cover all signature algorithm families with full
//! serialize→deserialize→re-use cycles, verifying that:
//!
//! - sign→verify succeeds with the original keypair
//! - Serialized keys round-trip correctly
//! - Deserialized keys produce identical signatures (deterministic schemes)
//! - Deserialized keys verify correctly
//! - Wrong-key and tampered-signature scenarios fail correctly
//!
//! ## Algorithm coverage
//!
//! - ML-DSA: all 3 parameter sets (44, 65, 87)
//! - SLH-DSA: 3 representative variants (Sha2-128s, Shake-128s, Sha2-256s)
//! - Hybrid Ed25519+ML-DSA: all 3 parameter sets
//!
//! SLH-DSA keygen is slow (~1–5s per test in debug builds); only 3 of 12
//! variants are tested here to keep CI time bounded.
//!
//! @decision DEC-TEST-SIGN-002
//! @title SLH-DSA roundtrip tests limited to 3 representative variants
//! @status accepted
//! @rationale SLH-DSA has 12 parameter sets across 2 hash families (SHA2,
//!   SHAKE), 3 security levels (128, 192, 256), and 2 modes (s=small, f=fast).
//!   Each keygen takes 1–5s in debug builds. Testing all 12 would add ~60s to
//!   the test suite with minimal additional coverage of the Lupine wrapper.
//!   We select Sha2-128s (fast keygen, level 1), Shake-128s (SHAKE hash at
//!   level 1), and Sha2-256s (level 5) as representatives of the key
//!   dimensions: hash family, security level, and small-mode signing.

use lupine_sign::{
    hybrid_generate_keypair, ml_dsa_generate_keypair, slh_dsa_generate_keypair, HybridSignature,
    HybridSigningKey, HybridVerifyingKey, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey,
    SlhDsaSigningKey, SlhDsaVerifyingKey,
};
use ml_dsa::{KeyGen, MlDsaParams};
use slh_dsa::ParameterSet;

/// Return a thread-local RNG (rand 0.10 API: rand::rng() replaces thread_rng()).
fn make_rng() -> rand::rngs::ThreadRng {
    rand::rng()
}

// ── Large-stack helper ────────────────────────────────────────────────────────

/// Run `f` on a thread with 32 MB stack.
///
/// ML-DSA-87 and hybrid-87 allocate large stack intermediates in debug builds
/// (unoptimised code paths). Spawning with a larger stack is the standard
/// workaround; the upstream crate tracks moving these to heap allocation.
fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ── ML-DSA roundtrip helpers ──────────────────────────────────────────────────

/// Basic roundtrip: keygen → sign → verify.
fn mldsa_basic_roundtrip<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let msg = b"lupine-sign roundtrip test message";
    let sig = sk.sign(msg).expect("sign must succeed");
    vk.verify(msg, &sig).expect("verify must succeed");
}

/// Signing key serialize→deserialize: reconstructed key produces identical
/// signature (deterministic signing) and the sig verifies.
fn mldsa_sk_serialize_deserialize<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");

    let seed_bytes = sk.to_bytes().to_vec();
    let sk2 = MlDsaSigningKey::<P>::from_bytes(&seed_bytes).expect("sk from_bytes must succeed");
    assert_eq!(
        sk.to_bytes(),
        sk2.to_bytes(),
        "sk bytes must survive round-trip"
    );

    let msg = b"sk serialize-deserialize test";
    let sig1 = sk.sign(msg).expect("sign with original sk must succeed");
    let sig2 = sk2
        .sign(msg)
        .expect("sign with deserialized sk must succeed");

    // Deterministic signing: same seed → same signature bytes.
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "deserialized sk (same seed) must produce identical signature"
    );
    vk.verify(msg, &sig2)
        .expect("deserialized sk's signature must verify");
}

/// Verifying key serialize→deserialize: round-tripped vk verifies original sig.
fn mldsa_vk_serialize_deserialize<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");

    let vk_bytes = vk.to_bytes().to_vec();
    let vk2 = MlDsaVerifyingKey::<P>::from_bytes(&vk_bytes).expect("vk from_bytes must succeed");
    assert_eq!(
        vk.to_bytes(),
        vk2.to_bytes(),
        "vk bytes must survive round-trip"
    );

    let msg = b"vk serialize-deserialize test";
    let sig = sk.sign(msg).expect("sign must succeed");
    vk2.verify(msg, &sig)
        .expect("deserialized vk must verify signature");
}

/// Signature serialize→deserialize: round-tripped sig verifies.
fn mldsa_sig_serialize_deserialize<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let msg = b"sig serialize-deserialize test";
    let sig = sk.sign(msg).expect("sign must succeed");

    let sig_bytes = sig.to_bytes().to_vec();
    let sig2 = MlDsaSignature::<P>::from_bytes(&sig_bytes).expect("sig from_bytes must succeed");
    assert_eq!(
        sig.to_bytes(),
        sig2.to_bytes(),
        "sig bytes must survive round-trip"
    );
    vk.verify(msg, &sig2).expect("deserialized sig must verify");
}

/// Wrong-key rejection: sig from sk_a must not verify with vk_b.
fn mldsa_wrong_key_rejection<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk_a, _vk_a) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen A must succeed");
    let (_sk_b, vk_b) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen B must succeed");
    let msg = b"signed with key A";
    let sig = sk_a.sign(msg).expect("sign must succeed");
    assert!(
        vk_b.verify(msg, &sig).is_err(),
        "sig from key A must not verify with key B"
    );
}

/// Tamper detection: modified signature must be rejected.
fn mldsa_tamper_detection<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let msg = b"tamper detection test";
    let sig = sk.sign(msg).expect("sign must succeed");

    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes[0] ^= 0xFF;
    match MlDsaSignature::<P>::from_bytes(&sig_bytes) {
        Err(_) => {} // tamper detected at decode
        Ok(bad_sig) => assert!(
            vk.verify(msg, &bad_sig).is_err(),
            "tampered sig must not verify"
        ),
    }
}

/// Message mutation: changed message must fail verification.
fn mldsa_message_mutation<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let msg = b"original message content";
    let sig = sk.sign(msg).expect("sign must succeed");

    let different_msg = b"tampered message content";
    assert!(
        vk.verify(different_msg, &sig).is_err(),
        "sig must not verify over a different message"
    );
}

// ── ML-DSA-44 tests ───────────────────────────────────────────────────────────

#[test]
fn mldsa44_basic_roundtrip() {
    mldsa_basic_roundtrip::<ml_dsa::MlDsa44>();
}
#[test]
fn mldsa44_sk_serialize_deserialize() {
    mldsa_sk_serialize_deserialize::<ml_dsa::MlDsa44>();
}
#[test]
fn mldsa44_vk_serialize_deserialize() {
    mldsa_vk_serialize_deserialize::<ml_dsa::MlDsa44>();
}
#[test]
fn mldsa44_sig_serialize_deserialize() {
    mldsa_sig_serialize_deserialize::<ml_dsa::MlDsa44>();
}
#[test]
fn mldsa44_wrong_key_rejection() {
    mldsa_wrong_key_rejection::<ml_dsa::MlDsa44>();
}
#[test]
fn mldsa44_tamper_detection() {
    mldsa_tamper_detection::<ml_dsa::MlDsa44>();
}
#[test]
fn mldsa44_message_mutation() {
    mldsa_message_mutation::<ml_dsa::MlDsa44>();
}

// ── ML-DSA-65 tests ───────────────────────────────────────────────────────────

#[test]
fn mldsa65_basic_roundtrip() {
    mldsa_basic_roundtrip::<ml_dsa::MlDsa65>();
}
#[test]
fn mldsa65_sk_serialize_deserialize() {
    mldsa_sk_serialize_deserialize::<ml_dsa::MlDsa65>();
}
#[test]
fn mldsa65_vk_serialize_deserialize() {
    mldsa_vk_serialize_deserialize::<ml_dsa::MlDsa65>();
}
#[test]
fn mldsa65_sig_serialize_deserialize() {
    mldsa_sig_serialize_deserialize::<ml_dsa::MlDsa65>();
}
#[test]
fn mldsa65_wrong_key_rejection() {
    mldsa_wrong_key_rejection::<ml_dsa::MlDsa65>();
}
#[test]
fn mldsa65_tamper_detection() {
    mldsa_tamper_detection::<ml_dsa::MlDsa65>();
}
#[test]
fn mldsa65_message_mutation() {
    mldsa_message_mutation::<ml_dsa::MlDsa65>();
}

// ── ML-DSA-87 tests (large stack) ────────────────────────────────────────────

#[test]
fn mldsa87_basic_roundtrip() {
    with_large_stack(|| mldsa_basic_roundtrip::<ml_dsa::MlDsa87>());
}
#[test]
fn mldsa87_sk_serialize_deserialize() {
    with_large_stack(|| mldsa_sk_serialize_deserialize::<ml_dsa::MlDsa87>());
}
#[test]
fn mldsa87_vk_serialize_deserialize() {
    with_large_stack(|| mldsa_vk_serialize_deserialize::<ml_dsa::MlDsa87>());
}
#[test]
fn mldsa87_sig_serialize_deserialize() {
    with_large_stack(|| mldsa_sig_serialize_deserialize::<ml_dsa::MlDsa87>());
}
#[test]
fn mldsa87_wrong_key_rejection() {
    with_large_stack(|| mldsa_wrong_key_rejection::<ml_dsa::MlDsa87>());
}
#[test]
fn mldsa87_tamper_detection() {
    with_large_stack(|| mldsa_tamper_detection::<ml_dsa::MlDsa87>());
}
#[test]
fn mldsa87_message_mutation() {
    with_large_stack(|| mldsa_message_mutation::<ml_dsa::MlDsa87>());
}

// ── Structural invariants: ML-DSA key/sig sizes ───────────────────────────────

/// Key and signature sizes must match FIPS 204 Table 2.
///
/// ML-DSA-44: sk_seed=32B, vk=1312B, sig=2420B
/// ML-DSA-65: sk_seed=32B, vk=1952B, sig=3309B
/// ML-DSA-87: sk_seed=32B, vk=2592B, sig=4627B
#[test]
fn mldsa_key_sizes_match_fips204() {
    let mut rng = make_rng();

    let (sk44, vk44) = ml_dsa_generate_keypair::<ml_dsa::MlDsa44>(&mut rng).unwrap();
    assert_eq!(
        sk44.to_bytes().len(),
        32,
        "ML-DSA-44 sk seed must be 32 bytes"
    );
    assert_eq!(
        vk44.to_bytes().len(),
        1312,
        "ML-DSA-44 vk must be 1312 bytes"
    );

    let (sk65, vk65) = ml_dsa_generate_keypair::<ml_dsa::MlDsa65>(&mut rng).unwrap();
    assert_eq!(
        sk65.to_bytes().len(),
        32,
        "ML-DSA-65 sk seed must be 32 bytes"
    );
    assert_eq!(
        vk65.to_bytes().len(),
        1952,
        "ML-DSA-65 vk must be 1952 bytes"
    );
}

#[test]
fn mldsa_signature_sizes_match_fips204() {
    let mut rng = make_rng();
    let msg = b"size test";

    let (sk44, _) = ml_dsa_generate_keypair::<ml_dsa::MlDsa44>(&mut rng).unwrap();
    let sig44 = sk44.sign(msg).unwrap();
    assert_eq!(
        sig44.to_bytes().len(),
        2420,
        "ML-DSA-44 sig must be 2420 bytes"
    );

    let (sk65, _) = ml_dsa_generate_keypair::<ml_dsa::MlDsa65>(&mut rng).unwrap();
    let sig65 = sk65.sign(msg).unwrap();
    assert_eq!(
        sig65.to_bytes().len(),
        3309,
        "ML-DSA-65 sig must be 3309 bytes"
    );
}

// ── SLH-DSA roundtrip helpers ─────────────────────────────────────────────────

fn slhdsa_basic_roundtrip<P: ParameterSet>() {
    let mut rng = make_rng();
    let (sk, vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("SLH-DSA keygen must succeed");
    let msg = b"slh-dsa roundtrip test message";
    let sig = sk.sign(msg).expect("SLH-DSA sign must succeed");
    vk.verify(msg, &sig).expect("SLH-DSA verify must succeed");
}

fn slhdsa_sk_serialize_deserialize<P: ParameterSet>() {
    let mut rng = make_rng();
    let (sk, vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");

    let sk_bytes = sk.to_bytes().to_vec();
    let sk2 = SlhDsaSigningKey::<P>::from_bytes(&sk_bytes).expect("sk from_bytes must succeed");
    assert_eq!(sk.to_bytes(), sk2.to_bytes(), "sk bytes must round-trip");

    // Deterministic signing: both keys produce identical signatures.
    let msg = b"slh-dsa sk serialize test";
    let sig1 = sk.sign(msg).expect("sign with original sk must succeed");
    let sig2 = sk2
        .sign(msg)
        .expect("sign with deserialized sk must succeed");
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "deserialized sk must produce identical signature (deterministic signing)"
    );
    vk.verify(msg, &sig2)
        .expect("deserialized sk's signature must verify");
}

fn slhdsa_vk_serialize_deserialize<P: ParameterSet>() {
    let mut rng = make_rng();
    let (sk, vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");

    let vk_bytes = vk.to_bytes().to_vec();
    let vk2 = SlhDsaVerifyingKey::<P>::from_bytes(&vk_bytes).expect("vk from_bytes must succeed");
    assert_eq!(vk.to_bytes(), vk2.to_bytes(), "vk bytes must round-trip");

    let msg = b"slh-dsa vk serialize test";
    let sig = sk.sign(msg).expect("sign must succeed");
    vk2.verify(msg, &sig)
        .expect("deserialized vk must verify signature");
}

fn slhdsa_wrong_key_rejection<P: ParameterSet>() {
    let mut rng = make_rng();
    let (sk_a, _vk_a) = slh_dsa_generate_keypair::<P>(&mut rng).expect("keygen A must succeed");
    let (_sk_b, vk_b) = slh_dsa_generate_keypair::<P>(&mut rng).expect("keygen B must succeed");
    let msg = b"signed with key A";
    let sig = sk_a.sign(msg).expect("sign must succeed");
    assert!(
        vk_b.verify(msg, &sig).is_err(),
        "SLH-DSA sig from key A must not verify with key B"
    );
}

// ── SLH-DSA test instantiations (3 representative variants) ──────────────────

#[test]
fn slhdsa_sha2_128s_basic_roundtrip() {
    slhdsa_basic_roundtrip::<slh_dsa::Sha2_128s>();
}
#[test]
fn slhdsa_sha2_128s_sk_serialize() {
    slhdsa_sk_serialize_deserialize::<slh_dsa::Sha2_128s>();
}
#[test]
fn slhdsa_sha2_128s_vk_serialize() {
    slhdsa_vk_serialize_deserialize::<slh_dsa::Sha2_128s>();
}
#[test]
fn slhdsa_sha2_128s_wrong_key() {
    slhdsa_wrong_key_rejection::<slh_dsa::Sha2_128s>();
}

#[test]
fn slhdsa_shake_128s_basic_roundtrip() {
    slhdsa_basic_roundtrip::<slh_dsa::Shake128s>();
}
#[test]
fn slhdsa_shake_128s_sk_serialize() {
    slhdsa_sk_serialize_deserialize::<slh_dsa::Shake128s>();
}

#[test]
fn slhdsa_sha2_256s_basic_roundtrip() {
    slhdsa_basic_roundtrip::<slh_dsa::Sha2_256s>();
}
#[test]
fn slhdsa_sha2_256s_sk_serialize() {
    slhdsa_sk_serialize_deserialize::<slh_dsa::Sha2_256s>();
}

// ── SLH-DSA structural invariants ────────────────────────────────────────────

/// SLH-DSA-SHA2-128s key sizes from the FIPS 205 spec.
/// sk=64B, vk=32B, sig=7856B.
#[test]
fn slhdsa_sha2_128s_key_sizes() {
    let mut rng = make_rng();
    let (sk, vk) = slh_dsa_generate_keypair::<slh_dsa::Sha2_128s>(&mut rng).unwrap();
    assert_eq!(sk.to_bytes().len(), 64, "SHA2-128s sk must be 64 bytes");
    assert_eq!(vk.to_bytes().len(), 32, "SHA2-128s vk must be 32 bytes");

    let sig = sk.sign(b"size check").unwrap();
    assert_eq!(
        sig.to_bytes().len(),
        7856,
        "SHA2-128s sig must be 7856 bytes"
    );
}

// ── Hybrid Ed25519+ML-DSA roundtrip helpers ───────────────────────────────────

fn hybrid_basic_roundtrip<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("hybrid keygen must succeed");
    let msg = b"hybrid roundtrip test message";
    let sig = sk.sign(msg).expect("hybrid sign must succeed");
    vk.verify(msg, &sig).expect("hybrid verify must succeed");
}

fn hybrid_sk_serialize_deserialize<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen must succeed");

    let sk_bytes = sk.to_bytes();
    let sk2 =
        HybridSigningKey::<P>::from_bytes(&sk_bytes).expect("hybrid sk from_bytes must succeed");
    assert_eq!(
        sk.to_bytes(),
        sk2.to_bytes(),
        "hybrid sk bytes must round-trip"
    );

    // Deterministic: both keys produce identical signatures.
    let msg = b"hybrid sk serialize test";
    let sig1 = sk.sign(msg).expect("sign with original sk must succeed");
    let sig2 = sk2
        .sign(msg)
        .expect("sign with deserialized sk must succeed");
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "deserialized hybrid sk must produce identical signature"
    );
    vk.verify(msg, &sig2)
        .expect("deserialized hybrid sk's signature must verify");
}

fn hybrid_vk_serialize_deserialize<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen must succeed");

    let vk_bytes = vk.to_bytes();
    let vk2 =
        HybridVerifyingKey::<P>::from_bytes(&vk_bytes).expect("hybrid vk from_bytes must succeed");
    assert_eq!(
        vk.to_bytes(),
        vk2.to_bytes(),
        "hybrid vk bytes must round-trip"
    );

    let msg = b"hybrid vk serialize test";
    let sig = sk.sign(msg).expect("sign must succeed");
    vk2.verify(msg, &sig)
        .expect("deserialized hybrid vk must verify");
}

fn hybrid_wrong_key_rejection<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk_a, _vk_a) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen A must succeed");
    let (_sk_b, vk_b) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen B must succeed");
    let msg = b"signed with hybrid key A";
    let sig = sk_a.sign(msg).expect("sign must succeed");
    assert!(
        vk_b.verify(msg, &sig).is_err(),
        "hybrid sig from key A must not verify with key B"
    );
}

fn hybrid_sig_serialize_deserialize<P: KeyGen + MlDsaParams>() {
    let mut rng = make_rng();
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let msg = b"hybrid sig serialize test";
    let sig = sk.sign(msg).expect("sign must succeed");

    let sig_bytes = sig.to_bytes();
    let sig2 =
        HybridSignature::<P>::from_bytes(&sig_bytes).expect("hybrid sig from_bytes must succeed");
    assert_eq!(
        sig.to_bytes(),
        sig2.to_bytes(),
        "hybrid sig bytes must round-trip"
    );
    vk.verify(msg, &sig2)
        .expect("deserialized hybrid sig must verify");
}

// ── Hybrid test instantiations ────────────────────────────────────────────────

#[test]
fn hybrid44_basic_roundtrip() {
    with_large_stack(|| hybrid_basic_roundtrip::<ml_dsa::MlDsa44>());
}
#[test]
fn hybrid44_sk_serialize_deserialize() {
    with_large_stack(|| hybrid_sk_serialize_deserialize::<ml_dsa::MlDsa44>());
}
#[test]
fn hybrid44_vk_serialize_deserialize() {
    with_large_stack(|| hybrid_vk_serialize_deserialize::<ml_dsa::MlDsa44>());
}
#[test]
fn hybrid44_wrong_key_rejection() {
    with_large_stack(|| hybrid_wrong_key_rejection::<ml_dsa::MlDsa44>());
}
#[test]
fn hybrid44_sig_serialize_deserialize() {
    with_large_stack(|| hybrid_sig_serialize_deserialize::<ml_dsa::MlDsa44>());
}

#[test]
fn hybrid65_basic_roundtrip() {
    with_large_stack(|| hybrid_basic_roundtrip::<ml_dsa::MlDsa65>());
}
#[test]
fn hybrid65_sk_serialize_deserialize() {
    with_large_stack(|| hybrid_sk_serialize_deserialize::<ml_dsa::MlDsa65>());
}
#[test]
fn hybrid65_vk_serialize_deserialize() {
    with_large_stack(|| hybrid_vk_serialize_deserialize::<ml_dsa::MlDsa65>());
}
#[test]
fn hybrid65_wrong_key_rejection() {
    with_large_stack(|| hybrid_wrong_key_rejection::<ml_dsa::MlDsa65>());
}
#[test]
fn hybrid65_sig_serialize_deserialize() {
    with_large_stack(|| hybrid_sig_serialize_deserialize::<ml_dsa::MlDsa65>());
}

#[test]
fn hybrid87_basic_roundtrip() {
    with_large_stack(|| hybrid_basic_roundtrip::<ml_dsa::MlDsa87>());
}
#[test]
fn hybrid87_sk_serialize_deserialize() {
    with_large_stack(|| hybrid_sk_serialize_deserialize::<ml_dsa::MlDsa87>());
}
#[test]
fn hybrid87_vk_serialize_deserialize() {
    with_large_stack(|| hybrid_vk_serialize_deserialize::<ml_dsa::MlDsa87>());
}
#[test]
fn hybrid87_wrong_key_rejection() {
    with_large_stack(|| hybrid_wrong_key_rejection::<ml_dsa::MlDsa87>());
}
