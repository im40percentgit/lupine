//! `lupine decapsulate` — decapsulate a shared secret using a KEM secret key.
//!
//! Reads a secret key file and ciphertext, then produces the shared secret.
//! For hybrid KEM keys in PEM/DER format the ML-KEM public key is embedded in
//! the secret key file and recovered automatically. In raw format the caller
//! must supply `--pub-key` so the KitchenSink combiner has the pk bytes it needs.
//!
//! @decision DEC-CLI-007
//! @title --pub-key required for hybrid KEM raw-format decapsulation
//! @status accepted
//! @rationale The KitchenSink combiner (HKDF-SHA-256 over all inputs) requires
//!   the static ML-KEM public key bytes as input. In PEM/DER format these are
//!   embedded in the composite secret key encoding. In raw format the secret key
//!   is stored as x25519_sk||x25519_pk||mlkem_sk with no room for the mlkem_pk,
//!   so the caller must provide the public key file via --pub-key. This is
//!   consistent with how other tools (e.g. age) require the recipient's public
//!   key to be passed explicitly when it cannot be derived from the secret key.

use anyhow::{bail, Result};

use crate::args::DecapsulateArgs;
use crate::format;

/// Run the decapsulate subcommand.
pub fn run(args: &DecapsulateArgs) -> Result<()> {
    let fmt = args.format;

    // Read secret key; may return embedded pk bytes for hybrid KEM DER/PEM.
    let (sk_bytes, alg, embedded_pk) =
        format::read_secret_key(&args.sec_key, fmt, args.algorithm)?;

    if !alg.is_kem() {
        bail!("algorithm {alg} is not a KEM algorithm");
    }

    let ct_bytes = format::read_ciphertext(&args.ciphertext)?;

    if alg.is_pure_kem() {
        decapsulate_mlkem(alg, &sk_bytes, &ct_bytes, args)
    } else {
        // Hybrid KEM: need mlkem pk bytes for the KitchenSink combiner.
        let mlkem_pk_bytes = match embedded_pk {
            Some(pk) => pk,
            None => {
                // Raw format: --pub-key must be provided.
                let pub_key_path = args.pub_key.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "hybrid KEM decapsulation in raw format requires --pub-key \
                         (the ML-KEM public key bytes are not stored in the raw secret key file)"
                    )
                })?;
                let (pk_bytes, _pk_alg) =
                    format::read_public_key(pub_key_path, fmt, Some(alg))?;
                // pk_bytes = x25519_pk(32) || mlkem_pk; extract just mlkem_pk
                let pk_size = alg.hybrid_kem_pk_size().unwrap();
                if pk_bytes.len() != pk_size {
                    bail!(
                        "public key has wrong size: expected {pk_size} bytes, got {}",
                        pk_bytes.len()
                    );
                }
                pk_bytes
            }
        };
        decapsulate_hybrid_kem(alg, &sk_bytes, &mlkem_pk_bytes, &ct_bytes, args)
    }
}

fn decapsulate_mlkem(
    alg: crate::algorithm::CliAlgorithm,
    sk_bytes: &[u8],
    ct_bytes: &[u8],
    args: &DecapsulateArgs,
) -> Result<()> {
    use lupine_kem::{MlKemCiphertext, MlKemSecretKey};

    macro_rules! do_mlkem_decapsulate {
        ($P:ty, $alg:expr, $sk_bytes:expr, $ct_bytes:expr, $args:expr) => {{
            let sk = MlKemSecretKey::<$P>::from_bytes($sk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let ct = MlKemCiphertext::<$P>::from_bytes($ct_bytes);
            let ss = sk.decapsulate(&ct)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            format::write_shared_secret($args.out_ss.as_deref(), ss.as_bytes())?;
            Ok(())
        }};
    }

    crate::dispatch_mlkem!(alg, do_mlkem_decapsulate!(alg, sk_bytes, ct_bytes, args))
}

fn decapsulate_hybrid_kem(
    alg: crate::algorithm::CliAlgorithm,
    sk_bytes: &[u8],
    // full hybrid pk bytes: x25519_pk(32) || mlkem_pk
    full_pk_bytes: &[u8],
    ct_bytes: &[u8],
    args: &DecapsulateArgs,
) -> Result<()> {
    use lupine_kem::{HybridKemCiphertext, HybridKemSecretKey};

    macro_rules! do_hybrid_kem_decapsulate {
        ($P:ty, $alg:expr, $sk_bytes:expr, $full_pk:expr, $ct_bytes:expr, $args:expr) => {{
            let mut sk = HybridKemSecretKey::<$P>::from_bytes($sk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            // Provide mlkem_pk bytes (bytes 32.. of the full hybrid pk).
            if $full_pk.len() < 32 {
                anyhow::bail!("hybrid pk too short");
            }
            let mlkem_pk = $full_pk[32..].to_vec();
            sk.set_mlkem_pk_bytes(mlkem_pk);
            let ct = HybridKemCiphertext::<$P>::from_bytes($ct_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let ss = sk.decapsulate(&ct)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            format::write_shared_secret($args.out_ss.as_deref(), ss.as_bytes())?;
            Ok(())
        }};
    }

    crate::dispatch_hybrid_kem!(
        alg,
        do_hybrid_kem_decapsulate!(alg, sk_bytes, full_pk_bytes, ct_bytes, args)
    )
}
