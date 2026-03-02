//! `lupine encapsulate` — encapsulate a shared secret to a KEM public key.
//!
//! Reads a public key file, auto-detects the algorithm from PEM/DER if not
//! specified, encapsulates a fresh shared secret, and writes the ciphertext
//! and shared secret to files or stdout.
//!
//! @decision DEC-CLI-006
//! @title Ciphertext always written as raw bytes regardless of --format
//! @status accepted
//! @rationale Ciphertexts are opaque byte blobs that the decapsulate command
//!   reads back verbatim. There is no standard DER/PEM framing for KEM
//!   ciphertexts, and adding one would require the decapsulate command to also
//!   understand it. Raw bytes are the simplest, most portable representation
//!   for a value that is only ever passed between encapsulate and decapsulate
//!   within the same tool. The --format flag controls key serialization only.

use anyhow::{bail, Result};

use crate::args::EncapsulateArgs;
use crate::format;

/// Run the encapsulate subcommand.
pub fn run(args: &EncapsulateArgs) -> Result<()> {
    let fmt = args.format;

    // Read public key; algorithm auto-detected from PEM/DER or from --algorithm hint.
    let (pk_bytes, alg) = format::read_public_key(&args.pub_key, fmt, args.algorithm)?;

    if !alg.is_kem() {
        bail!("algorithm {alg} is not a KEM algorithm; use 'sign' for signature operations");
    }

    if alg.is_pure_kem() {
        encapsulate_mlkem(alg, &pk_bytes, args)
    } else {
        encapsulate_hybrid_kem(alg, &pk_bytes, args)
    }
}

fn encapsulate_mlkem(
    alg: crate::algorithm::CliAlgorithm,
    pk_bytes: &[u8],
    args: &EncapsulateArgs,
) -> Result<()> {
    use lupine_kem::MlKemPublicKey;
    use rand::rngs::OsRng;

    macro_rules! do_mlkem_encapsulate {
        ($P:ty, $alg:expr, $pk_bytes:expr, $args:expr) => {{
            let pk = MlKemPublicKey::<$P>::from_bytes($pk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let mut rng = OsRng;
            let (ct, ss) = pk.encapsulate(&mut rng)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let ct_bytes = ct.to_bytes().to_vec();

            if let Some(p) = $args.out_ct.as_deref() {
                format::write_ciphertext(p, &ct_bytes)?;
                eprintln!("Ciphertext written to {p}");
            } else {
                eprintln!("Ciphertext (hex): {}", hex::encode(&ct_bytes));
            }
            format::write_shared_secret($args.out_ss.as_deref(), ss.as_bytes())?;
            if $args.out_ss.is_some() {
                eprintln!("Shared secret written to {}", $args.out_ss.as_deref().unwrap());
            }
            Ok(())
        }};
    }

    crate::dispatch_mlkem!(alg, do_mlkem_encapsulate!(alg, pk_bytes, args))
}

fn encapsulate_hybrid_kem(
    alg: crate::algorithm::CliAlgorithm,
    pk_bytes: &[u8],
    args: &EncapsulateArgs,
) -> Result<()> {
    use lupine_kem::HybridKemPublicKey;
    use rand::rngs::OsRng;

    macro_rules! do_hybrid_kem_encapsulate {
        ($P:ty, $alg:expr, $pk_bytes:expr, $args:expr) => {{
            let pk = HybridKemPublicKey::<$P>::from_bytes($pk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let mut rng = OsRng;
            let (ct, ss) = pk.encapsulate(&mut rng)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let ct_bytes = ct.to_bytes();

            if let Some(p) = $args.out_ct.as_deref() {
                format::write_ciphertext(p, &ct_bytes)?;
                eprintln!("Ciphertext written to {p}");
            } else {
                eprintln!("Ciphertext (hex): {}", hex::encode(&ct_bytes));
            }
            format::write_shared_secret($args.out_ss.as_deref(), ss.as_bytes())?;
            if $args.out_ss.is_some() {
                eprintln!("Shared secret written to {}", $args.out_ss.as_deref().unwrap());
            }
            Ok(())
        }};
    }

    crate::dispatch_hybrid_kem!(alg, do_hybrid_kem_encapsulate!(alg, pk_bytes, args))
}
