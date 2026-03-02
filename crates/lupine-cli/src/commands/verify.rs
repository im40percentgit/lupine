//! `lupine verify` — verify a signature over a message.
//!
//! Reads a public key file and signature file, reads the message from a file
//! or stdin, verifies the signature, and exits 0 on success or 1 on failure.
//! Status messages go to stderr so stdout can be used in pipelines.
//!
//! @decision DEC-CLI-009
//! @title Exit code 1 (not panic) on verification failure
//! @status accepted
//! @rationale Verification failure is an expected outcome in a verify command,
//!   not an internal error. Using `std::process::exit(1)` instead of `bail!`
//!   gives a clean exit without a Rust error backtrace, matching the behavior
//!   of tools like `gpg --verify`, `signify -V`, and `minisign -V`. The error
//!   message goes to stderr for scripting. Exit code 0 = valid, 1 = invalid,
//!   any other non-zero = internal error (propagated via anyhow).

use anyhow::{bail, Result};

use crate::args::VerifyArgs;
use crate::format;

/// Run the verify subcommand.
pub fn run(args: &VerifyArgs) -> Result<()> {
    let fmt = args.format;

    let (pk_bytes, alg) = format::read_public_key(&args.pub_key, fmt, args.algorithm)?;

    if !alg.is_sign() {
        bail!("algorithm {alg} is not a signature algorithm");
    }

    let (sig_bytes, _sig_alg) = format::read_signature(&args.signature, fmt, Some(alg))?;
    let message = format::read_message(args.message.as_deref())?;

    let verified = if alg.is_mldsa() {
        verify_mldsa(alg, &pk_bytes, &sig_bytes, &message)
    } else if alg.is_hybrid_sign() {
        verify_hybrid(alg, &pk_bytes, &sig_bytes, &message)
    } else {
        verify_slhdsa(alg, &pk_bytes, &sig_bytes, &message)
    };

    match verified {
        Ok(()) => {
            eprintln!("Signature verified.");
            Ok(())
        }
        Err(_) => {
            eprintln!("Verification FAILED.");
            std::process::exit(1);
        }
    }
}

fn verify_mldsa(
    alg: crate::algorithm::CliAlgorithm,
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<()> {
    use lupine_sign::{MlDsaSignature, MlDsaVerifyingKey};

    macro_rules! do_mldsa_verify {
        ($P:ty, $alg:expr, $pk_bytes:expr, $sig_bytes:expr, $message:expr) => {{
            let vk = MlDsaVerifyingKey::<$P>::from_bytes($pk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig = MlDsaSignature::<$P>::from_bytes($sig_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            vk.verify($message, &sig)
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        }};
    }

    crate::dispatch_mldsa!(alg, do_mldsa_verify!(alg, pk_bytes, sig_bytes, message))
}

fn verify_hybrid(
    alg: crate::algorithm::CliAlgorithm,
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<()> {
    use lupine_sign::{HybridSignature, HybridVerifyingKey};

    macro_rules! do_hybrid_verify {
        ($P:ty, $alg:expr, $pk_bytes:expr, $sig_bytes:expr, $message:expr) => {{
            let vk = HybridVerifyingKey::<$P>::from_bytes($pk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig = HybridSignature::<$P>::from_bytes($sig_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            vk.verify($message, &sig)
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        }};
    }

    crate::dispatch_hybrid_sign!(alg, do_hybrid_verify!(alg, pk_bytes, sig_bytes, message))
}

fn verify_slhdsa(
    alg: crate::algorithm::CliAlgorithm,
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<()> {
    use lupine_sign::{SlhDsaSignature, SlhDsaVerifyingKey};

    macro_rules! do_slhdsa_verify {
        ($P:ty, $alg:expr, $pk_bytes:expr, $sig_bytes:expr, $message:expr) => {{
            let vk = SlhDsaVerifyingKey::<$P>::from_bytes($pk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig = SlhDsaSignature::<$P>::from_bytes($sig_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            vk.verify($message, &sig)
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        }};
    }

    crate::dispatch_slhdsa!(alg, do_slhdsa_verify!(alg, pk_bytes, sig_bytes, message))
}
