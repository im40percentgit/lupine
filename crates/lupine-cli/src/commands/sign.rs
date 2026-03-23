//! `lupine sign` — sign a message using a signing secret key.
//!
//! Reads a secret key file, reads the message from a file or stdin, produces
//! a signature, and writes it to a file or stdout.
//!
//! @decision DEC-CLI-008
//! @title Stdin as default message source for sign and verify
//! @status accepted
//! @rationale Allowing the message to be piped via stdin enables the common
//!   Unix pattern `echo "data" | lupine sign --sec-key key.sec` and integrates
//!   naturally with shell pipelines. When --message is provided it takes
//!   precedence. This matches the convention used by gpg, signify, and minisign.

use anyhow::{bail, Result};

use crate::args::SignArgs;
use crate::format;

/// Run the sign subcommand.
pub fn run(args: &SignArgs) -> Result<()> {
    let fmt = args.format;

    let (sk_bytes, alg, _) = format::read_secret_key(&args.sec_key, fmt, args.algorithm)?;

    if !alg.is_sign() {
        bail!("algorithm {alg} is not a signature algorithm; use 'encapsulate' for KEM operations");
    }

    let message = format::read_message(args.message.as_deref())?;

    if alg.is_mldsa() {
        sign_mldsa(alg, &sk_bytes, &message, args)
    } else if alg.is_hybrid_sign() {
        sign_hybrid(alg, &sk_bytes, &message, args)
    } else {
        sign_slhdsa(alg, &sk_bytes, &message, args)
    }
}

fn sign_mldsa(
    alg: crate::algorithm::CliAlgorithm,
    sk_bytes: &[u8],
    message: &[u8],
    args: &SignArgs,
) -> Result<()> {
    use lupine_sign::MlDsaSigningKey;

    macro_rules! do_mldsa_sign {
        ($P:ty, $alg:expr, $sk_bytes:expr, $message:expr, $args:expr) => {{
            let sk = MlDsaSigningKey::<$P>::from_bytes($sk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig = sk.sign($message).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig_bytes = sig.to_bytes().to_vec();
            if let Some(p) = $args.out_sig.as_deref() {
                format::write_signature(p, &sig_bytes, $alg, $args.format)?;
                eprintln!("Signature written to {p}");
            } else {
                // Write to stdout as hex.
                println!("{}", hex::encode(&sig_bytes));
            }
            Ok(())
        }};
    }

    crate::dispatch_mldsa!(alg, do_mldsa_sign!(alg, sk_bytes, message, args))
}

fn sign_hybrid(
    alg: crate::algorithm::CliAlgorithm,
    sk_bytes: &[u8],
    message: &[u8],
    args: &SignArgs,
) -> Result<()> {
    use lupine_sign::HybridSigningKey;

    macro_rules! do_hybrid_sign {
        ($P:ty, $alg:expr, $sk_bytes:expr, $message:expr, $args:expr) => {{
            let sk = HybridSigningKey::<$P>::from_bytes($sk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig = sk.sign($message).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig_bytes = sig.to_bytes();
            if let Some(p) = $args.out_sig.as_deref() {
                format::write_signature(p, &sig_bytes, $alg, $args.format)?;
                eprintln!("Signature written to {p}");
            } else {
                println!("{}", hex::encode(&sig_bytes));
            }
            Ok(())
        }};
    }

    crate::dispatch_hybrid_sign!(alg, do_hybrid_sign!(alg, sk_bytes, message, args))
}

fn sign_slhdsa(
    alg: crate::algorithm::CliAlgorithm,
    sk_bytes: &[u8],
    message: &[u8],
    args: &SignArgs,
) -> Result<()> {
    use lupine_sign::SlhDsaSigningKey;

    macro_rules! do_slhdsa_sign {
        ($P:ty, $alg:expr, $sk_bytes:expr, $message:expr, $args:expr) => {{
            let sk = SlhDsaSigningKey::<$P>::from_bytes($sk_bytes)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig = sk.sign($message).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let sig_bytes = sig.to_bytes();
            if let Some(p) = $args.out_sig.as_deref() {
                format::write_signature(p, &sig_bytes, $alg, $args.format)?;
                eprintln!("Signature written to {p}");
            } else {
                println!("{}", hex::encode(&sig_bytes));
            }
            Ok(())
        }};
    }

    crate::dispatch_slhdsa!(alg, do_slhdsa_sign!(alg, sk_bytes, message, args))
}
