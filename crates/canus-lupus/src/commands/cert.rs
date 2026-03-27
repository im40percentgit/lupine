//! `canus-lupus cert` — X.509v3 certificate operations.
//!
//! Provides three subcommands:
//! - `cert generate` — Generate a self-signed or CA-signed certificate.
//! - `cert inspect`  — Display certificate fields from a PEM file.
//! - `cert verify-chain` — Validate a PEM certificate chain (leaf first, root last).
//!
//! # Algorithms
//!
//! Supported via `--algo`:
//! - `mldsa44`, `mldsa65` (default), `mldsa87`
//! - `hybrid-mldsa44`, `hybrid-mldsa65`, `hybrid-mldsa87`
//!
//! @decision DEC-CLI-030
//! @title cert generate outputs PEM to stdout when --out is omitted
//! @status accepted
//! @rationale Shell pipelines expect PEM on stdout. Requiring a file path would
//!   break `canus-lupus cert generate | openssl x509 -text -noout`. Defaulting
//!   to stdout is consistent with how OpenSSL and similar tools behave.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use lupine_cert::{
    generate::{CertAlgorithm, CertBuilder, GeneratedCert},
    parse::Certificate,
    validate::{verify_chain, verify_self_signed},
};

// ── Clap types ────────────────────────────────────────────────────────────────

/// Arguments for the `cert` subcommand group.
#[derive(Debug, Args)]
pub struct CertArgs {
    #[command(subcommand)]
    pub command: CertCommand,
}

#[derive(Debug, Subcommand)]
pub enum CertCommand {
    /// Generate a certificate (self-signed or CA-signed).
    Generate(GenerateArgs),
    /// Inspect a PEM certificate and print its fields.
    Inspect(InspectArgs),
    /// Verify a certificate chain (leaf first, root last).
    VerifyChain(VerifyChainArgs),
}

/// Arguments for `cert generate`.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Subject common name (required).
    #[arg(long)]
    pub subject: String,

    /// Generate a self-signed certificate.
    #[arg(long, conflicts_with_all = ["ca_cert", "ca_key"])]
    pub self_signed: bool,

    /// Path to the CA certificate PEM file (for CA-signed certs).
    #[arg(long, requires = "ca_key", conflicts_with = "self_signed")]
    pub ca_cert: Option<PathBuf>,

    /// Path to the CA signing key file (raw bytes).
    #[arg(long, requires = "ca_cert", conflicts_with = "self_signed")]
    pub ca_key: Option<PathBuf>,

    /// Signing algorithm.
    ///
    /// Accepted values: mldsa44, mldsa65, mldsa87,
    /// hybrid-mldsa44, hybrid-mldsa65, hybrid-mldsa87.
    #[arg(long, default_value = "mldsa65")]
    pub algo: String,

    /// Mark the certificate as a CA (adds BasicConstraints CA:TRUE).
    #[arg(long)]
    pub ca: bool,

    /// Validity period in days (default: 365).
    #[arg(long, default_value = "365")]
    pub days: u32,

    /// Write the certificate PEM to this file (default: stdout).
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Write the signing key bytes to this file (useful for CA certs).
    #[arg(long)]
    pub key_out: Option<PathBuf>,
}

/// Arguments for `cert inspect`.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Path to the PEM certificate file.
    pub cert_path: PathBuf,
}

/// Arguments for `cert verify-chain`.
#[derive(Debug, Args)]
pub struct VerifyChainArgs {
    /// Paths to PEM certificates: leaf first, root last.
    #[arg(required = true)]
    pub cert_paths: Vec<PathBuf>,
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub fn run(args: &CertArgs) -> anyhow::Result<()> {
    match &args.command {
        CertCommand::Generate(a) => run_generate(a),
        CertCommand::Inspect(a) => run_inspect(a),
        CertCommand::VerifyChain(a) => run_verify_chain(a),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

fn run_generate(args: &GenerateArgs) -> anyhow::Result<()> {
    let algo = parse_cert_algo(&args.algo)?;

    let builder = CertBuilder::new()
        .subject(&args.subject)
        .ca(args.ca)
        .validity_days(args.days);

    let generated: GeneratedCert = if args.self_signed {
        builder.self_signed(algo)?
    } else if let (Some(ca_cert_path), Some(ca_key_path)) = (&args.ca_cert, &args.ca_key) {
        // Load the CA cert + key and construct a GeneratedCert to pass to signed_by.
        let ca_pem = std::fs::read_to_string(ca_cert_path).map_err(|e| {
            anyhow::anyhow!("failed to read CA cert '{}': {e}", ca_cert_path.display())
        })?;
        let ca_parsed = Certificate::from_pem(&ca_pem)
            .map_err(|e| anyhow::anyhow!("failed to parse CA cert: {e}"))?;
        let signing_key_bytes = std::fs::read(ca_key_path).map_err(|e| {
            anyhow::anyhow!("failed to read CA key '{}': {e}", ca_key_path.display())
        })?;

        // Reconstruct the GeneratedCert the CA was born with, so signed_by can
        // read its signing_key_bytes and der_bytes fields.
        let ca_gen = GeneratedCert {
            der_bytes: ca_parsed.der_bytes().to_vec(),
            pem: ca_parsed.to_pem(),
            signing_key_bytes,
            verifying_key_bytes: ca_parsed.public_key_bytes().to_vec(),
            algorithm: algo,
        };

        builder.signed_by(&ca_gen, algo)?
    } else {
        anyhow::bail!("either --self-signed or --ca-cert + --ca-key must be provided");
    };

    // Write certificate PEM.
    match &args.out {
        Some(path) => {
            std::fs::write(path, generated.pem.as_bytes()).map_err(|e| {
                anyhow::anyhow!("failed to write cert to '{}': {e}", path.display())
            })?;
            eprintln!("Certificate written to {}", path.display());
        }
        None => {
            print!("{}", generated.pem);
        }
    }

    // Write signing key if requested.
    if let Some(key_path) = &args.key_out {
        std::fs::write(key_path, &generated.signing_key_bytes)
            .map_err(|e| anyhow::anyhow!("failed to write key to '{}': {e}", key_path.display()))?;
        eprintln!("Signing key written to {}", key_path.display());
    }

    Ok(())
}

fn run_inspect(args: &InspectArgs) -> anyhow::Result<()> {
    let pem_str = std::fs::read_to_string(&args.cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {e}", args.cert_path.display()))?;
    let cert = Certificate::from_pem(&pem_str)
        .map_err(|e| anyhow::anyhow!("failed to parse certificate: {e}"))?;

    println!("Subject:   {}", cert.subject_cn().unwrap_or("<unknown>"));
    println!("Issuer:    {}", cert.issuer_cn().unwrap_or("<unknown>"));
    println!("Algorithm: {}", oid_display(cert.signature_algorithm_oid()));
    println!("PublicKey: {} bytes", cert.public_key_bytes().len());
    println!("Signature: {} bytes", cert.signature_bytes().len());

    Ok(())
}

fn run_verify_chain(args: &VerifyChainArgs) -> anyhow::Result<()> {
    if args.cert_paths.is_empty() {
        anyhow::bail!("at least one certificate path is required");
    }

    let mut certs = Vec::with_capacity(args.cert_paths.len());
    for path in &args.cert_paths {
        let pem_str = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read '{}': {e}", path.display()))?;
        let cert = Certificate::from_pem(&pem_str)
            .map_err(|e| anyhow::anyhow!("failed to parse '{}': {e}", path.display()))?;
        certs.push(cert);
    }

    if certs.len() == 1 {
        verify_self_signed(&certs[0])
            .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))?;
    } else {
        verify_chain(&certs).map_err(|e| anyhow::anyhow!("chain verification failed: {e}"))?;
    }

    println!("OK — certificate chain verified ({} cert(s))", certs.len());
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a user-supplied algorithm string into a [`CertAlgorithm`].
fn parse_cert_algo(s: &str) -> anyhow::Result<CertAlgorithm> {
    match s {
        "mldsa44" => Ok(CertAlgorithm::MlDsa44),
        "mldsa65" => Ok(CertAlgorithm::MlDsa65),
        "mldsa87" => Ok(CertAlgorithm::MlDsa87),
        "hybrid-mldsa44" => Ok(CertAlgorithm::HybridEd25519MlDsa44),
        "hybrid-mldsa65" => Ok(CertAlgorithm::HybridEd25519MlDsa65),
        "hybrid-mldsa87" => Ok(CertAlgorithm::HybridEd25519MlDsa87),
        other => anyhow::bail!(
            "unknown algorithm '{}'; expected one of: \
             mldsa44, mldsa65, mldsa87, hybrid-mldsa44, hybrid-mldsa65, hybrid-mldsa87",
            other
        ),
    }
}

/// Return a human-readable name for well-known PQC OIDs.
fn oid_display(oid: &der::asn1::ObjectIdentifier) -> &'static str {
    use lupine_serial::oid::*;
    if *oid == OID_ML_DSA_44 {
        "ML-DSA-44 (FIPS 204)"
    } else if *oid == OID_ML_DSA_65 {
        "ML-DSA-65 (FIPS 204)"
    } else if *oid == OID_ML_DSA_87 {
        "ML-DSA-87 (FIPS 204)"
    } else if *oid == OID_HYBRID_SIGN_44 {
        "Hybrid Ed25519+ML-DSA-44"
    } else if *oid == OID_HYBRID_SIGN_65 {
        "Hybrid Ed25519+ML-DSA-65"
    } else if *oid == OID_HYBRID_SIGN_87 {
        "Hybrid Ed25519+ML-DSA-87"
    } else {
        "unknown"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Run a closure on a thread with a 32 MiB stack (ML-DSA needs it in debug).
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn generate_self_signed_writes_pem_file() {
        with_large_stack(|| {
            let dir = tempdir().unwrap();
            let cert_path = dir.path().join("test.pem");
            let key_path = dir.path().join("test.key");

            let args = GenerateArgs {
                subject: "CN=test-self".to_string(),
                self_signed: true,
                ca_cert: None,
                ca_key: None,
                algo: "mldsa65".to_string(),
                ca: false,
                days: 365,
                out: Some(cert_path.clone()),
                key_out: Some(key_path.clone()),
            };

            run_generate(&args).unwrap();

            // Cert file must exist and contain PEM
            assert!(cert_path.exists(), "cert file not found");
            let pem = std::fs::read_to_string(&cert_path).unwrap();
            assert!(
                pem.starts_with("-----BEGIN CERTIFICATE-----"),
                "not a PEM cert"
            );
            assert!(pem.contains("-----END CERTIFICATE-----"));

            // Key file must exist and be non-empty
            assert!(key_path.exists(), "key file not found");
            let key_bytes = std::fs::read(&key_path).unwrap();
            assert!(!key_bytes.is_empty(), "key file is empty");
        });
    }

    #[test]
    fn generate_ca_signed_cert() {
        with_large_stack(|| {
            let dir = tempdir().unwrap();
            let ca_cert_path = dir.path().join("ca.pem");
            let ca_key_path = dir.path().join("ca.key");
            let leaf_cert_path = dir.path().join("leaf.pem");

            // First generate the CA cert + key.
            let ca_args = GenerateArgs {
                subject: "CN=Test CA".to_string(),
                self_signed: true,
                ca_cert: None,
                ca_key: None,
                algo: "mldsa65".to_string(),
                ca: true,
                days: 365,
                out: Some(ca_cert_path.clone()),
                key_out: Some(ca_key_path.clone()),
            };
            run_generate(&ca_args).unwrap();

            // Now generate a leaf cert signed by the CA.
            let leaf_args = GenerateArgs {
                subject: "CN=leaf".to_string(),
                self_signed: false,
                ca_cert: Some(ca_cert_path),
                ca_key: Some(ca_key_path),
                algo: "mldsa65".to_string(),
                ca: false,
                days: 90,
                out: Some(leaf_cert_path.clone()),
                key_out: None,
            };
            run_generate(&leaf_args).unwrap();

            assert!(leaf_cert_path.exists(), "leaf cert not found");
            let pem = std::fs::read_to_string(&leaf_cert_path).unwrap();
            assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        });
    }

    #[test]
    fn inspect_self_signed_cert() {
        with_large_stack(|| {
            let dir = tempdir().unwrap();
            let cert_path = dir.path().join("inspect.pem");

            let gen_args = GenerateArgs {
                subject: "CN=inspect-me".to_string(),
                self_signed: true,
                ca_cert: None,
                ca_key: None,
                algo: "mldsa44".to_string(),
                ca: false,
                days: 365,
                out: Some(cert_path.clone()),
                key_out: None,
            };
            run_generate(&gen_args).unwrap();

            let inspect_args = InspectArgs {
                cert_path: cert_path.clone(),
            };
            // Should not panic or error.
            run_inspect(&inspect_args).unwrap();
        });
    }

    #[test]
    fn verify_chain_self_signed() {
        with_large_stack(|| {
            let dir = tempdir().unwrap();
            let cert_path = dir.path().join("root.pem");

            let gen_args = GenerateArgs {
                subject: "CN=self-root".to_string(),
                self_signed: true,
                ca_cert: None,
                ca_key: None,
                algo: "mldsa65".to_string(),
                ca: true,
                days: 365,
                out: Some(cert_path.clone()),
                key_out: None,
            };
            run_generate(&gen_args).unwrap();

            let verify_args = VerifyChainArgs {
                cert_paths: vec![cert_path],
            };
            run_verify_chain(&verify_args).unwrap();
        });
    }

    #[test]
    fn verify_chain_two_certs() {
        with_large_stack(|| {
            let dir = tempdir().unwrap();
            let ca_cert_path = dir.path().join("ca.pem");
            let ca_key_path = dir.path().join("ca.key");
            let leaf_cert_path = dir.path().join("leaf.pem");

            run_generate(&GenerateArgs {
                subject: "CN=Chain CA".to_string(),
                self_signed: true,
                ca_cert: None,
                ca_key: None,
                algo: "mldsa65".to_string(),
                ca: true,
                days: 365,
                out: Some(ca_cert_path.clone()),
                key_out: Some(ca_key_path.clone()),
            })
            .unwrap();

            run_generate(&GenerateArgs {
                subject: "CN=chain-leaf".to_string(),
                self_signed: false,
                ca_cert: Some(ca_cert_path.clone()),
                ca_key: Some(ca_key_path),
                algo: "mldsa65".to_string(),
                ca: false,
                days: 90,
                out: Some(leaf_cert_path.clone()),
                key_out: None,
            })
            .unwrap();

            let verify_args = VerifyChainArgs {
                cert_paths: vec![leaf_cert_path, ca_cert_path],
            };
            run_verify_chain(&verify_args).unwrap();
        });
    }

    #[test]
    fn unknown_algo_returns_error() {
        assert!(parse_cert_algo("bogus").is_err());
    }
}
