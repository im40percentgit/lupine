//! canus-lupus — Post-quantum Swiss Army Knife CLI.
//!
//! User-friendly command-line interface built on the `lupine::easy` high-level
//! API (Layer 1). Provides key generation, file encryption/decryption, and
//! digital signature operations without requiring knowledge of PQC algorithm
//! internals.
//!
//! # Subcommands
//!
//! ```text
//! canus-lupus keygen                      # generate default keypair
//! canus-lupus keygen --name alice         # generate named keypair
//! canus-lupus encrypt <file>              # encrypt for self
//! canus-lupus encrypt <file> -r alice     # encrypt for named recipient
//! canus-lupus decrypt <file.enc>          # decrypt with own key
//! canus-lupus sign <file>                 # sign a file → <file>.sig
//! canus-lupus verify <file>               # verify signature
//! canus-lupus keys list                   # list all known keys
//! canus-lupus keys import <file.pub>      # import a public key bundle
//! canus-lupus keys export --public        # print own public key bundle
//! canus-lupus vault init                  # initialize vault
//! canus-lupus vault set api/openai "sk-..." # store a secret
//! canus-lupus vault get api/openai        # retrieve a secret
//! canus-lupus vault list                  # list stored paths
//! canus-lupus vault rm api/openai         # remove a secret
//! ```
//!
//! # Stack size
//!
//! ML-DSA-65 operations require a large stack in debug builds (the FIPS 204
//! reference implementation uses large on-stack arrays). All work is dispatched
//! to a dedicated 32 MiB thread, matching the pattern used in `lupine-cli`.
//!
//! @decision DEC-CLI-020
//! @title Large-stack thread for ML-DSA compatibility
//! @status accepted
//! @rationale ML-DSA-65 signing allocates ~16 MB of stack in debug builds via
//!   the RustCrypto ml-dsa crate. Spawning a single 32 MB worker thread at
//!   startup avoids stack overflows on all supported parameter sets without
//!   requiring linker flags or upstream changes. This pattern is already
//!   established in lupine-cli (DEC-CLI-010) and is safe to replicate here.

mod commands;
mod keystore;
mod vault;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = commands::Cli::parse();

    // Dispatch all work to a large-stack thread to accommodate ML-DSA-65
    // stack requirements in debug builds.
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MiB
        .name("canus-lupus-main".into())
        .spawn(move || commands::run(cli))
        .expect("failed to spawn canus-lupus-main thread")
        .join()
        .expect("canus-lupus-main thread panicked")
}
