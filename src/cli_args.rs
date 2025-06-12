use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "Sign or verify firmware blobs using Ed25519", author, version)]
pub struct Props { // Make Props public
    /// Path to firmware binary
    #[clap(short = 'f', long)]
    pub path: Option<PathBuf>,

    /// Path to signing key (private key)
    #[clap(short = 's', long)]
    pub signing_key: Option<PathBuf>,

    /// Path to public key for verification
    #[clap(short = 'p', long)]
    pub public_key: Option<PathBuf>,

    /// Path to store the generated signature
    #[clap(short = 'o', long)]
    pub signature: Option<PathBuf>,

    /// Sign the firmware binary
    #[clap(long)]
    pub sign: bool,

    /// Verify the firmware signature
    #[clap(long)]
    pub verify: bool,

    /// Generate a new password-protected key pair
    #[clap(long)]
    pub generate_keys: bool, // Add a specific flag for key generation

    #[cfg(test)]
    #[clap(subcommand)]
    pub command: Option<TestCommand>,
}

#[cfg(test)]
#[derive(Subcommand, Debug)]
pub enum TestCommand { // Make TestCommand public
    Test {
        #[clap(long)]
        t: String,
    },
}