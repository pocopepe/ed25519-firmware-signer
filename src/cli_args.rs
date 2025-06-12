use clap::Parser;
use std::path::PathBuf;

#[cfg(test)] // Apply this cfg to the use statement as well
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(about = "Sign or verify firmware blobs using Ed25519", author, version)]
pub struct Props {
    /// Path to firmware binary or Intel HEX file to sign or verify.
    #[clap(short = 'f', long)]
    pub path: Option<PathBuf>,

    /// Path to the private key file for signing (password-encrypted).
    #[clap(short = 's', long)]
    pub signing_key: Option<PathBuf>,

    /// Path to the public key file for verification.
    #[clap(short = 'p', long)]
    pub public_key: Option<PathBuf>,

    /// Path to store the generated signature, or load for verification. Defaults to 'firmware.sig'.
    #[clap(short = 'o', long)]
    pub signature: Option<PathBuf>,

    /// Sign the firmware binary or hex file.
    #[clap(long)]
    pub sign: bool,

    /// Verify the firmware signature.
    #[clap(long)]
    pub verify: bool,

    /// Generate a new password-protected Ed25519 key pair.
    #[clap(long)]
    pub generate_keys: bool,

    #[cfg(test)]
    #[clap(subcommand)]
    pub command: Option<TestCommand>,
}

#[cfg(test)]
#[derive(Subcommand, Debug)]
pub enum TestCommand {
    Test {
        #[clap(long)]
        t: String,
    },
}