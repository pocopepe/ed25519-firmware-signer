use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use std::path::PathBuf;
use std::io::Write; 

mod crypto_logic;
mod read_files;

#[cfg(test)]
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(about = "Sign or verify firmware blobs using Ed25519", author, version)]
struct Props {
    /// Path to firmware binary
    #[clap(short = 'f', long)]
    path: Option<PathBuf>,

    /// Path to private key for signing
    #[clap(short = 's', long)]
    signing_key: Option<PathBuf>,

    /// Path to public key for verification
    #[clap(short = 'p', long)]
    public_key: Option<PathBuf>,

    /// Path to store the generated signature
    #[clap(short = 'o', long)]
    signature: Option<PathBuf>,

    /// Sign the firmware binary
    #[clap(long)]
    sign: bool,

    /// Verify the firmware signature
    #[clap(long)]
    verify: bool,

    #[cfg(test)]
    #[clap(subcommand)]
    command: Option<TestCommand>,
}

#[cfg(test)]
#[derive(Subcommand, Debug)]
enum TestCommand {
    Test {
        #[clap(long)]
        t: String,
    },
}


fn main() {
    let args = Props::parse();

    let base_dir: PathBuf = {
        #[cfg(test)]
        {
            if let Some(TestCommand::Test { t }) = &args.command {
                PathBuf::from("test").join(t)
            } else {
                std::env::current_dir().expect("Failed to get current working directory")
            }
        }
        #[cfg(not(test))]
        {
            std::env::current_dir().expect("Failed to get current working directory")
        }
    };

    // Sign logic
    if args.sign {
        let binary_path = if let Some(p) = args.path {
            base_dir.join(p)
        } else {
            #[cfg(test)]
            {
                base_dir.join("test.bin")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Firmware binary path is required for signing (--path)");
                std::process::exit(1);
            }
        };
        let binary_data = read_files::read_firmware_data(&binary_path)
            .unwrap_or_else(|e| {
                eprintln!("Error reading firmware from {:?}: {}", binary_path, e);
                std::process::exit(1);
            });


        let signing_key = if let Some(key_path) = args.signing_key.as_deref() {
            let bytes = std::fs::read(key_path).expect("Failed to read key file");
            SigningKey::from_bytes(&bytes.try_into().expect("Invalid key length (expected 32 bytes)"))
        } else {
            let default_private_key_path = base_dir.join("signing_key.bin");
            if default_private_key_path.exists() {
                let bytes = std::fs::read(&default_private_key_path)
                    .expect(&format!("Failed to read private key from {:?}", default_private_key_path));
                SigningKey::from_bytes(&bytes.try_into().expect("Invalid key length (expected 32 bytes)"))
            } else {
                println!("No signing key specified and 'signing_key.bin' not found. Generating a new key pair...");
                crypto_logic::generate_key_pair_in_dir(&base_dir)
            }
        };

        let signature: Signature = crypto_logic::sign(&binary_data, signing_key.clone());

        let signature_filename = base_dir.join("firmware.sig");
        let signature_bytes = signature.to_bytes();

        match std::fs::write(&signature_filename, signature_bytes) {
            Ok(_) => {
                println!("Signature successfully saved to {}.", signature_filename.display());
                println!("Exec Sucess");
            },
            Err(e) => eprintln!("Error saving signature to {}: {}", signature_filename.display(), e),
        }
    }

    // Verify logic
    else if args.verify {
        let public_key_path = if let Some(p) = args.public_key {
            p
        } else {
            let default_public_key_filename = base_dir.join("public_key.bin");
            if default_public_key_filename.exists() {
                default_public_key_filename.to_path_buf()
            } else {
                eprintln!("Error: Public key path is required for verification (--keypath) or 'public_key.bin' must exist in the current directory.");
                std::process::exit(1);
            }
        };
        let public_key_bytes = std::fs::read(&public_key_path)
            .expect(&format!("Failed to read public key from {:?}", public_key_path));
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Invalid public key length (expected 32 bytes)"))
            .expect("Failed to create VerifyingKey from bytes");

        let binary_path = if let Some(p) = args.path {
            base_dir.join(p)
        } else {
            #[cfg(test)]
            {
                base_dir.join("test.bin")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Firmware binary path is required for verification (--path)");
                std::process::exit(1);
            }
        };
        let binary_data = read_files::read_firmware_data(&binary_path)
                    .unwrap_or_else(|e| {
                        eprintln!("Error reading firmware from {:?}: {}", binary_path, e);
                        std::process::exit(1);
                    });

        let signature_path = if let Some(p) = args.signature {
            base_dir.join(p)
        } else {
            #[cfg(test)]
            {
                base_dir.join("firmware.sig")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Signature path is required for verification (--signature_path)");
                std::process::exit(1);
            }
        };
        let signature_bytes = std::fs::read(&signature_path)
            .expect(&format!("Failed to read signature from {:?}", signature_path));
        let signature = Signature::from_bytes(&signature_bytes.try_into().expect("Invalid signature length (expected 64 bytes)"));
        crypto_logic::verifier(signature, &binary_data, verifying_key);
    }

    // Generate keys logic, if everything falls through
    else  {
        let private_key_path = base_dir.join("signing_key.bin");
        let public_key_path = base_dir.join("public_key.bin");

        if private_key_path.exists() {
            if public_key_path.exists() {
                eprintln!("Warning: Existing '{}' and '{}' found in {}.",
                          private_key_path.display(), public_key_path.display(), base_dir.display());
                eprintln!("Ths command will overwrite existing keys, and the old keys cannot be retrieved.");
                eprint!("Are you sure you want to proceed? (y/n): ");
                std::io::stdout().flush().expect("Failed to flush stdout");

                let mut input = String::new();
                std::io::stdin().read_line(&mut input).expect("Failed to read line");
                let confirmation = input.trim().to_lowercase();

                if confirmation == "y" || confirmation == "yes" {
                    println!("Overwriting existing keys...");
                    crypto_logic::generate_key_pair_in_dir(&base_dir);
                } else {
                    println!("Key generation cancelled.");
                }
            } else {
                println!("'signing_key.bin' found but 'public_key.bin' is missing. Regenerating public key from existing private key...");
                let private_key_bytes = std::fs::read(&private_key_path)
                    .expect(&format!("Failed to read private key from {:?}", private_key_path));
                let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid private key length (expected 32 bytes)"));
                let public_key = signing_key.verifying_key();

                match std::fs::write(&public_key_path, public_key.to_bytes()) {
                    Ok(_) => println!("Public key successfully regenerated and saved to {}.", public_key_path.display()),
                    Err(e) => eprintln!("Error saving public key to {}: {}", public_key_path.display(), e),
                }
            }
        } else {
            println!("No existing 'signing_key.bin' found. Generating a new key pair...");
            crypto_logic::generate_key_pair_in_dir(&base_dir);
        }
    }
}