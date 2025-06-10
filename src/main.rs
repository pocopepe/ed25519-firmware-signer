use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::io::{self, Write}; 

#[cfg(test)]
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(about = "Sign or verify firmware blobs using Ed25519", author, version)]
struct Props {
    #[clap(short='b', long, help = "Path to firmware binary")]
    path: Option<std::path::PathBuf>,

    #[clap(short= 'k', long, help = "Path to private key for signing")]
    signing_key: Option<std::path::PathBuf>,

    #[clap(short = 'p' ,long, help="Path to store Keys (for public key in verify mode)")]
    public_key: Option<std::path::PathBuf>,

    #[clap(long, help="Path to store Signature (for verification mode)")]
    signature: Option<std::path::PathBuf>,

    #[clap(short = 's', long, help = "Sign the firmware")]
    sign: bool,

    #[clap(short = 'v', long, help = "Verify the firmware signature")]
    verify: bool,

    #[clap(short = 'g', long, help = "Generate a new key pair")]
    gen_keys: bool,

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
        let binary_data = std::fs::read(&binary_path)
            .expect(&format!("Failed to read firmware binary from {:?}", binary_path));

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
                generate_key_pair_in_dir(&base_dir)
            }
        };

        let signature: Signature = sign(&binary_data, signing_key.clone());

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
        let binary_data = std::fs::read(&binary_path)
            .expect(&format!("Failed to read firmware binary from {:?}", binary_path));

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
        verifier(signature, &binary_data, verifying_key);
    }

    // Generate keys logic
    else if args.gen_keys {
        let private_key_path = base_dir.join("signing_key.bin");
        let public_key_path = base_dir.join("public_key.bin");

        if private_key_path.exists() {
            if public_key_path.exists() {
                eprintln!("Warning: Existing '{}' and '{}' found in {}.",
                          private_key_path.display(), public_key_path.display(), base_dir.display());
                eprintln!("Running '--gen-keys' will overwrite these files, and the old keys cannot be retrieved.");
                eprint!("Are you sure you want to proceed? (y/N): ");
                io::stdout().flush().expect("Failed to flush stdout");

                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let confirmation = input.trim().to_lowercase();

                if confirmation == "y" || confirmation == "yes" {
                    println!("Overwriting existing keys...");
                    generate_key_pair_in_dir(&base_dir);
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
            generate_key_pair_in_dir(&base_dir);
        }
    }

    else {
        eprintln!("No operation specified.");
        eprintln!("For help, use: {} --help", env!("CARGO_PKG_NAME"));
        std::process::exit(1);
    }
}


fn generate_key_pair_in_dir(output_dir: &Path) -> SigningKey {
    let mut rng = OsRng;

    let signing_key = SigningKey::generate(&mut rng);

    let public_key = signing_key.verifying_key();

    let private_key_filename = output_dir.join("signing_key.bin");
    let public_key_filename = output_dir.join("public_key.bin");

    match std::fs::write(&private_key_filename, signing_key.to_bytes()) {
        Ok(_) => println!("Private key saved to {}.", private_key_filename.display()),
        Err(e) => eprintln!("Error saving private key to {}: {}", private_key_filename.display(), e),
    }
    match std::fs::write(&public_key_filename, public_key.to_bytes()) {
        Ok(_) => println!("Public key saved to {}.", public_key_filename.display()),
        Err(e) => eprintln!("Error saving public key to {}: {}", public_key_filename.display(), e),
    }

    signing_key
}

fn sign(message: &[u8], signing_key:SigningKey)->Signature{
    let signature = signing_key.sign(message);
    signature
}

fn verifier(signature:Signature, message:&[u8], verifying_key:VerifyingKey){
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Signature verified."),
        Err(_) => eprintln!("Signature verification failed!"),
    }
}
