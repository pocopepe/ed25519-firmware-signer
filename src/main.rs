// src/main.rs

use std::path::PathBuf;
use std::fs;
use clap::{Parser};
use ed25519_dalek::{VerifyingKey, Signature};

mod cli_args;
mod basic_logic;
mod read_files;
mod password_crypto;

fn main() {
    let args = cli_args::Props::parse();

    let base_dir: PathBuf = {
        #[cfg(test)]
        {
            if let Some(cli_args::TestCommand::Test { t }) = &args.command {
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
            p
        } else {
            #[cfg(test)]
            {
                base_dir.join("test.bin")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Firmware binary path (--path) is required for signing.");
                std::process::exit(1);
            }
        };

        let binary_data = read_files::read_firmware_data(&binary_path)
            .unwrap_or_else(|e| {
                eprintln!("Error reading firmware from {}: {}", binary_path.display(), e);
                std::process::exit(1);
            });

        let signing_key_path = args.signing_key.unwrap_or_else(|| base_dir.join("signing_key.bin"));

        let signing_key = basic_logic::load_encrypted_signing_key(&signing_key_path)
            .unwrap_or_else(|e| {
                eprintln!("Error loading signing key from {}: {}", signing_key_path.display(), e);
                std::process::exit(1);
            });

        let signature: Signature = basic_logic::sign(&binary_data, signing_key);

        let signature_filename = args.signature.unwrap_or_else(|| base_dir.join("firmware.sig"));

        match fs::write(&signature_filename, signature.to_bytes()) {
            Ok(_) => {
                println!("Signature successfully saved to {}.", signature_filename.display());
                println!("Exec Success");
            },
            Err(e) => eprintln!("Error saving signature to {}: {}", signature_filename.display(), e),
        }
    }
    else if args.verify {
        // Verify logic remains the same
        let public_key_path = args.public_key.unwrap_or_else(|| base_dir.join("public_key.bin"));

        let public_key_bytes = fs::read(&public_key_path)
            .unwrap_or_else(|e| {
                eprintln!("Error reading public key from {}: {}", public_key_path.display(), e);
                std::process::exit(1);
            });
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Invalid public key length (expected 32 bytes)"))
            .expect("Failed to create VerifyingKey from bytes");

        let binary_path = if let Some(p) = args.path {
            p
        } else {
            #[cfg(test)]
            {
                base_dir.join("test.bin")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Firmware binary path (--path) is required for verification.");
                std::process::exit(1);
            }
        };

        let binary_data = read_files::read_firmware_data(&binary_path)
                    .unwrap_or_else(|e| {
                        eprintln!("Error reading firmware from {}: {}", binary_path.display(), e);
                        std::process::exit(1);
                    });

        let signature_path = args.signature.unwrap_or_else(|| base_dir.join("firmware.sig"));

        let signature_bytes = fs::read(&signature_path)
            .unwrap_or_else(|e| {
                eprintln!("Error reading signature from {}: {}", signature_path.display(), e);
                std::process::exit(1);
            });
        let signature = Signature::from_bytes(&signature_bytes.try_into().expect("Invalid signature length (expected 64 bytes)"));

        basic_logic::verifier(signature, &binary_data, verifying_key);
    }
    else if !args.generate_keys { // Only enter this if --generate-keys wasn't explicitly used
        println!("No specific action specified. Defaulting to key generation.");
        basic_logic::generate_key_pair_in_dir(&base_dir)
            .unwrap_or_else(|e| {
                eprintln!("Error generating key pair: {}", e);
                std::process::exit(1);
            });
    }
}