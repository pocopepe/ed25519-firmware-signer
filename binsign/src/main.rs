use binsign_core::{crypto, firmware, manifest};
use clap::Parser;
use ed25519_dalek::{Signature, VerifyingKey};
use std::fs;
use std::path::PathBuf;

mod cli_args;
mod git;

fn main() {
    let args: cli_args::Props = cli_args::Props::parse();

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

    if args.track {
        // --track: detect firmware changes and append a signed entry to the manifest.
        let binary_path = args.path.unwrap_or_else(|| {
            eprintln!("Error: --path is required for --track.");
            std::process::exit(1);
        });

        let firmware_data = firmware::read_firmware_data(&binary_path).unwrap_or_else(|e| {
            eprintln!(
                "Error reading firmware from {}: {}",
                binary_path.display(),
                e
            );
            std::process::exit(1);
        });

        let manifest_path = args.manifest.unwrap_or_else(|| {
            let stem = binary_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("firmware");
            base_dir.join(format!("{}.manifest.json", stem))
        });

        let public_key_path = args
            .public_key
            .unwrap_or_else(|| base_dir.join("public_key.bin"));
        let public_key_bytes = fs::read(&public_key_path).unwrap_or_else(|e| {
            eprintln!(
                "Error reading public key from {}: {}",
                public_key_path.display(),
                e
            );
            std::process::exit(1);
        });
        let public_key_hex = hex::encode(&public_key_bytes);
        let firmware_name = binary_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("firmware")
            .to_string();

        let mut fw_manifest = manifest::FirmwareManifest::load_or_new(
            &manifest_path,
            &firmware_name,
            &public_key_hex,
        )
        .unwrap_or_else(|e| {
            eprintln!(
                "Error loading manifest from {}: {}",
                manifest_path.display(),
                e
            );
            std::process::exit(1);
        });

        if !fw_manifest.firmware_changed(&firmware_data) {
            println!(
                "No changes detected — firmware matches version {}.",
                fw_manifest.entries.last().map(|e| e.version).unwrap_or(0)
            );
            return;
        }

        let signing_key_path = args
            .signing_key
            .unwrap_or_else(|| base_dir.join("signing_key.bin"));
        let signing_key =
            crypto::load_encrypted_signing_key(&signing_key_path).unwrap_or_else(|e| {
                eprintln!(
                    "Error loading signing key from {}: {}",
                    signing_key_path.display(),
                    e
                );
                std::process::exit(1);
            });

        let version = fw_manifest.append_entry(&firmware_data, &signing_key);

        fw_manifest.save(&manifest_path).unwrap_or_else(|e| {
            eprintln!(
                "Error saving manifest to {}: {}",
                manifest_path.display(),
                e
            );
            std::process::exit(1);
        });

        println!(
            "Firmware changed — signed as version {} and saved to {}.",
            version,
            manifest_path.display()
        );
    } else if args.sign {
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

        let binary_data = firmware::read_firmware_data(&binary_path).unwrap_or_else(|e| {
            eprintln!(
                "Error reading firmware from {}: {}",
                binary_path.display(),
                e
            );
            std::process::exit(1);
        });

        let signing_key_path = args
            .signing_key
            .unwrap_or_else(|| base_dir.join("signing_key.bin"));
        let signing_key =
            crypto::load_encrypted_signing_key(&signing_key_path).unwrap_or_else(|e| {
                eprintln!(
                    "Error loading signing key from {}: {}",
                    signing_key_path.display(),
                    e
                );
                std::process::exit(1);
            });

        let sig: Signature = crypto::sign(&binary_data, &signing_key);
        let signature_filename = args
            .signature
            .unwrap_or_else(|| base_dir.join("firmware.sig"));

        match fs::write(&signature_filename, sig.to_bytes()) {
            Ok(_) => println!(
                "Signature successfully saved to {}.",
                signature_filename.display()
            ),
            Err(e) => eprintln!(
                "Error saving signature to {}: {}",
                signature_filename.display(),
                e
            ),
        }
    } else if args.verify {
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

        let binary_data = firmware::read_firmware_data(&binary_path).unwrap_or_else(|e| {
            eprintln!(
                "Error reading firmware from {}: {}",
                binary_path.display(),
                e
            );
            std::process::exit(1);
        });

        // Manifest-based verification (--manifest provided)
        if let Some(manifest_path) = args.manifest {
            let fw_manifest = manifest::FirmwareManifest::load_or_new(&manifest_path, "", "")
                .unwrap_or_else(|e| {
                    eprintln!(
                        "Error loading manifest from {}: {}",
                        manifest_path.display(),
                        e
                    );
                    std::process::exit(1);
                });

            match fw_manifest.verify_latest(&binary_data) {
                Ok(entry) => {
                    println!("Verification successful!");
                    println!("  Version  : {}", entry.version);
                    println!("  Signed   : {}", entry.timestamp);
                    println!("  SHA-256  : {}", entry.sha256);
                    println!("  Size     : {} bytes", entry.size_bytes);
                }
                Err(e) => {
                    eprintln!("Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            // Raw .sig file verification (legacy path)
            let public_key_path = args
                .public_key
                .unwrap_or_else(|| base_dir.join("public_key.bin"));
            let public_key_bytes = fs::read(&public_key_path).unwrap_or_else(|e| {
                eprintln!(
                    "Error reading public key from {}: {}",
                    public_key_path.display(),
                    e
                );
                std::process::exit(1);
            });
            let verifying_key = VerifyingKey::from_bytes(
                &public_key_bytes
                    .try_into()
                    .expect("Invalid public key length (expected 32 bytes)"),
            )
            .expect("Failed to create VerifyingKey from bytes");

            let signature_path = args
                .signature
                .unwrap_or_else(|| base_dir.join("firmware.sig"));
            let signature_bytes = fs::read(&signature_path).unwrap_or_else(|e| {
                eprintln!(
                    "Error reading signature from {}: {}",
                    signature_path.display(),
                    e
                );
                std::process::exit(1);
            });
            let signature = Signature::from_bytes(
                &signature_bytes
                    .try_into()
                    .expect("Invalid signature length (expected 64 bytes)"),
            );

            crypto::verifier(signature, &binary_data, verifying_key);
        }
    } else if args.generate_keys {
        crypto::generate_key_pair_in_dir(&base_dir).unwrap_or_else(|e| {
            eprintln!("Error generating key pair: {}", e);
            std::process::exit(1);
        });
    } else if args.init {
        println!("Initializing project at current directory");
    } else if let Some(commit_hash) = args.switch.as_ref() {
        println!("Switching to commit {}", commit_hash);
    } else if let Some(opt_count) = &args.history {
        let count = opt_count.unwrap_or(5);
        println!("History count: {}", count);
        let _ = git::print_latest_n_commits(count);
    } else {
        println!("No action specified.\nUse --help to see available options.");
    }
}
