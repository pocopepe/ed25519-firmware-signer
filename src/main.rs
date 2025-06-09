use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};


#[derive(Parser, Debug)]
#[command(about = "Sign or verify firmware blobs using Ed25519", author, version)]
struct Props {
    #[clap(long, help = "Path to firmware binary")]
    path: Option<std::path::PathBuf>,

    #[clap(long, help = "Path to private key for signing")]
    key: Option<std::path::PathBuf>,

    #[clap(short = 's', long, help = "Sign the firmware")]
    sign: bool,

    #[clap(short = 'v', long, help = "Verify the firmware signature")]
    verify: bool,

    #[clap(short = 'g', long, help = "Generate a new key pair")]
    gen_keys: bool,

    #[clap(long, help="Path to store Keys (for public key in verify mode)")]
    keypath: Option<std::path::PathBuf>,

    #[clap(long, help="Path to store Signature (for verification mode)")]
    signature_path: Option<std::path::PathBuf>, 
    
    #[cfg(feature = "test_mode")]
    #[clap(short='t', help = "Enable testing mode with a specified base directory for test files (e.g., --test-mode test/test0)")]
    test_mode: Option<std::path::PathBuf>,
}

fn main() {
    let args = Props::parse();

    let base_dir: PathBuf = {
        #[cfg(feature = "test_mode")]
        {
            args.test_mode.unwrap_or_else(|| {
                std::env::current_dir().expect("Failed to get current working directory")
            })
        }
        #[cfg(not(feature = "test_mode"))]
        {
            std::env::current_dir().expect("Failed to get current working directory")
        }
    };

    //sign logic
        if args.sign {
        let binary_path = if let Some(p) = args.path {
            base_dir.join(p)
        } else {
            #[cfg(feature = "test_mode")]
            {
                base_dir.join("test.bin") // Default binary name in test mode
            }
            #[cfg(not(feature = "test_mode"))]
            {
                eprintln!("Error: Firmware binary path is required for signing (--path)");
                std::process::exit(1);
            }
        };
        let binary_data = std::fs::read(&binary_path)
            .expect(&format!("Failed to read firmware binary from {:?}", binary_path));

        let signing_key = if let Some(key_path) = args.key.as_deref() {
            let bytes = std::fs::read(key_path).expect("Failed to read key file");
            SigningKey::from_bytes(&bytes.try_into().expect("Invalid key length (expected 32 bytes)"))
        } else {
            let default_private_key_path = base_dir.join("signing_key.bin");
            if default_private_key_path.exists() {
                let bytes = std::fs::read(&default_private_key_path)
                    .expect(&format!("Failed to read private key from {:?}", default_private_key_path));
                SigningKey::from_bytes(&bytes.try_into().expect("Invalid key length (expected 32 bytes)"))
            } else {
                generate_key_pair_in_dir(&base_dir)
            }
        };

        let signature: Signature = sign(&binary_data, signing_key.clone());

        let signature_filename = base_dir.join("firmware.sig");
        let signature_bytes = signature.to_bytes();

        match std::fs::write(&signature_filename, signature_bytes) {
            Ok(_) => {},
            Err(e) => eprintln!("Error saving signature to {}: {}", signature_filename.display(), e),
        }

        print!("Exec Sucess\n");
    }

    // Verify logic
    else if args.verify {
        let public_key_path = if let Some(p) = args.keypath {
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
        
        // START: Modified binary_path resolution for verify logic
        let binary_path = if let Some(p) = args.path {
            base_dir.join(p)
        } else {
            #[cfg(feature = "test_mode")]
            {
                base_dir.join("test.bin") // Default binary name in test mode
            }
            #[cfg(not(feature = "test_mode"))]
            {
                eprintln!("Error: Firmware binary path is required for verification (--path)");
                std::process::exit(1);
            }
        };
        // END: Modified binary_path resolution
        let binary_data = std::fs::read(&binary_path)
            .expect(&format!("Failed to read firmware binary from {:?}", binary_path));
        
        // START: Modified signature_path resolution for verify logic
        let signature_path = if let Some(p) = args.signature_path {
            base_dir.join(p)
        } else {
            #[cfg(feature = "test_mode")]
            {
                base_dir.join("firmware.sig") // Default signature name in test mode
            }
            #[cfg(not(feature = "test_mode"))]
            {
                eprintln!("Error: Signature path is required for verification (--signature_path)");
                std::process::exit(1);
            }
        };
        // END: Modified signature_path resolution
        let signature_bytes = std::fs::read(&signature_path)
            .expect(&format!("Failed to read signature from {:?}", signature_path));
        let signature = Signature::from_bytes(&signature_bytes.try_into().expect("Invalid signature length (expected 64 bytes)"));
        verifier(signature, &binary_data, verifying_key);
    }
    
    //key generation logic
    else if args.gen_keys{
        generate_key_pair_in_dir(&base_dir);
    }

    //fallback yessir
    else {
        eprintln!("No operation specified. Use --sign, --verify, or --gen-keys.");
        eprintln!("For help, use: {} --help", env!("CARGO_PKG_NAME")); 
        std::process::exit(1);
    }

}

pub struct ReturnKeypair {
    pub signature: Signature,
    pub signing_key: SigningKey,
}

fn generate_key_pair_in_dir(output_dir: &Path) -> SigningKey {
    let mut rng = OsRng;

    let signing_key = SigningKey::generate(&mut rng);

    let public_key = signing_key.verifying_key();

    let private_key_filename = output_dir.join("signing_key.bin");
    let public_key_filename = output_dir.join("public_key.bin");

    match std::fs::write(&private_key_filename, signing_key.to_bytes()) {
        Ok(_) => {},
        Err(e) => eprintln!("Error saving private key to {}: {}", private_key_filename.display(), e),
    }
    match std::fs::write(&public_key_filename, public_key.to_bytes()) {
        Ok(_) => {},
        Err(e) => eprintln!("Error saving public key to {}: {}", public_key_filename.display(), e),
    }

    return signing_key;
}

fn sign(message: &[u8], signing_key:SigningKey)->Signature{
    let signature = signing_key.sign(message);
    return signature;
}

fn verifier(signature:Signature, message:&[u8], verifying_key:VerifyingKey){
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Signature verified."),
        Err(_) => eprintln!("Signature verification failed!"),
    }
}