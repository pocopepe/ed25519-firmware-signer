use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::rngs::OsRng;


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
    signature_path: Option<std::path::PathBuf>
}

fn main() {
    let args = Props::parse();

    //sign logic
    if args.sign{
    let path = args.path.unwrap_or_else(|| "./test.bin".into());
    let bytes = std::fs::read(&path);

    let keys = if let Some(key_path) = args.key.as_deref() {
        let bytes = std::fs::read(key_path).expect("Failed to read key file");
        SigningKey::from_bytes(&bytes.try_into().expect("Invalid key length"))
    } else {
        generate_key_pair()
    };

    match bytes {
        Ok(data) => {
            let signature: Signature=sign(&data, keys.clone());

            let signature_filename = "firmware.sig";
            let signature_bytes = signature.to_bytes();

            match std::fs::write(signature_filename, signature_bytes) {
                Ok(_) => println!("Signature saved to: {}", signature_filename),
                Err(e) => eprintln!("Error saving signature to {}: {}", signature_filename, e),
            }
        }
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    }
    if args.gen_keys{
        generate_key_pair();
    }
    }

    //verify logic
    else if args.verify {
            // Fallback for missing public key path: provide error and exit
            let public_key_path = if let Some(p) = args.keypath {
                p
            } else {
                eprintln!("Error: Public key path is required for verification (--keypath)");
                std::process::exit(1);
            };
            let public_key_bytes = std::fs::read(&public_key_path)
                .expect(&format!("Failed to read public key from {:?}", public_key_path));
            let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Invalid public key length (expected 32 bytes)"))
                .expect("Failed to create VerifyingKey from bytes");

            // Fallback for missing firmware binary path: provide error and exit
            let binary_path = if let Some(p) = args.path {
                p
            } else {
                eprintln!("Error: Firmware binary path is required for verification (--path)");
                std::process::exit(1);
            };
            let binary_data = std::fs::read(&binary_path)
                .expect(&format!("Failed to read firmware binary from {:?}", binary_path));

            // Fallback for missing signature path: provide error and exit
            let signature_path = if let Some(p) = args.signature_path {
                p
            } else {
                eprintln!("Error: Signature path is required for verification (--signaturepath)");
                std::process::exit(1);
            };
            let signature_bytes = std::fs::read(&signature_path)
                .expect(&format!("Failed to read signature from {:?}", signature_path));
            let signature = Signature::from_bytes(&signature_bytes.try_into().expect("Invalid signature length (expected 64 bytes)"));
            verifier(signature, &binary_data, verifying_key);
        }
    
    //key generation logic
    else if args.gen_keys{
        generate_key_pair();
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

fn generate_key_pair() -> SigningKey {
    let mut rng = OsRng;

    let signing_key = SigningKey::generate(&mut rng);

    let public_key = signing_key.verifying_key();

    let private_key_filename = "signing_key.bin";
    let public_key_filename = "public_key.bin";

    match std::fs::write(private_key_filename, signing_key.to_bytes()) {
        Ok(_) => println!("Private signing key saved to: {}", private_key_filename),
        Err(e) => eprintln!("Error saving private key to {}: {}", private_key_filename, e),
    }
    match std::fs::write(public_key_filename, public_key.to_bytes()) {
        Ok(_) => println!("Public key saved to: {}", public_key_filename),
        Err(e) => eprintln!("Error saving public key to {}: {}", public_key_filename, e),
    }

    return signing_key;
}

//add storing logic into signing
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