use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::prelude::*;

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
    signaturepath: Option<std::path::PathBuf>
}

fn main() {
    let args = Props::parse();
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
            println!("{:?}", signature); //remove it later
        }
        Err(e) => {
            eprintln!("Error reading file: {}", e);
        }
    }
    if args.gen_keys{
        generate_key_pair();
    }
    }
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
            let signature_path = if let Some(p) = args.signaturepath {
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

    else if args.gen_keys{
        generate_key_pair();
    }

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

//add storing logic into genkeypair
fn generate_key_pair() -> SigningKey {
let mut rng = rand::rng();
    let bytestream:[u8; 32]=rng.random();        
    let signing_key = SigningKey::from_bytes(&bytestream);
    print!("done deal"); //remove it in post
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