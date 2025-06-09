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

    #[clap(long, help="Path to store Keys")]
    keypath: Option<std::path::PathBuf>,

    #[clap(long, help="Path to store Keys")]
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
        let public_key_path = args.keypath
            .expect("Public key path is required for verification (--keypath)");
        let public_key_bytes = std::fs::read(&public_key_path)
            .expect(&format!("Failed to read public key from {:?}", public_key_path));
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Invalid public key length (expected 32 bytes)"))
            .expect("Failed to create VerifyingKey from bytes");
        let binary_path = args.path
            .expect("Firmware binary path is required for verification (--path)");
        let binary_data = std::fs::read(&binary_path)
            .expect(&format!("Failed to read firmware binary from {:?}", binary_path));
        let signature_path = args.signaturepath
            .expect("Signature path is required for verification (--signaturepath)");
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