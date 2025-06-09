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

    #[clap(long, help = "Sign or verify")]
    mode: String, // e.g., "sign" or "verify"
}


fn main() {
    let args = Props::parse();
    let path = args.path.unwrap_or_else(|| "./test.bin".into());

    let bytes = std::fs::read(&path);
    let keys=generate_key_pair();

    match bytes {
        Ok(data) => {
            let signature: Signature=sign(&data, keys.clone());
            verifier(signature, &data, keys);
        }
        Err(e) => {
            eprintln!("Error reading file: {}", e);
        }
    }
}
pub struct ReturnKeypair {
    pub signature: Signature,
    pub signing_key: SigningKey,
}



fn generate_key_pair() -> SigningKey {
let mut rng = rand::rng();
    let bytestream:[u8; 32]=rng.random();        
    let signing_key = SigningKey::from_bytes(&bytestream);
    return signing_key;
}

fn sign(message: &[u8], signing_key:SigningKey)->Signature{
    let signature = signing_key.sign(message);
    return signature;
}

fn verifier(signature:Signature, message:&[u8], signing_key:SigningKey){
let verifying_key: VerifyingKey = signing_key.verifying_key();
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Signature verified."),
        Err(_) => eprintln!("Signature verification failed!"),
    }
}