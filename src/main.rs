use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::prelude::*;





#[derive(Parser, Debug)]
struct Props{
    #[clap(long)]
path: Option<std::path::PathBuf>,
}

fn main() {
    let args = Props::parse();
    let path = args.path.unwrap_or_else(|| "./test.bin".into());

    let bytes = std::fs::read(&path);

    


    match bytes {
        Ok(data) => {
            let temp=generate_key_pair(&data);
            verifier(temp.signature, &data, temp.signing_key);


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



fn generate_key_pair(message: &[u8]) -> ReturnKeypair {
let mut rng = rand::rng();
    let bytestream:[u8; 32]=rng.random();        
    let signing_key = SigningKey::from_bytes(&bytestream);
    let signature = signing_key.sign(message);
    ReturnKeypair {signature,signing_key,}
}

fn verifier(signature:Signature, message:&[u8], signing_key:SigningKey){
let verifying_key: VerifyingKey = signing_key.verifying_key();
assert!(
    verifying_key.verify(message, &signature).is_ok(),
    "Signature verification failed!"
);}