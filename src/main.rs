use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use ed25519_dalek::{VerifyingKey, Verifier};




#[derive(Parser, Debug)]
struct Props{
    path: std::path::PathBuf,
}

fn main() {
    // let args = Props::parse();
    // let bytes = std::fs::read(&args.path);
    let message:&[u8] = b"This is a test of the tsunami alert system.";

    let temp=generate_key_pair(message);
    verifier(temp.signature, message, temp.signing_key);
    


    // match bytes {
    //     Ok(_data) => {
    //     }
    //     Err(e) => {
    //         eprintln!("Error reading file: {}", e);
    //     }
    // }
}
pub struct ReturnKeypair {
    pub signature: Signature,
    pub signing_key: SigningKey,
}



fn generate_key_pair(message: &[u8]) -> ReturnKeypair {
    let bytestream: [u8; 32] = [1, 2, 3, 4, 1, 2, 3, 4,1, 2, 3, 4, 1, 2, 3, 4,1, 2, 3, 4, 1, 2, 3, 4,1, 2, 3, 4, 1, 2, 3, 4];
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