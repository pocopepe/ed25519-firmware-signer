use ed25519_dalek::{Signature, Signer, SigningKey};
use ed25519_dalek::{VerifyingKey, Verifier};


pub fn sign(message: &[u8], signing_key: SigningKey) -> Signature {
    let signature = signing_key.sign(message);
    signature
}

pub fn verifier(signature:Signature, message:&[u8], verifying_key:VerifyingKey){
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Signature verified."),
        Err(_) => eprintln!("Signature verification failed!"),
    }
}

