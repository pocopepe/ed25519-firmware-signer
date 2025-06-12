use ed25519_dalek::{Signature, Signer, SigningKey};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::rngs::OsRng;


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

pub fn generate_key_pair_in_dir(output_dir: &std::path::Path) -> SigningKey {
    let mut rng = OsRng;

    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key();

    let private_key_filename = output_dir.join("signing_key.bin");
    let public_key_filename = output_dir.join("public_key.bin");

    match std::fs::write(&private_key_filename, signing_key.to_bytes()) {
        Ok(_) => println!("Private key saved to {}.", private_key_filename.display()),
        Err(e) => eprintln!("Error saving private key to {}: {}", private_key_filename.display(), e),
    }
    match std::fs::write(&public_key_filename, public_key.to_bytes()) {
        Ok(_) => println!("Public key saved to {}.", public_key_filename.display()),
        Err(e) => eprintln!("Error saving public key to {}: {}", public_key_filename.display(), e),
    }

    signing_key
}