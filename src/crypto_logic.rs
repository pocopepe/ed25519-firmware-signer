use ed25519_dalek::{Signature, Signer, SigningKey};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::rngs::OsRng;
use std::io::{self, Write}; 

pub fn take_password_entry()->String{
    loop {
        print!("Enter password for private key: ");
        std::io::stdout().flush().expect("Failed to flush stdout");
        let first_entry: String = rpassword::read_password()
            .expect("Failed to read password from stdin");

        print!("Confirm password: ");
        io::stdout().flush().expect("Failed to flush stdout");
        let second_entry = rpassword::read_password()
            .expect("Failed to read password from stdin");

        if first_entry == second_entry {
            if first_entry.is_empty() {
                eprintln!("Password cannot be empty. Please try again.");
            } else {
                println!("Password confirmed.");
                return first_entry;
            }
        } else {
            eprintln!("Passwords do not match. Please try again.");
        }
    }
}

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