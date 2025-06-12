use ed25519_dalek::{Signature, Signer, SigningKey};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::rngs::OsRng;
use std::io::{self, Write}; 
use rpassword;

pub fn take_password_entry(prompt_type: String) -> String {// maybe later convert prompt from string to a struct so that I can have auto fill on this
    match prompt_type.as_str() { 
        "firsttime" => { //used for first entry of the password
            loop {
                print!("Enter password for private key: ");
                io::stdout().flush().expect("Failed to flush stdout");
                let first_entry = rpassword::read_password()
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
        },
        "verify" => {// used for logic when password is entered to use the keys
            loop {
                print!("Enter password for private key: ");
                io::stdout().flush().expect("Failed to flush stdout");
                let entry = rpassword::read_password()
                    .expect("Failed to read password from stdin");

                if entry.is_empty() {
                    eprintln!("Password cannot be empty. Please try again.");
                } else {
                    return entry;
                }
            }
        },
        _ => {
            eprintln!("Error: The program has reached its end, try again");
            std::process::exit(1);
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