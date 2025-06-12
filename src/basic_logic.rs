use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize; // For securely clearing password from memory

// Import password_crypto from the crate root
use crate::password_crypto;

// --- Helper for user password input ---
pub fn take_password_entry(prompt_type: &str) -> io::Result<String> {
    loop {
        print!("Enter password for private key: ");
        io::stdout().flush()?;
        let first_entry = rpassword::read_password()?;

        match prompt_type {
            "firsttime" => {
                print!("Confirm password: ");
                io::stdout().flush()?;
                let second_entry = rpassword::read_password()?;

                if first_entry == second_entry {
                    if first_entry.is_empty() {
                        eprintln!("Password cannot be empty. Please try again.");
                    } else {
                        println!("Password confirmed.");
                        return Ok(first_entry);
                    }
                } else {
                    eprintln!("Passwords do not match. Please try again.");
                }
            },
            "verify" => {
                if first_entry.is_empty() {
                    eprintln!("Password cannot be empty. Please try again.");
                } else {
                    println!("Password entered."); // More neutral message
                    return Ok(first_entry);
                }
            },
            _ => {
                eprintln!("Error: Invalid password prompt type '{}'. Program will exit.", prompt_type);
                std::process::exit(1);
            }
        }
    }
}

// --- Public Function: Generate Key Pair (password-protected) ---
pub fn generate_key_pair_in_dir(output_dir: &Path) -> io::Result<SigningKey> {
    let signing_key_path = output_dir.join("signing_key.bin");
    let public_key_path = output_dir.join("public_key.bin");

    if signing_key_path.exists() || public_key_path.exists() {
        eprintln!("Warning: Existing '{}' or '{}' found in {}.",
                  signing_key_path.display(), public_key_path.display(), output_dir.display());
        eprintln!("This command will overwrite existing keys, and the old keys cannot be retrieved.");
        print!("Are you sure you want to proceed? (y/n): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let confirmation = input.trim().to_lowercase();

        if confirmation != "y" && confirmation != "yes" {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Key generation cancelled by user."));
        }
        println!("Overwriting existing keys...");
    }

    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();

    let password = take_password_entry("firsttime")?; // Call your password prompt
    
    let (salt, nonce, ciphertext_with_tag) =
        password_crypto::encrypt_with_password(&signing_key.to_bytes(), &password)?;

    // Concatenate salt, nonce, and ciphertext for storage
    // The format in the file will be: [SALT_LEN bytes] || [NONCE_LEN bytes] || [CIPHERTEXT + TAG bytes]
    let mut encrypted_data_to_save = Vec::new();
    encrypted_data_to_save.extend_from_slice(&salt);
    encrypted_data_to_save.extend_from_slice(&nonce);
    encrypted_data_to_save.extend_from_slice(&ciphertext_with_tag);

    std::fs::write(&signing_key_path, encrypted_data_to_save)?;
    std::fs::write(&public_key_path, public_key.to_bytes())?;

    println!("Key pair generated successfully.");
    println!("Private key (encrypted) saved to: {}", signing_key_path.display());
    println!("Public key saved to: {}", public_key_path.display());

    Ok(signing_key)
}

pub fn load_encrypted_signing_key(key_path: &Path) -> io::Result<SigningKey> {
    if !key_path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Key file not found: {}", key_path.display())));
    }

    let encrypted_data = std::fs::read(key_path)?;

    let mut password_attempts = 0;
    loop {
        let mut password = take_password_entry("verify")?; // Call your password prompt
        let decrypted_bytes_result = password_crypto::decrypt_with_password(&encrypted_data, &password);
        
        password.zeroize(); // Securely clear password from memory

        match decrypted_bytes_result {
            Ok(decrypted_bytes) => {
                const EXPECTED_KEY_LEN: usize = 32;
                if decrypted_bytes.len() != EXPECTED_KEY_LEN {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Decrypted key has incorrect length. It might be corrupted or the wrong password was used."));
                }
                let signing_key = SigningKey::from_bytes(
                    &decrypted_bytes.try_into()
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to convert decrypted bytes to SigningKey array"))?
                );
                return Ok(signing_key);
            },
            Err(e) => {
                eprintln!("Decryption failed: {}", e);
                password_attempts += 1;
                if password_attempts >= 3 {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Too many incorrect password attempts."));
                }
                eprintln!("Incorrect password. Please try again.");
            }
        }
    }
}

// --- Public Function: Sign Data ---
pub fn sign(message: &[u8], signing_key: SigningKey) -> Signature {
    signing_key.sign(message) // This will now work
}

// --- Public Function: Verify Data ---
pub fn verifier(signature: Signature, message: &[u8], public_key: VerifyingKey) {
    match public_key.verify(message, &signature) { // This will now work
        Ok(_) => {
            println!("Signature verification successful!");
            println!("Exec Success");
        },
        Err(e) => {
            eprintln!("Signature verification failed: {}", e);
            std::process::exit(1);
        },
    }
}