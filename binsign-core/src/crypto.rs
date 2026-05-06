use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroize;

use crate::password;

pub fn take_password_entry(prompt_type: &str) -> io::Result<String> {
    loop {
        print!("Enter password for private key: ");
        io::stdout().flush()?;
        let first = rpassword::read_password()?;

        match prompt_type {
            "firsttime" => {
                print!("Confirm password: ");
                io::stdout().flush()?;
                let second = rpassword::read_password()?;
                if first.is_empty() {
                    eprintln!("Password cannot be empty. Please try again.");
                } else if first != second {
                    eprintln!("Passwords do not match. Please try again.");
                } else {
                    println!("Password confirmed.");
                    return Ok(first);
                }
            }
            "verify" => {
                if first.is_empty() {
                    eprintln!("Password cannot be empty. Please try again.");
                } else {
                    return Ok(first);
                }
            }
            _ => {
                eprintln!("Unknown prompt type '{}'. Exiting.", prompt_type);
                std::process::exit(1);
            }
        }
    }
}

pub fn generate_key_pair_in_dir(output_dir: &Path) -> io::Result<SigningKey> {
    let signing_key_path = output_dir.join("signing_key.bin");
    let public_key_path = output_dir.join("public_key.bin");

    if signing_key_path.exists() || public_key_path.exists() {
        eprintln!(
            "Warning: existing keys found in {}. This will overwrite them permanently.",
            output_dir.display()
        );
        print!("Are you sure you want to proceed? (y/n): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "key generation cancelled by user",
            ));
        }
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key();
    let pw = take_password_entry("firsttime")?;

    let (salt, nonce, ct) = password::encrypt_with_password(&signing_key.to_bytes(), &pw)?;
    let mut blob = salt;
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);

    std::fs::write(&signing_key_path, blob)?;
    std::fs::write(&public_key_path, public_key.to_bytes())?;

    println!("Key pair generated.");
    println!("  Private key: {}", signing_key_path.display());
    println!("  Public key:  {}", public_key_path.display());

    Ok(signing_key)
}

pub fn generate_key_pair_in_dir_with_password(
    output_dir: &Path,
    password: &str,
    overwrite_existing: bool,
) -> io::Result<SigningKey> {
    let signing_key_path = output_dir.join("signing_key.bin");
    let public_key_path = output_dir.join("public_key.bin");

    if (signing_key_path.exists() || public_key_path.exists()) && !overwrite_existing {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("key files already exist in {}", output_dir.display()),
        ));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key();

    let (salt, nonce, ct) = password::encrypt_with_password(&signing_key.to_bytes(), password)?;
    let mut blob = salt;
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);

    std::fs::write(&signing_key_path, blob)?;
    std::fs::write(&public_key_path, public_key.to_bytes())?;

    println!("Key pair generated.");
    println!("  Private key: {}", signing_key_path.display());
    println!("  Public key:  {}", public_key_path.display());

    Ok(signing_key)
}

pub fn load_encrypted_signing_key(key_path: &Path) -> io::Result<SigningKey> {
    if !key_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("key file not found: {}", key_path.display()),
        ));
    }

    let encrypted = std::fs::read(key_path)?;

    for attempt in 0..3 {
        let mut pw = take_password_entry("verify")?;
        let result = password::decrypt_with_password(&encrypted, &pw);
        pw.zeroize();

        match result {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "decrypted key is not 32 bytes")
                })?;
                return Ok(SigningKey::from_bytes(&arr));
            }
            Err(e) => {
                eprintln!("Incorrect password: {}", e);
                if attempt == 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "too many incorrect password attempts",
                    ));
                }
            }
        }
    }

    unreachable!()
}

pub fn sign(message: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(message)
}

pub fn verify(signature: &Signature, message: &[u8], public_key: &VerifyingKey) -> io::Result<()> {
    public_key
        .verify(message, signature)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

pub fn verifier(signature: Signature, message: &[u8], public_key: VerifyingKey) {
    match verify(&signature, message, &public_key) {
        Ok(_) => println!("Signature verification successful."),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

pub fn load_encrypted_signing_key_with_password(
    key_path: &Path,
    password: &str,
) -> io::Result<SigningKey> {
    if !key_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("key file not found: {}", key_path.display()),
        ));
    }

    let encrypted = std::fs::read(key_path)?;
    let bytes = password::decrypt_with_password(&encrypted, password)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypted key is not 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, vk) = keypair();
        let sig = sign(b"hello firmware", &sk);
        assert!(verify(&sig, b"hello firmware", &vk).is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = keypair();
        let (_, wrong_vk) = keypair();
        let sig = sign(b"hello firmware", &sk);
        assert!(verify(&sig, b"hello firmware", &wrong_vk).is_err());
    }

    #[test]
    fn tampered_message_fails() {
        let (sk, vk) = keypair();
        let sig = sign(b"original", &sk);
        assert!(verify(&sig, b"tampered", &vk).is_err());
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let (sk, _) = keypair();
        let s1 = sign(b"message one", &sk);
        let s2 = sign(b"message two", &sk);
        assert_ne!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn empty_message_can_be_signed_and_verified() {
        let (sk, vk) = keypair();
        let sig = sign(b"", &sk);
        assert!(verify(&sig, b"", &vk).is_ok());
    }

    #[test]
    fn large_message_roundtrip() {
        let (sk, vk) = keypair();
        let big = vec![0xCC_u8; 1024 * 1024]; // 1 MB
        let sig = sign(&big, &sk);
        assert!(verify(&sig, &big, &vk).is_ok());
    }
}
