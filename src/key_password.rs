use aes_gcm::{Aes256Gcm, Key};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Params, PasswordHasher, password_hash::{SaltString, rand_core::OsRng as KdfOsRng}};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io;
use typenum::U12;

//setting generics cause Nonce len really messed with me on the last push
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PRIVATE_KEY_LEN: usize = 32; //an average private key's of 32 bytes so far

fn derive_aes_key(password: &str, salt: &[u8]) -> io::Result<Key<Aes256Gcm>> {
    let salt_string = SaltString::b64_encode(salt)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid salt format for KDF: {}", e)))?;

    // Memory: 6MB, Iterations: 2, Parallelism: 2, Output Key Length: PRIVATE_KEY_LEN
    let argon2_params = Params::new(1024 * 6, 2, 2, Some(PRIVATE_KEY_LEN))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 parameter error: {}", e)))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0_19,
        argon2_params,
    );

    let mut derived_key_bytes = [0u8; PRIVATE_KEY_LEN]; // Buffer for the derived key
    argon2.hash_password_into(password.as_bytes(), &salt_string, &mut derived_key_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to derive key with Argon2: {}", e)))?;

    Ok(Key::<Aes256Gcm>::from_slice(&derived_key_bytes))
}

//does the actual aes itself, moved from crypto_logic to here
fn perform_aes_gcm_encryption(
    data_to_encrypt: &[u8],
    aes_encryption_key: &Key<Aes256Gcm>,
    rng: &mut OsRng,
) -> io::Result<(Vec<u8>, aes_gcm::Nonce<U12>)> {
    let cipher = Aes256Gcm::new(aes_encryption_key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::<U12>::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data_to_encrypt)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES-GCM encryption failed: {}", e)))?;

    Ok((ciphertext, nonce))
}

//takes user's password and private_key in bytes and returns  asalt, nonce, and cypher text
//all stored together for later decryption
pub fn encrypt_with_password(
    private_key_bytes: &[u8],
    password: &str,
) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng; //salt

    let mut salt_bytes = [0u8; SALT_LEN];
    KdfOsRng.fill_bytes(&mut salt_bytes); //argon 2 salt I need it seems :sob:

    let aes_encryption_key = derive_aes_key(password, &salt_bytes)?;

    let (ciphertext_with_tag, nonce) = perform_aes_gcm_encryption(
        private_key_bytes,
        &aes_encryption_key,
        &mut rng, 
    )?;

    Ok((salt_bytes.to_vec(), nonce.to_vec(), ciphertext_with_tag))
}