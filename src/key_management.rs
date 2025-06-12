use aes_gcm::{Aes256Gcm, Key};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Params, password_hash::{SaltString, rand_core::OsRng as KdfOsRng}};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io;
use typenum::U12; 

//keeping consistency using default consts
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; 
const PRIVATE_KEY_LEN: usize = 32; 
const TAG_LEN: usize = 16;


fn derive_aes_key(password: &str, salt: &[u8]) -> io::Result<Key<Aes256Gcm>> {
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid salt format for KDF: {}", e)))?;

    let num_cores = std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(1); 

    let argon2_params = Params::new(1024 * 6, 2, num_cores, Some(PRIVATE_KEY_LEN))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 parameter error: {}", e)))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut derived_key_bytes = [0u8; PRIVATE_KEY_LEN]; // Buffer for the derived key
    argon2.hash_password_into(password.as_bytes(), salt_string.as_str().as_bytes(), &mut derived_key_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to derive key with Argon2: {}", e)))?;

    Ok(*Key::<Aes256Gcm>::from_slice(&derived_key_bytes))
}


fn perform_aes_gcm_encryption(
    data_to_encrypt: &[u8],
    aes_encryption_key: &Key<Aes256Gcm>,
    rng: &mut OsRng,
) -> io::Result<(Vec<u8>, aes_gcm::Nonce<U12>)> {
    let cipher = Aes256Gcm::new(aes_encryption_key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::<U12>::from_slice(&nonce_bytes); // Creates an owned Nonce

    let cloned_nonce = nonce.clone();

    let ciphertext = cipher.encrypt(nonce, data_to_encrypt) // `nonce` is moved (consumed) here
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES-GCM encryption failed: {}", e)))?;

    Ok((ciphertext, cloned_nonce)) 
}

fn perform_aes_gcm_decryption(
    ciphertext_with_tag: &[u8],
    aes_decryption_key: &Key<Aes256Gcm>,
    nonce: &aes_gcm::Nonce<U12>,
) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(aes_decryption_key);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext_with_tag)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("AES-GCM decryption failed: {}", e)))?;

    Ok(decrypted_bytes)
}

pub fn encrypt_with_password(
    private_key_bytes: &[u8],
    password: &str,
) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng; 

    let mut salt_bytes = [0u8; SALT_LEN];
    KdfOsRng.fill_bytes(&mut salt_bytes); 

    let aes_encryption_key = derive_aes_key(password, &salt_bytes)?;

    let (ciphertext_with_tag, nonce) = perform_aes_gcm_encryption(
        private_key_bytes,
        &aes_encryption_key,
        &mut rng,
    )?;

    Ok((salt_bytes.to_vec(), nonce.to_vec(), ciphertext_with_tag))
}



pub fn decrypt_with_password(
    encrypted_data_from_file: &[u8],
    password: &str,
) -> io::Result<Vec<u8>> {
    if encrypted_data_from_file.len() < SALT_LEN + NONCE_LEN + PRIVATE_KEY_LEN + TAG_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
                                   "Encrypted data is too short or corrupted."));
    }
    let salt_bytes = &encrypted_data_from_file[0..SALT_LEN];
    let nonce_bytes = &encrypted_data_from_file[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext_with_tag = &encrypted_data_from_file[(SALT_LEN + NONCE_LEN)..];

    let nonce = aes_gcm::Nonce::<U12>::from_slice(nonce_bytes);
    let aes_decryption_key = derive_aes_key(password, salt_bytes)?;

    let decrypted_private_key_bytes = perform_aes_gcm_decryption(
        ciphertext_with_tag,
        &aes_decryption_key,
        &nonce,
    )?;
        //one final check before I return
    if decrypted_private_key_bytes.len() != PRIVATE_KEY_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Decrypted key has incorrect length. File might be corrupted or password incorrect."));
    }

    Ok(decrypted_private_key_bytes)
}