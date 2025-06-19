use aes_gcm::{Aes256Gcm, Key};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Params, password_hash::{SaltString, rand_core::OsRng as KdfOsRng}};
use rand::rngs::OsRng;
use rand::RngCore; // Needed for rng.fill_bytes
use std::io;
use typenum::U12; // For the 12-byte Nonce type

//just a massive ai slop ahead

// --- Constants for the encryption/decryption format ---
// These are crucial and must match between encryption and decryption logic.
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // GCM nonces are 12 bytes
const PRIVATE_KEY_LEN: usize = 32; // Ed25519 private key length (plaintext)
const TAG_LEN: usize = 16; // AES-GCM authentication tag length (added by GCM itself)


// --- Private Helper: Derive AES Key from Password and Salt ---
/// Derives a 32-byte AES-256 key using Argon2id from a password and salt.
/// This function is private to this module.
fn derive_aes_key(password: &str, salt: &[u8]) -> io::Result<Key<Aes256Gcm>> {
    let salt_string = SaltString::encode_b64(salt) // Use `encode_b64` as per deprecation warning
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid salt format for KDF: {}", e)))?;

    // Parallelism based on available cores for better performance
    let num_cores = std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(1); // Fallback to 1 if detection fails or unavailable

    // Argon2 parameters (Memory: 6MB, Iterations: 2, Parallelism: num_cores, Output Key Length: 32 bytes)
    let argon2_params = Params::new(1024 * 6, 2, num_cores, Some(PRIVATE_KEY_LEN))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 parameter error: {}", e)))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13, // Using V0x13 as it worked for your specific setup
        argon2_params,
    );

    let mut derived_key_bytes = [0u8; PRIVATE_KEY_LEN]; // Buffer for the derived key
    argon2.hash_password_into(password.as_bytes(), salt_string.as_str().as_bytes(), &mut derived_key_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to derive key with Argon2: {}", e)))?;

    // This dereference (*) is included as per your compiler's insistent suggestion.
    // In a typical setup with up-to-date dependencies, `Key::from_slice` directly returns an owned value.
    Ok(*Key::<Aes256Gcm>::from_slice(&derived_key_bytes))
}

// --- Private Helper: Perform AES-GCM Encryption ---
/// Performs AES-256-GCM encryption on the given data using the provided key and a newly generated nonce.
/// This function is private to this module.
fn perform_aes_gcm_encryption(
    data_to_encrypt: &[u8],
    aes_encryption_key: &Key<Aes256Gcm>,
    rng: &mut OsRng,
) -> io::Result<(Vec<u8>, aes_gcm::Nonce<U12>)> {
    let cipher = Aes256Gcm::new(aes_encryption_key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::<U12>::from_slice(&nonce_bytes);

    // Clone `nonce` before moving it into `cipher.encrypt` so it can be returned.
    let cloned_nonce = nonce.clone();

    let ciphertext = cipher.encrypt(nonce, data_to_encrypt) // `nonce` is moved (consumed) here
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES-GCM encryption failed: {}", e)))?;

    Ok((ciphertext, cloned_nonce)) // Return the cloned nonce
}

// --- Private Helper: Perform AES-GCM Decryption ---
/// Performs AES-256-GCM decryption on the given ciphertext using the provided key and nonce.
/// This function is private to this module.
fn perform_aes_gcm_decryption(
    ciphertext_with_tag: &[u8],
    aes_decryption_key: &Key<Aes256Gcm>,
    nonce: &aes_gcm::Nonce<U12>, // Expects a reference to the Nonce
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
    // 1. Validate length of encrypted data
    // Minimum expected length: SALT_LEN + NONCE_LEN + PRIVATE_KEY_LEN (ciphertext) + TAG_LEN (authentication tag)
    if encrypted_data_from_file.len() < SALT_LEN + NONCE_LEN + PRIVATE_KEY_LEN + TAG_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
                                   "Encrypted data is too short or corrupted."));
    }

    // 2. Parse the file content: Extract salt, nonce, and ciphertext
    let salt_bytes = &encrypted_data_from_file[0..SALT_LEN];
    let nonce_bytes = &encrypted_data_from_file[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext_with_tag = &encrypted_data_from_file[(SALT_LEN + NONCE_LEN)..];

    // Create the Nonce object from its bytes
    let nonce = aes_gcm::Nonce::<U12>::from_slice(nonce_bytes);

    // 3. Derive AES decryption key from password and salt
    let aes_decryption_key = derive_aes_key(password, salt_bytes)?;

    // 4. Perform AES-GCM decryption
    let decrypted_private_key_bytes = perform_aes_gcm_decryption(
        ciphertext_with_tag,
        &aes_decryption_key,
        &nonce, // Pass a reference to the Nonce
    )?;

    // 5. Verify decrypted length (optional but good sanity check)
    if decrypted_private_key_bytes.len() != PRIVATE_KEY_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Decrypted key has incorrect length. File might be corrupted or password incorrect."));
    }

    Ok(decrypted_private_key_bytes)
}