use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use argon2::{
    password_hash::{rand_core::OsRng as KdfOsRng, SaltString},
    Argon2, Params,
};
use rand::{rngs::OsRng, RngCore};
use std::io;
use typenum::U12;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

fn derive_key(password: &str, salt: &[u8]) -> io::Result<Key<Aes256Gcm>> {
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(1);

    let params = Params::new(1024 * 6, 2, parallelism, Some(KEY_LEN))
        .map_err(|e| io::Error::other(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key_bytes = [0u8; KEY_LEN];
    argon2
        .hash_password_into(
            password.as_bytes(),
            salt_string.as_str().as_bytes(),
            &mut key_bytes,
        )
        .map_err(|e| io::Error::other(e.to_string()))?;

    Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
}

pub fn encrypt_with_password(
    plaintext: &[u8],
    password: &str,
) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;

    let mut salt = [0u8; SALT_LEN];
    KdfOsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::<U12>::from_slice(&nonce_bytes);

    let key = derive_key(password, &salt)?;
    let ciphertext = Aes256Gcm::new(&key)
        .encrypt(nonce, plaintext)
        .map_err(|e| io::Error::other(e.to_string()))?;

    Ok((salt.to_vec(), nonce.to_vec(), ciphertext))
}

pub fn decrypt_with_password(data: &[u8], password: &str) -> io::Result<Vec<u8>> {
    let min_len = SALT_LEN + NONCE_LEN + TAG_LEN;
    if data.len() < min_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted data is too short or corrupted",
        ));
    }

    let salt = &data[0..SALT_LEN];
    let nonce = aes_gcm::Nonce::<U12>::from_slice(&data[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, salt)?;
    Aes256Gcm::new(&key)
        .decrypt(nonce, ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(password: &str) -> Vec<u8> {
        let plaintext = [0xAB_u8; 32];
        let (salt, nonce, ct) = encrypt_with_password(&plaintext, password).unwrap();
        let mut blob = salt;
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        decrypt_with_password(&blob, password).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        assert_eq!(roundtrip("hunter2"), [0xAB_u8; 32]);
    }

    #[test]
    fn wrong_password_fails() {
        let (salt, nonce, ct) = encrypt_with_password(&[1u8; 32], "correct").unwrap();
        let mut blob = salt;
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        assert!(decrypt_with_password(&blob, "wrong").is_err());
    }

    #[test]
    fn truncated_data_fails() {
        assert!(decrypt_with_password(&[0u8; 10], "password").is_err());
    }

    #[test]
    fn different_encryptions_of_same_data_produce_different_ciphertext() {
        // Each call generates a fresh random salt and nonce so output must differ.
        let (s1, n1, ct1) = encrypt_with_password(b"key", "pass").unwrap();
        let (s2, n2, ct2) = encrypt_with_password(b"key", "pass").unwrap();
        assert!(s1 != s2 || n1 != n2 || ct1 != ct2);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let (salt, nonce, ct) = encrypt_with_password(b"", "password").unwrap();
        let mut blob = salt;
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        assert_eq!(decrypt_with_password(&blob, "password").unwrap(), b"");
    }

    #[test]
    fn unicode_password_works() {
        let (salt, nonce, ct) = encrypt_with_password(&[0xAB; 32], "p@$$w🔐rd").unwrap();
        let mut blob = salt;
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        assert_eq!(
            decrypt_with_password(&blob, "p@$$w🔐rd").unwrap(),
            [0xAB; 32]
        );
    }
}
