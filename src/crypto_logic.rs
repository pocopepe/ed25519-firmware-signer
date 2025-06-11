use ed25519_dalek::{Signature, Signer, SigningKey};

pub fn sign(message: &[u8], signing_key: SigningKey) -> Signature {
    let signature = signing_key.sign(message);
    signature
}

