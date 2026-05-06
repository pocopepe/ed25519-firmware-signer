use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;

use crate::crypto;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirmwareEntry {
    pub version: u32,
    pub timestamp: String,
    pub sha256: String,
    pub signature: String,
    pub size_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FirmwareManifest {
    pub firmware_name: String,
    pub public_key: String,
    pub entries: Vec<FirmwareEntry>,
}

impl FirmwareManifest {
    pub fn new(firmware_name: String, public_key_hex: String) -> Self {
        FirmwareManifest {
            firmware_name,
            public_key: public_key_hex,
            entries: Vec::new(),
        }
    }

    pub fn load_or_new(path: &Path, firmware_name: &str, public_key_hex: &str) -> io::Result<Self> {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str(&data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        } else {
            Ok(FirmwareManifest::new(
                firmware_name.to_string(),
                public_key_hex.to_string(),
            ))
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::other(e.to_string()))?;
        std::fs::write(path, json)
    }

    pub fn firmware_changed(&self, firmware: &[u8]) -> bool {
        match self.entries.last() {
            Some(e) => compute_sha256(firmware) != e.sha256,
            None => true,
        }
    }

    pub fn append_entry(&mut self, firmware: &[u8], signing_key: &SigningKey) -> u32 {
        let version = self.entries.last().map(|e| e.version + 1).unwrap_or(1);
        self.entries.push(FirmwareEntry {
            version,
            timestamp: Utc::now().to_rfc3339(),
            sha256: compute_sha256(firmware),
            signature: hex::encode(crypto::sign(firmware, signing_key).to_bytes()),
            size_bytes: firmware.len() as u64,
        });
        version
    }

    pub fn verify_latest(&self, firmware: &[u8]) -> io::Result<&FirmwareEntry> {
        let entry = self
            .entries
            .last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "manifest has no entries"))?;
        self.verify_entry(firmware, entry)
    }

    pub fn verify_version(&self, firmware: &[u8], version: u32) -> io::Result<&FirmwareEntry> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.version == version)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("version {} not found in manifest", version),
                )
            })?;
        self.verify_entry(firmware, entry)
    }

    fn verify_entry<'a>(
        &self,
        firmware: &[u8],
        entry: &'a FirmwareEntry,
    ) -> io::Result<&'a FirmwareEntry> {
        let actual = compute_sha256(firmware);
        if actual != entry.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SHA256 mismatch for version {}.\n  expected: {}\n  got:      {}",
                    entry.version, entry.sha256, actual
                ),
            ));
        }

        let pubkey_bytes: [u8; 32] = hex::decode(&self.public_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .try_into()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "public key must be 32 bytes")
            })?;

        let vk = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let sig_bytes: [u8; 64] = hex::decode(&entry.signature)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .try_into()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "signature must be 64 bytes")
            })?;

        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        crypto::verify(&sig, firmware, &vk).map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("invalid signature for version {}: {}", entry.version, e),
            )
        })?;

        Ok(entry)
    }
}

pub fn compute_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn signed_manifest(firmware: &[u8]) -> (FirmwareManifest, SigningKey) {
        let sk = make_key();
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let mut m = FirmwareManifest::new("test.bin".into(), pk_hex);
        m.append_entry(firmware, &sk);
        (m, sk)
    }

    #[test]
    fn sha256_is_deterministic() {
        assert_eq!(compute_sha256(b"abc"), compute_sha256(b"abc"));
    }

    #[test]
    fn sha256_differs_for_different_inputs() {
        assert_ne!(compute_sha256(b"a"), compute_sha256(b"b"));
    }

    #[test]
    fn empty_manifest_always_reports_changed() {
        let m = FirmwareManifest::new("f.bin".into(), "".into());
        assert!(m.firmware_changed(b"anything"));
    }

    #[test]
    fn same_firmware_not_changed() {
        let (m, _) = signed_manifest(b"firmware v1");
        assert!(!m.firmware_changed(b"firmware v1"));
    }

    #[test]
    fn different_firmware_is_changed() {
        let (m, _) = signed_manifest(b"firmware v1");
        assert!(m.firmware_changed(b"firmware v2"));
    }

    #[test]
    fn append_increments_version() {
        let sk = make_key();
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let mut m = FirmwareManifest::new("f.bin".into(), pk_hex);
        assert_eq!(m.append_entry(b"v1", &sk), 1);
        assert_eq!(m.append_entry(b"v2", &sk), 2);
        assert_eq!(m.append_entry(b"v3", &sk), 3);
    }

    #[test]
    fn verify_latest_succeeds() {
        let firmware = b"firmware bytes";
        let (m, _) = signed_manifest(firmware);
        assert!(m.verify_latest(firmware).is_ok());
    }

    #[test]
    fn verify_latest_wrong_firmware_fails() {
        let (m, _) = signed_manifest(b"firmware bytes");
        assert!(m.verify_latest(b"different bytes").is_err());
    }

    #[test]
    fn verify_version_not_found_fails() {
        let (m, _) = signed_manifest(b"v1");
        assert!(m.verify_version(b"v1", 99).is_err());
    }

    #[test]
    fn verify_wrong_public_key_fails() {
        let firmware = b"firmware bytes";
        let sk = make_key();
        let wrong_pk = hex::encode(make_key().verifying_key().to_bytes());
        let mut m = FirmwareManifest::new("f.bin".into(), wrong_pk);
        m.append_entry(firmware, &sk);
        assert!(m.verify_latest(firmware).is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let firmware = b"roundtrip test";
        let (m, _) = signed_manifest(firmware);
        let path = std::env::temp_dir().join("binsign_manifest_roundtrip.json");
        m.save(&path).unwrap();
        let loaded = FirmwareManifest::load_or_new(&path, "", "").unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].sha256, compute_sha256(firmware));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_or_new_creates_fresh_when_file_missing() {
        let path = std::env::temp_dir().join("binsign_nonexistent_manifest.json");
        let _ = std::fs::remove_file(&path); // ensure it doesn't exist
        let m = FirmwareManifest::load_or_new(&path, "fw.bin", "aabbcc").unwrap();
        assert_eq!(m.firmware_name, "fw.bin");
        assert_eq!(m.public_key, "aabbcc");
        assert!(m.entries.is_empty());
    }

    #[test]
    fn load_bad_json_fails() {
        let path = std::env::temp_dir().join("binsign_bad.json");
        std::fs::write(&path, b"not json at all {{{{").unwrap();
        assert!(FirmwareManifest::load_or_new(&path, "", "").is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_specific_version_succeeds() {
        let sk = make_key();
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let mut m = FirmwareManifest::new("f.bin".into(), pk_hex);
        m.append_entry(b"v1 firmware", &sk);
        m.append_entry(b"v2 firmware", &sk);
        assert!(m.verify_version(b"v1 firmware", 1).is_ok());
        assert!(m.verify_version(b"v2 firmware", 2).is_ok());
    }

    #[test]
    fn verify_latest_on_empty_manifest_fails() {
        let m = FirmwareManifest::new("f.bin".into(), "".into());
        assert!(m.verify_latest(b"anything").is_err());
    }

    #[test]
    fn sha256_of_empty_input_is_stable() {
        let empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(compute_sha256(b""), empty_sha256);
    }

    #[test]
    fn entry_sha256_matches_firmware() {
        let firmware = b"check the stored hash";
        let (m, _) = signed_manifest(firmware);
        assert_eq!(m.entries[0].sha256, compute_sha256(firmware));
    }

    #[test]
    fn corrupted_signature_in_entry_fails() {
        let firmware = b"good firmware";
        let (mut m, _) = signed_manifest(firmware);
        // Flip one character in the stored signature hex.
        let bad_sig = m.entries[0].signature.replace('a', "f");
        m.entries[0].signature = bad_sig;
        assert!(m.verify_latest(firmware).is_err());
    }

    #[test]
    fn manifest_preserves_firmware_name() {
        let sk = make_key();
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let m = FirmwareManifest::new("bootloader_v2.bin".into(), pk_hex);
        assert_eq!(m.firmware_name, "bootloader_v2.bin");
    }

    #[test]
    fn latest_sha256_is_none_when_empty() {
        let m = FirmwareManifest::new("f.bin".into(), "".into());
        assert!(m.entries.last().is_none());
    }
}
