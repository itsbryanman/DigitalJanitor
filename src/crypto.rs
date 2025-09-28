use crate::{Error, Result, AES_KEY_SIZE, AES_NONCE_SIZE};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: [u8; AES_NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CryptoKey {
    inner: [u8; AES_KEY_SIZE],
}

impl CryptoKey {
    pub fn new(key: [u8; AES_KEY_SIZE]) -> Self {
        Self { inner: key }
    }

    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| Error::encryption(format!("Failed to encode salt: {}", e)))?;

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| Error::encryption(format!("Failed to hash password: {}", e)))?;

        let hash = password_hash.hash.unwrap();
        let hash_bytes = hash.as_bytes();
        if hash_bytes.len() < AES_KEY_SIZE {
            return Err(Error::encryption("Password hash too short"));
        }

        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(&hash_bytes[..AES_KEY_SIZE]);
        Ok(Self::new(key))
    }

    pub fn random() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        getrandom::getrandom(&mut key).expect("Failed to generate random key");
        Self::new(key)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.inner));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| Error::encryption(format!("Encryption failed: {}", e)))?;

        Ok(EncryptedData {
            nonce: nonce.as_slice().try_into().unwrap(),
            ciphertext,
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.inner));
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| Error::decryption(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub salt: Vec<u8>,
    pub encrypted_repo_key: EncryptedData,
    pub encrypted_mac_key: EncryptedData,
    pub version: u32,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory: 65536, // 64MB
            iterations: 3,
            parallelism: 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepositoryKeys {
    pub encryption_key: CryptoKey,
    pub mac_key: CryptoKey,
}

impl Default for RepositoryKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl RepositoryKeys {
    pub fn new() -> Self {
        Self {
            encryption_key: CryptoKey::random(),
            mac_key: CryptoKey::random(),
        }
    }

    pub fn encrypt_with_password(&self, password: &str) -> Result<KeyFile> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|e| Error::encryption(format!("Failed to generate salt: {}", e)))?;

        let master_key = CryptoKey::from_password(password, &salt)?;

        let encrypted_repo_key = master_key.encrypt(self.encryption_key.as_bytes())?;
        let encrypted_mac_key = master_key.encrypt(self.mac_key.as_bytes())?;

        Ok(KeyFile {
            salt: salt.to_vec(),
            encrypted_repo_key,
            encrypted_mac_key,
            version: 1,
            kdf_params: KdfParams::default(),
        })
    }

    pub fn decrypt_from_keyfile(keyfile: &KeyFile, password: &str) -> Result<Self> {
        let master_key = CryptoKey::from_password(password, &keyfile.salt)?;

        let repo_key_bytes = master_key.decrypt(&keyfile.encrypted_repo_key)?;
        let mac_key_bytes = master_key.decrypt(&keyfile.encrypted_mac_key)?;

        if repo_key_bytes.len() != AES_KEY_SIZE || mac_key_bytes.len() != AES_KEY_SIZE {
            return Err(Error::decryption("Invalid key length"));
        }

        let mut repo_key = [0u8; AES_KEY_SIZE];
        let mut mac_key = [0u8; AES_KEY_SIZE];
        repo_key.copy_from_slice(&repo_key_bytes);
        mac_key.copy_from_slice(&mac_key_bytes);

        Ok(Self {
            encryption_key: CryptoKey::new(repo_key),
            mac_key: CryptoKey::new(mac_key),
        })
    }
}

pub struct StreamCipher {
    key: CryptoKey,
}

impl StreamCipher {
    pub fn new(key: CryptoKey) -> Self {
        Self { key }
    }

    pub fn encrypt_chunk(&mut self, data: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_bytes()));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| Error::encryption(format!("Chunk encryption failed: {}", e)))?;

        Ok(EncryptedData {
            nonce: nonce.as_slice().try_into().unwrap(),
            ciphertext,
        })
    }

    pub fn decrypt_chunk(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_bytes()));
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| Error::decryption(format!("Chunk decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

pub fn verify_password_strength(password: &str) -> Result<()> {
    if password.len() < 12 {
        return Err(Error::validation(
            "Password must be at least 12 characters long",
        ));
    }

    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let mut strength_score = 0;
    if has_lowercase {
        strength_score += 1;
    }
    if has_uppercase {
        strength_score += 1;
    }
    if has_digit {
        strength_score += 1;
    }
    if has_special {
        strength_score += 1;
    }

    if strength_score < 3 {
        return Err(Error::validation(
            "Password must contain at least 3 of: lowercase, uppercase, digits, special characters",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_key_generation() {
        let key1 = CryptoKey::random();
        let key2 = CryptoKey::random();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encryption_decryption() {
        let key = CryptoKey::random();
        let plaintext = b"Hello, World!";

        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_password_derivation() {
        let password = "test_password_123";
        let salt = b"test_salt_32_bytes_long_padding";

        let key1 = CryptoKey::from_password(password, salt).unwrap();
        let key2 = CryptoKey::from_password(password, salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_repository_keys() {
        let keys = RepositoryKeys::new();
        let password = "strong_password_123!";

        let keyfile = keys.encrypt_with_password(password).unwrap();
        let restored_keys = RepositoryKeys::decrypt_from_keyfile(&keyfile, password).unwrap();

        assert_eq!(
            keys.encryption_key.as_bytes(),
            restored_keys.encryption_key.as_bytes()
        );
        assert_eq!(keys.mac_key.as_bytes(), restored_keys.mac_key.as_bytes());
    }
}
