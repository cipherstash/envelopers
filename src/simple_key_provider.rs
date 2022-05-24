//! Trait for a KeyProvider

use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::aes::cipher::consts::{U12, U16};
use aes_gcm::{Aes128Gcm, Key}; // Or `Aes256Gcm`
use async_trait::async_trait;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::cell::RefCell;

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::{DataKey, KeyProvider};

#[derive(Debug)]
pub struct SimpleKeyProvider<R: SeedableRng + RngCore = ChaChaRng> {
    kek: [u8; 16],
    rng: RefCell<R>,
}

// EncryptedSimpleKey relies on this size being constant. If this ever needs to be changed a new
// version of EncryptedSimpleKey needs to be created.
type Nonce = aes_gcm::Nonce<U12>;
const NONCE_SIZE: usize = 12;

/// A decoded intermediate representation of an encrypted simple key
///
/// The data this struct is created from exists in memory like so:
///
/// | Pos  | Data                   |
/// | -----|------------------------|
/// | 0    | Version tag (1 byte)   |
/// | 1-13 | Nonce       (12 bytes) |
/// | 13-  | Encrypted key          |
#[derive(Debug)]
struct EncryptedSimpleKey<'a> {
    // Keep a version tag on the key just in case the format gets changed
    // This could have other header information - but it should be safe since we're only expected
    // keys created by the SimpleKeyProvider.
    version: u8,
    nonce: &'a Nonce,
    key: &'a [u8],
}

impl<'a> EncryptedSimpleKey<'a> {
    fn from_slice(bytes: &'a [u8]) -> Result<Self, KeyDecryptionError> {
        if bytes.len() < 1 + NONCE_SIZE {
            return Err(KeyDecryptionError::Other(format!(
                "Slice was too small to load an EncryptedSimpleKey. Received: {}",
                bytes.len()
            )));
        }

        let version = bytes[0];

        if version != 1 {
            return Err(KeyDecryptionError::Other(format!(
                "EncryptedSimpleKey version tag was invalid. Received: {}",
                version
            )));
        }

        let nonce: &'a Nonce = Nonce::from_slice(&bytes[1..1 + NONCE_SIZE]);
        let key: &'a [u8] = &bytes[1 + NONCE_SIZE..];

        Ok(Self {
            version,
            nonce,
            key,
        })
    }

    fn to_vec(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1 + self.nonce.len() + self.key.len());
        output.push(self.version);
        output.extend_from_slice(self.nonce);
        output.extend_from_slice(self.key);
        output
    }
}

impl<R: SeedableRng + RngCore> SimpleKeyProvider<R> {
    pub fn init(kek: [u8; 16]) -> Self {
        Self {
            kek,
            rng: RefCell::new(R::from_entropy()),
        }
    }
}

#[async_trait(?Send)]
impl<R: SeedableRng + RngCore> KeyProvider for SimpleKeyProvider<R> {
    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError> {
        let key = Key::from_slice(&self.kek);
        let cipher = Aes128Gcm::new(key);

        let decoded_key = EncryptedSimpleKey::from_slice(&encrypted_key)?;

        let data_key = cipher.decrypt(
            decoded_key.nonce,
            Payload {
                msg: decoded_key.key,
                aad: b"",
            },
        )?;

        return Ok(*Key::from_slice(&data_key));
    }

    async fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
        let key = Key::from_slice(&self.kek);
        let cipher = Aes128Gcm::new(key);

        let mut data_key: Key<U16> = Default::default();
        let mut nonce: Nonce = Default::default();

        let mut rng = self.rng.borrow_mut();
        rng.try_fill_bytes(&mut data_key)?;
        rng.try_fill_bytes(&mut nonce)?;

        let payload = Payload {
            msg: &data_key,
            aad: b"",
        };

        let ciphertext = cipher.encrypt(&nonce, payload)?;

        let encrypted_key = EncryptedSimpleKey {
            version: 1,
            key: &ciphertext,
            nonce: &nonce,
        };

        return Ok(DataKey {
            key: data_key,
            encrypted_key: encrypted_key.to_vec(),
            key_id: String::from("simplekey"),
        });
    }
}

#[cfg(test)]
mod tests {
    use tokio;

    use super::{EncryptedSimpleKey, Nonce};
    use crate::{key_provider::DataKey, KeyProvider, SimpleKeyProvider};

    fn create_provider() -> SimpleKeyProvider {
        SimpleKeyProvider::init([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    }

    #[tokio::test]
    async fn test_generate_decrypt_data_key() {
        let provider = create_provider();

        let DataKey {
            encrypted_key, key, ..
        } = provider.generate_data_key().await.unwrap();

        assert_eq!(
            key,
            provider.decrypt_data_key(&encrypted_key).await.unwrap()
        );
    }

    #[tokio::test]
    async fn test_generate_decrypt_data_key_boxed() {
        let provider: Box<dyn KeyProvider> = Box::new(create_provider());

        let DataKey {
            encrypted_key, key, ..
        } = provider.generate_data_key().await.unwrap();

        assert_eq!(
            key,
            provider.decrypt_data_key(&encrypted_key).await.unwrap()
        );
    }

    #[tokio::test]
    async fn test_fails_on_invalid_data_key() {
        let first: SimpleKeyProvider = SimpleKeyProvider::init([0; 16]);

        let second: SimpleKeyProvider = SimpleKeyProvider::init([1; 16]);

        let DataKey { encrypted_key, .. } = first.generate_data_key().await.unwrap();

        assert_eq!(
            second
                .decrypt_data_key(&encrypted_key)
                .await
                .map_err(|e| e.to_string())
                .expect_err("Decrypting data key suceeded"),
            "failed to decrypt key"
        );
    }

    #[test]
    fn test_load_encrypted_key_from_slice() {
        let slice: Vec<u8> = vec![
            1, // version
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // nonce
            1, 2, 3, 4, 5, 6, // encrypted key (size is unknown)
        ];

        let key = EncryptedSimpleKey::from_slice(&slice).unwrap();

        assert_eq!(key.version, 1);
        assert_eq!(
            key.nonce,
            Nonce::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        );
        assert_eq!(key.key, &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_fails_on_invalid_version() {
        let slice: Vec<u8> = vec![
            5, // version
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // nonce
            1, 2, 3, 4, 5, 6, // encrypted key (size is unknown)
        ];

        let err =
            EncryptedSimpleKey::from_slice(&slice).expect_err("Encrypted key decode succeeded");

        assert_eq!(
            err.to_string(),
            "EncryptedSimpleKey version tag was invalid. Received: 5"
        );
    }

    #[test]
    fn test_fails_on_tiny_slice() {
        let slice: Vec<u8> = vec![5, 1, 2, 3, 4, 5, 6];

        let err =
            EncryptedSimpleKey::from_slice(&slice).expect_err("Encrypted key decode succeeded");

        assert_eq!(
            err.to_string(),
            "Slice was too small to load an EncryptedSimpleKey. Received: 7"
        );
    }

    #[test]
    fn test_seriailze_key() {
        let version = 1;
        let nonce = Nonce::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let key = &[1, 2, 3, 4, 5, 6];

        let encrypted_key = EncryptedSimpleKey {
            version,
            nonce,
            key,
        };

        let bytes = encrypted_key.to_vec();

        assert_eq!(
            bytes,
            vec![
                1, // version
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // nonce
                1, 2, 3, 4, 5, 6, // encrypted key (size is unknown)
            ]
        );
    }
}
