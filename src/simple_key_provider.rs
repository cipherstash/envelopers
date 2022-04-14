//! Trait for a KeyProvider

use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or `Aes256Gcm`
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

        // FIXME: Don't use a fixed nonce
        let nonce = Nonce::from_slice(b"unique bonce");
        let data_key = cipher.decrypt(
            nonce,
            Payload {
                msg: encrypted_key,
                aad: b"",
            },
        )?;

        return Ok(*Key::from_slice(&data_key));
    }

    async fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
        let key = Key::from_slice(&self.kek);
        let cipher = Aes128Gcm::new(key);
        let mut data_key: Key<U16> = Default::default();

        self.rng.borrow_mut().try_fill_bytes(&mut data_key)?;

        // FIXME: Don't use a fixed nonce
        let nonce = Nonce::from_slice(b"unique bonce");

        let payload = Payload {
            msg: &data_key,
            aad: b"",
        };

        let ciphertext = cipher.encrypt(nonce, payload)?;

        return Ok(DataKey {
            key: data_key,
            encrypted_key: ciphertext,
            key_id: String::from("simplekey"),
        });
    }
}

#[cfg(test)]
mod tests {
    use tokio;

    use crate::{key_provider::DataKey, KeyProvider, SimpleKeyProvider};

    #[tokio::test]
    async fn test_generate_decrypt_data_key() {
        let provider: SimpleKeyProvider =
            SimpleKeyProvider::init([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

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
}
