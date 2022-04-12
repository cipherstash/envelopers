//! Trait for a KeyProvider

use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or `Aes256Gcm`
use async_trait::async_trait;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::cell::RefCell;

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::AsyncKeyProvider;

#[derive(Debug)]
pub struct DataKey {
    pub key: Key<U16>,
    // TODO: Maybe make a type for EncryptedKey
    pub encrypted_key: Vec<u8>,
    pub key_id: String,
}

pub trait KeyProvider {
    fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError>;
    fn decrypt_data_key(&self, encrypted_key: &Vec<u8>) -> Result<Key<U16>, KeyDecryptionError>;
}

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

impl<R: SeedableRng + RngCore> KeyProvider for SimpleKeyProvider<R> {
    fn decrypt_data_key(&self, encrypted_key: &Vec<u8>) -> Result<Key<U16>, KeyDecryptionError> {
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

    fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
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

#[async_trait(?Send)]
impl AsyncKeyProvider for dyn KeyProvider {
    async fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
        KeyProvider::generate_data_key(self)
    }

    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError> {
        KeyProvider::decrypt_data_key(self, encrypted_key)
    }
}
