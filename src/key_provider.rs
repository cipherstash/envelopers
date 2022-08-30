//! Trait for a KeyProvider

use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::Key;
use async_trait::async_trait;
use zeroize::Zeroize;

use crate::errors::{KeyDecryptionError, KeyGenerationError};

#[derive(Debug, Clone, Zeroize)]
pub struct DataKey {
    pub key: Key<U16>,
    // TODO: Maybe make a type for EncryptedKey
    pub encrypted_key: Vec<u8>,
    pub key_id: String,
}

#[async_trait(?Send)]
pub trait KeyProvider {
    async fn generate_data_key(&self, bytes: usize) -> Result<DataKey, KeyGenerationError>;
    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError>;
}

#[async_trait(?Send)]
impl KeyProvider for Box<dyn KeyProvider> {
    async fn generate_data_key(&self, bytes: usize) -> Result<DataKey, KeyGenerationError> {
        (**self).generate_data_key(bytes).await
    }

    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError> {
        (**self).decrypt_data_key(encrypted_key).await
    }
}
