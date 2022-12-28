//! Trait for a KeyProvider

use aes_gcm::aes::cipher::{consts::U16, generic_array::ArrayLength};
use aes_gcm::Key;
use async_trait::async_trait;
use zeroize::Zeroize;

use crate::errors::{KeyDecryptionError, KeyGenerationError};

#[derive(Debug, Clone, Zeroize)]
pub struct DataKey<S: ArrayLength<u8>> {
    pub key: Key<S>,
    // TODO: Maybe make a type for EncryptedKey
    pub encrypted_key: Vec<u8>,
    pub key_id: String,
}

#[async_trait]
pub trait KeyProvider<S: ArrayLength<u8> = U16>: Send + Sync {
    /// Generate a [`DataKey`] to encrypt a specific number of bytes
    ///
    /// # Arguments
    ///
    /// * `bytes_to_encrypt` - The number of bytes that this key will be used to encrypt
    ///
    async fn generate_data_key(
        &self,
        bytes_to_encrypt: usize,
    ) -> Result<DataKey<S>, KeyGenerationError>;

    /// Decrypt an encrypted key and return the plaintext key
    async fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Key<S>, KeyDecryptionError>;
}

#[async_trait]
impl<S: ArrayLength<u8>> KeyProvider<S> for Box<dyn KeyProvider<S>> {
    async fn generate_data_key(
        &self,
        bytes_to_encrypt: usize,
    ) -> Result<DataKey<S>, KeyGenerationError> {
        (**self).generate_data_key(bytes_to_encrypt).await
    }

    async fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Key<S>, KeyDecryptionError> {
        (**self).decrypt_data_key(encrypted_key).await
    }
}
