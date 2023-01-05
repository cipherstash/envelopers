//! Trait for a KeyProvider

use aes_gcm::Key;
use aes_gcm::KeySizeUser;
use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{KeyDecryptionError, KeyGenerationError};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataKey<S: KeySizeUser> {
    pub key: Key<S>,
    // TODO: Maybe make a type for EncryptedKey
    pub encrypted_key: Vec<u8>,
    pub key_id: String,
}

#[async_trait]
pub trait KeyProvider<S: KeySizeUser>: Send + Sync {
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
impl<S: KeySizeUser> KeyProvider<S> for Box<dyn KeyProvider<S>> {
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
