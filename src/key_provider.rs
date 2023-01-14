//! Trait for a KeyProvider

use aes_gcm::{Key, KeySizeUser};
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
pub trait KeyProvider: Send + Sync {
    type Cipher: KeySizeUser;

    /// Generate a [`DataKey`] to encrypt a specific number of bytes
    ///
    /// # Arguments
    ///
    /// * `bytes_to_encrypt` - The number of bytes that this key will be used to encrypt
    ///
    async fn generate_data_key(
        &self,
        bytes_to_encrypt: usize,
    ) -> Result<DataKey<Self::Cipher>, KeyGenerationError>;

    /// Decrypt an encrypted key and return the plaintext key
    async fn decrypt_data_key(
        &self,
        encrypted_key: &[u8],
    ) -> Result<Key<Self::Cipher>, KeyDecryptionError>;

    async fn generate_data_key_with_aad(
        &self,
        aad: &str,
        bytes_to_encrypt: usize,
    ) -> Result<DataKey<Self::Cipher>, KeyGenerationError>;

    async fn decrypt_data_key_with_aad(
        &self,
        aad: &str,
        encrypted_key: &[u8],
    ) -> Result<Key<Self::Cipher>, KeyDecryptionError>;
}

#[async_trait]
impl<S: KeySizeUser> KeyProvider for Box<dyn KeyProvider<Cipher = S>> {
    type Cipher = S;

    async fn generate_data_key(
        &self,
        bytes_to_encrypt: usize,
    ) -> Result<DataKey<S>, KeyGenerationError> {
        (**self).generate_data_key(bytes_to_encrypt).await
    }

    async fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Key<S>, KeyDecryptionError> {
        (**self).decrypt_data_key(encrypted_key).await
    }

    async fn generate_data_key_with_aad(
        &self,
        _aad: &str,
        _bytes_to_encrypt: usize,
    ) -> Result<DataKey<Self::Cipher>, KeyGenerationError> {
        todo!()
    }

    async fn decrypt_data_key_with_aad(
        &self,
        _aad: &str,
        _encrypted_key: &[u8],
    ) -> Result<Key<Self::Cipher>, KeyDecryptionError> {
        todo!()
    }
}
