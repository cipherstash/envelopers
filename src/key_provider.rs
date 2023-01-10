//! Trait for a KeyProvider

use aes_gcm::{Key, KeySizeUser};
use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{KeyDecryptionError, KeyGenerationError};

#[derive(Clone, Copy, Debug)]
pub struct GenerateKeySpec {
    pub bytes_to_encrypt: usize,
}

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
    /// * `spec` - [`GenerateKeySpec`] containing the number of bytes that this key will be used to encrypt
    ///
    async fn generate_data_key(
        &self,
        spec: GenerateKeySpec,
    ) -> Result<DataKey<Self::Cipher>, KeyGenerationError>;

    /// Decrypt an encrypted key and return the plaintext key
    async fn decrypt_data_key(
        &self,
        encrypted_key: &[u8],
    ) -> Result<Key<Self::Cipher>, KeyDecryptionError>;

    /// Generate multiple [`DataKey`] for a slice of [`GenerateKeySpec`]
    async fn generate_many_data_keys(
        &self,
        specs: &[GenerateKeySpec],
    ) -> Result<Vec<DataKey<Self::Cipher>>, KeyGenerationError> {
        let mut output = Vec::with_capacity(specs.len());

        for spec in specs {
            output.push(self.generate_data_key(*spec).await?);
        }

        Ok(output)
    }

    /// Decrypt multiple encrypted keys and return their plaintext keys
    async fn decrypt_many_data_keys(
        &self,
        encrypted_keys: &[Vec<u8>],
    ) -> Result<Vec<Key<Self::Cipher>>, KeyDecryptionError> {
        let mut output = Vec::with_capacity(encrypted_keys.len());

        for key in encrypted_keys {
            output.push(self.decrypt_data_key(key).await?);
        }

        Ok(output)
    }
}

#[async_trait]
impl<S: KeySizeUser> KeyProvider for Box<dyn KeyProvider<Cipher = S>> {
    type Cipher = S;

    async fn generate_data_key(
        &self,
        spec: GenerateKeySpec,
    ) -> Result<DataKey<S>, KeyGenerationError> {
        (**self).generate_data_key(spec).await
    }

    async fn decrypt_data_key(&self, encrypted_key: &[u8]) -> Result<Key<S>, KeyDecryptionError> {
        (**self).decrypt_data_key(encrypted_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::{GenerateKeySpec, KeyProvider};
    use crate::SimpleKeyProvider;

    #[tokio::test]
    async fn test_round_trip_many_keys() {
        let provider: SimpleKeyProvider = SimpleKeyProvider::init([1; 16]);

        let keys = provider
            .generate_many_data_keys(&vec![
                GenerateKeySpec {
                    bytes_to_encrypt: 100
                };
                100
            ])
            .await
            .expect("Failed to generate keys");

        let (keys, encrypted_keys): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .map(|key| (key.key, key.encrypted_key.clone()))
            .unzip();

        let decrypted_keys = provider
            .decrypt_many_data_keys(encrypted_keys.as_slice())
            .await
            .expect("Failed to decrypt keys");

        assert_ne!(keys[0], keys[1]);
        assert_eq!(keys, decrypted_keys);
    }
}
