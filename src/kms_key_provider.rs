use async_trait::async_trait;
use aws_sdk_kms::model::DataKeySpec;
use aws_sdk_kms::types::Blob;
use aws_sdk_kms::Client;

use crate::async_key_provider::AsyncKeyProvider;
use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::DataKey;
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::Key;

pub struct KMSKeyProvider {
    key_id: String,
    client: Client,
}

impl KMSKeyProvider {
    pub fn new(client: Client, key_id: impl Into<String>) -> Self {
        Self {
            client,
            key_id: key_id.into(),
        }
    }
}

#[async_trait(?Send)]
impl AsyncKeyProvider for KMSKeyProvider {
    async fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
        let mut response = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(DataKeySpec::Aes128)
            .send()
            .await
            .map_err(|e| KeyGenerationError::Other(format!("{}", e)))?;

        let encrypted_key = response
            .ciphertext_blob
            .take()
            .ok_or_else(|| {
                KeyGenerationError::Other(String::from("Response did not contain encrypted key"))
            })?
            .into_inner();

        let key_id = response.key_id.ok_or_else(|| {
            KeyGenerationError::Other(String::from("Response did not contain key_id"))
        })?;

        let plaintext_blob = response.plaintext.ok_or_else(|| {
            KeyGenerationError::Other(String::from("Response did not contain key plaintext key"))
        })?;

        let key = Key::clone_from_slice(plaintext_blob.as_ref());

        Ok(DataKey {
            key,
            encrypted_key,
            key_id,
        })
    }

    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError> {
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(encrypted_key.clone()))
            .send()
            .await
            .map_err(|e| KeyDecryptionError::Other(format!("{}", e)));

        let plaintext_blob = response.plaintext().ok_or_else(|| {
            KeyDecryptionError::Other(String::from("Response did not contain plaintext key"))
        })?;

        Ok(Key::clone_from_slice(plaintext_blob.as_ref()))
    }
}
