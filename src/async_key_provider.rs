use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::DataKey;
use async_trait::async_trait;

use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::Key;

#[async_trait(?Send)]
pub trait AsyncKeyProvider {
    async fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError>;
    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError>;
}
