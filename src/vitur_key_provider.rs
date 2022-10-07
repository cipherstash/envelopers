//! Trait for a KeyProvider


use aes_gcm::aes::cipher::consts::U16;

use aes_gcm::{Key};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::{DataKey, KeyProvider};
use base64::{decode_config, encode_config};

#[derive(Deserialize)]
struct ViturDataKeyPair {
    dk: String,
    wdk: String
}

#[derive(Serialize)]
pub struct ViturEncryptedDataKey {
    data_key: String // TODO: Change this to wdk
}

#[derive(Deserialize, Debug)]
pub struct ViturDataKey {
    dk: String
}

#[derive(Debug)]
pub struct ViturKeyProvider {
    host: String,
    key_id: String
}

impl ViturKeyProvider {
    pub fn new(host: String, key_id: String) -> Self {
        Self { key_id, host }
    }
}

#[async_trait(?Send)]
impl KeyProvider for ViturKeyProvider {
    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError> {

        let client = reqwest::Client::new();

        let vdk = ViturEncryptedDataKey {
            data_key: encode_config(&encrypted_key, base64::URL_SAFE_NO_PAD)
        };

        let res = client.post(format!("{}/api/keys/{}/decrypt", self.host, self.key_id))
            .json(&vdk)
            .send()
            .await.unwrap();

        let dk: ViturDataKey = res.json().await.unwrap();
        let decoded = decode_config(&dk.dk, base64::URL_SAFE_NO_PAD).unwrap();

        return Ok(*Key::from_slice(&decoded));
    }

    async fn generate_data_key(&self, _bytes: usize) -> Result<DataKey, KeyGenerationError> {

        let client = reqwest::Client::new();

        let res = client.post(format!("{}/api/keys/{}/gen-data-key", self.host, self.key_id))
            .send()
            .await.unwrap();

        // TODO: We probably should use a fast binary format instead of JSON but 🤪
        let dkp: ViturDataKeyPair = res.json().await.unwrap();
        
        return Ok(DataKey {
            key: *Key::from_slice(&decode_config(dkp.dk, base64::URL_SAFE_NO_PAD).unwrap()),
            encrypted_key: decode_config(dkp.wdk, base64::URL_SAFE_NO_PAD).unwrap(),
            key_id: self.key_id.to_string(),
        });
    }
}




