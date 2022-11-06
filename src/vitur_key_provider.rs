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
struct DataKeyRequest {
    tag: String
}

#[derive(Serialize)]
pub struct DecryptRequest {
    wdk: String,
    context: Option<String>
}

#[derive(Deserialize, Debug)]
pub struct ViturDataKey {
    dk: String
}

#[derive(Debug)]
pub struct ViturKeyProvider {
    host: String,
    key_id: String,
    access_token: String
}

impl ViturKeyProvider {
    pub fn new(host: String, key_id: String, access_token: String) -> Self {
        Self { key_id, host, access_token }
    }
}

#[async_trait]
impl KeyProvider for ViturKeyProvider {
    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
        context: Option<String>
    ) -> Result<Key<U16>, KeyDecryptionError> {

        let client = reqwest::Client::new();

        let vdk = DecryptRequest {
            wdk: encode_config(&encrypted_key, base64::URL_SAFE_NO_PAD),
            context
        };

        let res = client.post(format!("{}/api/keys/{}/decrypt", self.host, self.key_id))
            .json(&vdk)
            .bearer_auth(&self.access_token)
            .send()
            .await.unwrap();

        let dk: ViturDataKey = res.json().await.unwrap();
        let decoded = decode_config(&dk.dk, base64::URL_SAFE_NO_PAD).unwrap();

        return Ok(*Key::from_slice(&decoded));
    }

    async fn generate_data_key(&self, _bytes: usize, tag: &Option<String>) -> Result<DataKey, KeyGenerationError> {
        let client = reqwest::Client::new();
        let data_key_request = DataKeyRequest {
            tag: tag.as_ref().ok_or("Tag must be provided").unwrap().to_string()
        };
        let res = client.post(format!("{}/api/keys/{}/gen-data-key", self.host, self.key_id))
            .json(&data_key_request)
            .bearer_auth(&self.access_token)
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




