//! Trait for a KeyProvider


use aes_gcm::aes::cipher::consts::U16;

use aes_gcm::{Key};
use async_trait::async_trait;
use hyper::http::{Request, Method, Uri};
use hyper::{Client, Body};
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
        Self { host, key_id }
    }
}

#[async_trait(?Send)]
impl KeyProvider for ViturKeyProvider {
    async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError> {

        let client = Client::new();

        let uri = Uri::builder()
            .scheme("http")
            .authority(self.host.to_string())
            .path_and_query(format!("/api/keys/{}/decrypt", self.key_id))
            .build()
            .unwrap();

        let vdk = ViturEncryptedDataKey {
            data_key: encode_config(&encrypted_key, base64::URL_SAFE_NO_PAD)
        };

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&vdk).unwrap()))
            .expect("request builder");

        let resp = client.request(req).await.unwrap();
        let buf = hyper::body::to_bytes(resp).await.unwrap();
        let dk: ViturDataKey = serde_json::from_slice(&buf[..]).unwrap();
        let decoded = decode_config(&dk.dk, base64::URL_SAFE_NO_PAD).unwrap();

        return Ok(*Key::from_slice(&decoded));
    }

    async fn generate_data_key(&self, _bytes: usize) -> Result<DataKey, KeyGenerationError> {
        let client = Client::new();

        let uri = Uri::builder()
            .scheme("http")
            .authority(self.host.to_string())
            .path_and_query(format!("/api/keys/{}/gen-data-key", self.key_id))
            .build()
            .unwrap();

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(""))
            .expect("request builder");

        let resp = client.request(req).await.unwrap();

        // TODO: We probably should use a fast binary format instead of JSON but 🤪
        let buf = hyper::body::to_bytes(resp).await.unwrap();
        let dkp: ViturDataKeyPair = serde_json::from_slice(&buf[..]).unwrap();
        
        return Ok(DataKey {
            key: *Key::from_slice(&decode_config(dkp.dk, base64::URL_SAFE_NO_PAD).unwrap()),
            encrypted_key: decode_config(dkp.wdk, base64::URL_SAFE_NO_PAD).unwrap(),
            key_id: self.key_id.to_string(),
        });
    }
}




