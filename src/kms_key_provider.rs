use async_trait::async_trait;
use aws_sdk_kms::model::DataKeySpec;
use aws_sdk_kms::types::Blob;
use aws_sdk_kms::{Client, Config, Credentials, Region};

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::{DataKey, KeyProvider};
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::Key;

pub struct KMSKeyProvider {
    key_id: String,
    data_key_spec: DataKeySpec,
    client: Client,
}

impl KMSKeyProvider {
    pub fn new(client: Client, key_id: String) -> Self {
        Self {
            client,
            data_key_spec: DataKeySpec::Aes128,
            key_id,
        }
    }

    /// Create a KMS key provider from raw credentials
    ///
    /// This method is particularly useful when you can't load credentials from environment variables.
    pub fn from_credentials(
        key_id: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        let aws_creds = Credentials::new(
            access_key_id,
            secret_access_key,
            Some(session_token.into()),
            None,
            "Static",
        );

        let config = Config::builder()
            .region(Region::new(region.into()))
            .credentials_provider(aws_creds)
            .build();

        let client = Client::from_conf(config);

        Self::new(client, key_id.into())
    }

    pub fn with_spec(mut self, spec: DataKeySpec) -> Self {
        self.data_key_spec = spec;
        self
    }
}

#[async_trait(?Send)]
impl KeyProvider for KMSKeyProvider {
    async fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
        let mut response = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(self.data_key_spec.clone())
            .send()
            .await
            .map_err(|e| {
                KeyGenerationError::Other(format!("KMS generate data key request failed: {}", e))
            })?;

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
            KeyGenerationError::Other(String::from("Response did not contain plaintext key"))
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
            .map_err(|e| KeyDecryptionError::Other(e.to_string()))?;

        let plaintext_blob = response.plaintext().ok_or_else(|| {
            KeyDecryptionError::Other(String::from("Response did not contain plaintext key"))
        })?;

        Ok(Key::clone_from_slice(plaintext_blob.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use tokio;

    use aws_sdk_kms::{Client, Config, Credentials, Region};
    use aws_smithy_client::test_connection::TestConnection;
    use aws_smithy_http::body::SdkBody;
    use base64::encode;
    use core::future::Future;
    use http::{Request, Response, StatusCode};

    use crate::{KMSKeyProvider, KeyProvider};

    async fn with_mocked_response<C, F>(
        request_body: impl Into<String>,
        response_body: impl Into<String>,
        response_code: u16,
        callback: C,
    ) where
        C: FnOnce(Client) -> F,
        F: Future<Output = ()>,
    {
        let creds = Credentials::new(
            "ANOTREAL",
            "notrealrnrELgWzOk3IfjzDKtFBhDby",
            Some("notarealsessiontoken".to_string()),
            None,
            "test",
        );

        let conn = TestConnection::new(vec![(
            Request::builder()
                .uri("https://kms.ap-southeast-2.amazonaws.com")
                .body(SdkBody::from(request_body.into()))
                .expect("Failed to create request body"),
            Response::builder()
                .status(StatusCode::from_u16(response_code).expect("Invalid status code"))
                .body(response_body.into())
                .expect("Failed to create response body"),
        )]);

        let conf = Config::builder()
            .region(Region::new("ap-southeast-2"))
            .credentials_provider(creds)
            .build();

        let client = Client::from_conf_conn(conf, conn.clone());

        callback(client).await;

        assert_eq!(conn.requests().len(), 1);
        conn.assert_requests_match(&[]);
    }

    #[tokio::test]
    async fn test_generate_data_key() {
        let key_id = "test-key-id";
        let plaintext: Vec<u8> = vec![1; 16];
        let ciphertext: Vec<u8> = vec![2; 16];

        with_mocked_response(
            r#"{"KeyId":"test-key-id","KeySpec":"AES_128"}"#,
            format!(
                r#"{{"CiphertextBlob":"{}","Plaintext":"{}","KeyId":"{}"}}"#,
                encode(&ciphertext),
                encode(&plaintext),
                key_id
            ),
            200,
            |client| async move {
                let provider = KMSKeyProvider::new(client, key_id.into());

                let key = provider
                    .generate_data_key()
                    .await
                    .expect("Failed to generate data key");

                assert_eq!(key.key.as_slice(), plaintext.as_slice());
                assert_eq!(key.encrypted_key.as_slice(), ciphertext.as_slice());
                assert_eq!(key.key_id, key_id);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_generate_missing_encrypted_key_response() {
        let key_id = "test-key-id";

        with_mocked_response(
            r#"{"KeyId":"test-key-id","KeySpec":"AES_128"}"#,
            "{}",
            200,
            |client| async move {
                let provider = KMSKeyProvider::new(client, key_id.into());

                let result = provider.generate_data_key().await;

                assert_eq!(
                    result
                        .map_err(|e| e.to_string())
                        .expect_err("Expected result to be error"),
                    String::from("Response did not contain encrypted key")
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_generate_missing_plaintext_key_response() {
        let key_id = "test-key-id";
        let ciphertext: Vec<u8> = vec![2; 16];

        with_mocked_response(
            r#"{"KeyId":"test-key-id","KeySpec":"AES_128"}"#,
            format!(
                r#"{{"CiphertextBlob":"{}","KeyId":"{}"}}"#,
                encode(&ciphertext),
                key_id
            ),
            200,
            |client| async move {
                let provider = KMSKeyProvider::new(client, key_id.into());

                let result = provider.generate_data_key().await;

                assert_eq!(
                    result
                        .map_err(|e| e.to_string())
                        .expect_err("Expected result to be error"),
                    String::from("Response did not contain plaintext key")
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_generate_missing_key_id_response() {
        let key_id = "test-key-id";
        let ciphertext: Vec<u8> = vec![2; 16];
        let plaintext: Vec<u8> = vec![1; 16];

        with_mocked_response(
            r#"{"KeyId":"test-key-id","KeySpec":"AES_128"}"#,
            format!(
                r#"{{"CiphertextBlob":"{}","PlaintextKey":"{}"}}"#,
                encode(&ciphertext),
                encode(&plaintext)
            ),
            200,
            |client| async move {
                let provider = KMSKeyProvider::new(client, key_id.into());

                let result = provider.generate_data_key().await;

                assert_eq!(
                    result
                        .map_err(|e| e.to_string())
                        .expect_err("Expected result to be error"),
                    String::from("Response did not contain key_id")
                );
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_generate_bad_request() {
        let key_id = "test-key-id";

        with_mocked_response(
            r#"{"KeyId":"test-key-id","KeySpec":"AES_128"}"#,
            "{}",
            500,
            |client| async move {
                let provider = KMSKeyProvider::new(client, key_id.into());

                let result = provider.generate_data_key().await;

                assert_eq!(
                    result
                        .map_err(|e| e.to_string())
                        .expect_err("Expected result to be error"),
                    String::from("KMS generate data key request failed: Error")
                );
            },
        )
        .await;
    }
}
