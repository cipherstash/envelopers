use std::marker::PhantomData;

use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, KeySizeUser};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
use async_trait::async_trait;
use aws_config::retry::RetryConfig;
use aws_sdk_kms::config::{Credentials, Region};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_kms::{Client, Config};

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::{DataKey, KeyProvider};

pub struct KMSKeyProvider<S: KeySizeUser = Aes128Gcm> {
    key_id: String,
    client: Client,
    phantom_data: PhantomData<S>,
}

impl<S: KeySizeUser> KMSKeyProvider<S> {
    pub fn new(client: Client, key_id: String) -> Self {
        Self {
            client,
            key_id,
            phantom_data: PhantomData,
        }
    }

    /// Create a KMS key provider from raw credentials
    ///
    /// This method is particularly useful when you can't load credentials from environment variables.
    pub fn from_credentials(
        key_id: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<impl Into<String>>,
        region: impl Into<String>,
    ) -> Self {
        let aws_creds = Credentials::new(
            access_key_id,
            secret_access_key,
            session_token.map(|x| x.into()),
            None,
            "Static",
        );

        let config = Config::builder()
            .region(Region::new(region.into()))
            .credentials_provider(aws_creds)
            .retry_config(RetryConfig::standard().with_max_attempts(5))
            .build();

        let client = Client::from_conf(config);

        Self::new(client, key_id.into())
    }
}

macro_rules! define_kms_key_provider_impl {
    ($name:ty, $data_key_spec:expr) => {
        #[async_trait]
        impl KeyProvider for KMSKeyProvider<$name> {
            type Cipher = $name;

            async fn generate_data_key(
                &self,
                _bytes_to_encrypt: usize,
                aad: Option<&str>,
            ) -> Result<DataKey<$name>, KeyGenerationError> {
                let mut generate_data_key = self.client.generate_data_key();
                if let Some(a) = aad {
                    generate_data_key = generate_data_key.encryption_context("aad", a);
                }
                let mut response = generate_data_key
                    .key_id(&self.key_id)
                    .key_spec($data_key_spec)
                    .send()
                    .await
                    .map_err(|e| {
                        KeyGenerationError::Other(format!(
                            "KMS generate data key request failed: {}",
                            e
                        ))
                    })?;

                let encrypted_key = response
                    .ciphertext_blob
                    .take()
                    .ok_or_else(|| {
                        KeyGenerationError::Other(String::from(
                            "Response did not contain encrypted key",
                        ))
                    })?
                    .into_inner();

                let key_id = response.key_id.ok_or_else(|| {
                    KeyGenerationError::Other(String::from("Response did not contain key_id"))
                })?;

                let plaintext_blob = response.plaintext.ok_or_else(|| {
                    KeyGenerationError::Other(String::from(
                        "Response did not contain plaintext key",
                    ))
                })?;

                let key = Key::<$name>::clone_from_slice(plaintext_blob.as_ref());

                Ok(DataKey {
                    key,
                    encrypted_key,
                    key_id,
                })
            }

            async fn decrypt_data_key(
                &self,
                encrypted_key: &[u8],
                aad: Option<&str>,
            ) -> Result<Key<$name>, KeyDecryptionError> {
                let mut decrypt = self.client.decrypt();
                if let Some(a) = aad {
                    decrypt = decrypt.encryption_context("aad", a);
                }
                let response = decrypt
                    .ciphertext_blob(Blob::new(encrypted_key.to_vec()))
                    .send()
                    .await
                    .map_err(|e| KeyDecryptionError::Other(e.to_string()))?;

                let plaintext_blob = response.plaintext().ok_or_else(|| {
                    KeyDecryptionError::Other(String::from(
                        "Response did not contain plaintext key",
                    ))
                })?;

                Ok(Key::<$name>::clone_from_slice(plaintext_blob.as_ref()))
            }
        }
    };
}

define_kms_key_provider_impl!(Aes128Gcm, DataKeySpec::Aes128);
define_kms_key_provider_impl!(Aes256Gcm, DataKeySpec::Aes256);
define_kms_key_provider_impl!(Aes128GcmSiv, DataKeySpec::Aes128);
define_kms_key_provider_impl!(Aes256GcmSiv, DataKeySpec::Aes256);

#[cfg(test)]
mod tests {

    use aes_gcm::Aes128Gcm;
    use aws_sdk_kms::config::{Credentials, Region};
    use aws_sdk_kms::{Client, Config};
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
            .http_connector(conn.clone())
            .region(Region::new("ap-southeast-2"))
            .credentials_provider(creds)
            .build();

        let client = Client::from_conf(conf);

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
                let provider = KMSKeyProvider::<Aes128Gcm>::new(client, key_id.into());

                let key = provider
                    .generate_data_key(0, None)
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
                let provider = KMSKeyProvider::<Aes128Gcm>::new(client, key_id.into());

                let result = provider.generate_data_key(0, None).await;

                match result {
                    Ok(_) => panic!("Expected result to be an error"),
                    Err(e) => assert_eq!(e.to_string(), "Response did not contain encrypted key"),
                }
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
                let provider = KMSKeyProvider::<Aes128Gcm>::new(client, key_id.into());

                let result = provider.generate_data_key(0, None).await;

                match result {
                    Ok(_) => panic!("Expected result to be an error"),
                    Err(e) => assert_eq!(e.to_string(), "Response did not contain plaintext key"),
                }
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
                let provider = KMSKeyProvider::<Aes128Gcm>::new(client, key_id.into());

                let result = provider.generate_data_key(0, None).await;

                match result {
                    Ok(_) => panic!("Expected result to be an error"),
                    Err(e) => assert_eq!(e.to_string(), "Response did not contain key_id"),
                }
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
                let provider = KMSKeyProvider::<Aes128Gcm>::new(client, key_id.into());

                let result = provider.generate_data_key(0, None).await;

                match result {
                    Ok(_) => panic!("Expected result to be an error"),
                    Err(e) => {
                        assert_eq!(
                            e.to_string(),
                            "KMS generate data key request failed: service error"
                        )
                    }
                }
            },
        )
        .await;
    }
}
