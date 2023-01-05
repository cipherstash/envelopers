//! Trait for a KeyProvider

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::aes::Aes128;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Key, KeyInit, KeySizeUser};
use async_trait::async_trait;
use rand_chacha::ChaChaRng;
use std::marker::PhantomData;
use std::sync::Mutex;

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::{DataKey, KeyProvider};
use crate::safe_rng::SafeRng;

// EncryptedSimpleKey relies on this size being constant. If this ever needs to be changed a new
// version of EncryptedSimpleKey needs to be created.
type Nonce = aes_gcm::Nonce<U16>;
const NONCE_SIZE: usize = 16;

/// A decoded intermediate representation of an encrypted simple key
///
/// The encoded version of the encrypted simple key looks like so:
///
/// | Pos  | Data                   |
/// | -----|------------------------|
/// | 0    | Version tag (1 byte)   |
/// | 1-17 | Nonce       (16 bytes) |
/// | 17-  | Encrypted key          |
#[derive(Debug)]
struct EncryptedSimpleKey<'a> {
    // Keep a version tag on the key just in case the format gets changed
    // This could have other header information - but it should be safe since we're only expected
    // keys created by the SimpleKeyProvider.
    version: u8,
    nonce: &'a Nonce,
    key: &'a [u8],
}

impl<'a> EncryptedSimpleKey<'a> {
    /// Decode an [`EncryptedSimpleKey`] from a slice following its encoded representation
    fn from_slice(bytes: &'a [u8]) -> Result<Self, KeyDecryptionError> {
        if bytes.len() < 1 + NONCE_SIZE {
            return Err(KeyDecryptionError::Other(format!(
                "Slice was too small to load an EncryptedSimpleKey. Received: {}",
                bytes.len()
            )));
        }

        let version = bytes[0];

        let nonce: &'a Nonce = Nonce::from_slice(&bytes[1..1 + NONCE_SIZE]);
        let key: &'a [u8] = &bytes[1 + NONCE_SIZE..];

        Ok(Self {
            version,
            nonce,
            key,
        })
    }

    /// Encode an [`EncryptedSimpleKey`] as bytes
    fn to_vec(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1 + self.nonce.len() + self.key.len());
        output.push(self.version);
        output.extend_from_slice(self.nonce);
        output.extend_from_slice(self.key);
        output
    }
}

#[derive(Debug)]
pub struct SimpleKeyProvider<S: KeySizeUser, R: SafeRng = ChaChaRng> {
    kek: [u8; 16],
    rng: Mutex<R>,
    phantom_data: PhantomData<S>,
}

impl<S: KeySizeUser, R: SafeRng> SimpleKeyProvider<S, R> {
    pub fn init(kek: [u8; 16]) -> Self {
        Self {
            kek,
            rng: Mutex::new(R::from_entropy()),
            phantom_data: PhantomData,
        }
    }
}

macro_rules! define_simple_key_provider_impl {
    ($name:ty) => {
        #[async_trait]
        impl<R: SafeRng> KeyProvider<$name> for SimpleKeyProvider<$name, R> {
            async fn decrypt_data_key(
                &self,
                encrypted_key: &[u8],
            ) -> Result<Key<$name>, KeyDecryptionError> {
                let key = Key::<Aes128>::from_slice(&self.kek);
                let cipher = AesGcm::<Aes128, U16>::new(key);
                let decoded_key = EncryptedSimpleKey::from_slice(encrypted_key)?;

                let data_key = cipher.decrypt(
                    decoded_key.nonce,
                    Payload {
                        msg: decoded_key.key,
                        aad: &[decoded_key.version],
                    },
                )?;

                return Ok(*Key::<$name>::from_slice(&data_key));
            }

            async fn generate_data_key(
                &self,
                _bytes: usize,
            ) -> Result<DataKey<$name>, KeyGenerationError> {
                let key = Key::<Aes128>::from_slice(&self.kek);
                let cipher = AesGcm::<Aes128, U16>::new(key);

                let version = 1;
                let mut data_key: Key<$name> = Default::default();
                let mut nonce: Nonce = Default::default();

                {
                    let mut rng = self.rng.lock().unwrap_or_else(|e| e.into_inner());
                    rng.try_fill_bytes(&mut data_key)?;
                    rng.try_fill_bytes(&mut nonce)?;
                }

                let payload = Payload {
                    msg: &data_key,
                    aad: &[version],
                };

                let ciphertext = cipher.encrypt(&nonce, payload)?;

                let encrypted_key = EncryptedSimpleKey {
                    version,
                    key: &ciphertext,
                    nonce: &nonce,
                };

                return Ok(DataKey {
                    key: data_key,
                    encrypted_key: encrypted_key.to_vec(),
                    key_id: String::from("simplekey"),
                });
            }
        }
    };
}

define_simple_key_provider_impl!(Aes128Gcm);
define_simple_key_provider_impl!(Aes256Gcm);

#[cfg(test)]
mod tests {
    use aes_gcm::{Aes128Gcm, KeySizeUser, Aes256Gcm};

    use super::{EncryptedSimpleKey, Nonce};
    use crate::{KeyProvider, SimpleKeyProvider};

    fn create_provider<S: KeySizeUser>() -> SimpleKeyProvider<S> where SimpleKeyProvider<S>: KeyProvider<S> {
        SimpleKeyProvider::init([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    }

    async fn test_generate_decrypt_data_key<S: KeySizeUser, K: KeyProvider<S>>(provider: K) {
        let data_key = provider.generate_data_key(0).await.unwrap();
        let decrypted_data_key = provider
            .decrypt_data_key(&data_key.encrypted_key)
            .await
            .unwrap();

        assert_eq!(data_key.key, decrypted_data_key);
    }

    #[tokio::test]
    async fn test_generate_decrypt_data_key_128_gcm() {
        let provider: SimpleKeyProvider<Aes128Gcm> = create_provider();
        test_generate_decrypt_data_key(provider).await;

        let provider: SimpleKeyProvider<Aes128Gcm> = create_provider();
        let provider: Box<dyn KeyProvider<_>> = Box::new(provider);
        test_generate_decrypt_data_key(provider).await;
    }

    #[tokio::test]
    async fn test_generate_decrypt_data_key_256_gcm() {
        let provider: SimpleKeyProvider<Aes256Gcm> = create_provider();
        test_generate_decrypt_data_key(provider).await;

        let provider: SimpleKeyProvider<Aes256Gcm> = create_provider();
        let provider: Box<dyn KeyProvider<_>> = Box::new(provider);
        test_generate_decrypt_data_key(provider).await;
    }

    #[tokio::test]
    async fn test_fails_on_invalid_data_key() {
        let first: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([0; 16]);
        let second: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([1; 16]);

        let data_key = first.generate_data_key(0).await.unwrap();

        assert_eq!(
            second
                .decrypt_data_key(&data_key.encrypted_key)
                .await
                .map_err(|e| e.to_string())
                .expect_err("Decrypting data key suceeded"),
            "failed to decrypt key"
        );
    }

    #[tokio::test]
    async fn test_fails_on_invalid_nonce() {
        let provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([0; 16]);

        let mut data_key = provider.generate_data_key(0).await.unwrap();

        // Decrypts data key fine
        assert!(provider
            .decrypt_data_key(&data_key.encrypted_key)
            .await
            .is_ok());

        // Replace the nonce with a nonsense one
        data_key.encrypted_key[1..17]
            .clone_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        assert_eq!(
            provider
                .decrypt_data_key(&data_key.encrypted_key)
                .await
                .map_err(|e| e.to_string())
                .expect_err("Decrypting data key succeeded"),
            "failed to decrypt key"
        );
    }

    #[tokio::test]
    async fn test_fails_on_invalid_version() {
        let provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([0; 16]);

        let mut data_key = provider.generate_data_key(0).await.unwrap();

        // Decrypts data key fine
        assert!(provider
            .decrypt_data_key(&data_key.encrypted_key)
            .await
            .is_ok());

        // Replace key version with invalid one
        data_key.encrypted_key[0] = 5;

        assert_eq!(
            provider
                .decrypt_data_key(&data_key.encrypted_key)
                .await
                .map_err(|e| e.to_string())
                .expect_err("Decrypting data key succeeded"),
            "failed to decrypt key"
        );
    }

    #[test]
    fn test_load_encrypted_key_from_slice() {
        let slice: Vec<u8> = vec![
            1, // version
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // nonce
            1, 2, 3, 4, 5, 6, // encrypted key (size is unknown)
        ];

        let key = EncryptedSimpleKey::from_slice(&slice).unwrap();

        assert_eq!(key.version, 1);
        assert_eq!(
            key.nonce,
            Nonce::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        );
        assert_eq!(key.key, &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_fails_on_tiny_slice() {
        let slice: Vec<u8> = vec![5, 1, 2, 3, 4, 5, 6];

        let err =
            EncryptedSimpleKey::from_slice(&slice).expect_err("Encrypted key decode succeeded");

        assert_eq!(
            err.to_string(),
            "Slice was too small to load an EncryptedSimpleKey. Received: 7"
        );
    }

    #[test]
    fn test_serialize_key() {
        let version = 1;
        let nonce = Nonce::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let key = &[1, 2, 3, 4, 5, 6];

        let encrypted_key = EncryptedSimpleKey {
            version,
            nonce,
            key,
        };

        let bytes = encrypted_key.to_vec();

        assert_eq!(
            bytes,
            vec![
                1, // version
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // nonce
                1, 2, 3, 4, 5, 6, // encrypted key (size is unknown)
            ]
        );
    }
}
