//! envelope is a very simple, envelope encryption library that can use external key providers such
//! as AWS KMS to encrypt data safely. It uses the concept of data-keys to encrypt messages but
//! these data keys are themselves encrypted by a Key-Encryption-Key (or KEK, sometimes also called
//! Customer Master Key) with the resulting ciphertext stored with the encrypted data (the
//! "wrapped" data-key).
//!
//! # Usage
//!
//! **NOTE: This is Alpha software and should not be used in production**
//!
//! ## Encrypt a message with a local Key Provider
//!
//! The `SimpleKeyProvider` allows envelope encryption to be used with a local key.
//!
//! ```rust
//! use envelopers::{EnvelopeCipher, SimpleKeyProvider};
//!
//! # use tokio::runtime::Runtime;
//! # let rt = Runtime::new().unwrap();
//! # rt.block_on(async {
//! #
//! use hex_literal::hex;
//! let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! let key_provider: SimpleKeyProvider<_> = SimpleKeyProvider::init(kek);
//!
//! let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(
//!     key_provider,
//! );
//! let er = cipher.encrypt(b"hey there monkey boy").await.unwrap();
//! #
//! # });
//! ```
//!
//! ## Encoding a CipherText
//!
//! ```rust
//! # use envelopers::{EnvelopeCipher, SimpleKeyProvider};
//! #
//! # use tokio::runtime::Runtime;
//! # let rt = Runtime::new().unwrap();
//! # rt.block_on(async {
//! #
//! # use hex_literal::hex;
//! # let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let key_provider: SimpleKeyProvider<_> = SimpleKeyProvider::init(kek);
//! #
//! # let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(
//! #   key_provider,
//! # );
//! #
//! # let er = cipher.encrypt(b"hey there monkey boy").await.unwrap();
//! #
//! let bytes = er.to_vec().unwrap();
//! hex::encode(&bytes);
//! # });
//! ```
//!
//! ## Decrypting a CipherText
//! ```rust
//! use envelopers::{EnvelopeCipher, SimpleKeyProvider, EncryptedRecord};
//!
//! #
//! # use tokio::runtime::Runtime;
//! # let rt = Runtime::new().unwrap();
//! # rt.block_on(async {
//! #
//! # use hex_literal::hex;
//! # let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let key_provider: SimpleKeyProvider<_> = SimpleKeyProvider::init(kek);
//! #
//! # let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(
//! #    key_provider,
//! # );
//! # let er = cipher.encrypt(b"hey there monkey boy").await.unwrap();
//! # let bytes = er.to_vec().unwrap();
//! # hex::encode(&bytes);
//! #
//! let dec = EncryptedRecord::from_vec(bytes).unwrap();
//! let pt = cipher.decrypt(&dec).await.unwrap();
//!
//! assert!(std::str::from_utf8(&pt).unwrap() == "hey there monkey boy");
//! #
//! # });
//! ```

pub mod errors;
pub mod safe_rng;

mod key_provider;
mod simple_key_provider;

#[cfg(feature = "aws-kms")]
mod kms_key_provider;

#[cfg(feature = "cache")]
mod caching_key_wrapper;

pub use crate::key_provider::{DataKey, KeyProvider};

#[cfg(feature = "cache")]
pub use crate::caching_key_wrapper::{CacheOptions, CachingKeyWrapper};
pub use crate::simple_key_provider::SimpleKeyProvider;

#[cfg(feature = "aws-kms")]
pub use crate::kms_key_provider::KMSKeyProvider;

pub use aes_gcm::aes::cipher::consts::{U16, U32};
pub use aes_gcm::Key;

use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
// Or `Aes256Gcm`
use async_mutex::Mutex as AsyncMutex;
use rand_chacha::ChaChaRng;
use safe_rng::SafeRng;
use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;

pub use errors::{DecryptionError, EncryptionError, KeyDecryptionError, KeyGenerationError};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub encrypted_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_id: String,
}

impl EncryptedRecord {
    pub fn to_vec(&self) -> serde_cbor::Result<Vec<u8>> {
        serde_cbor::to_vec(&self)
    }

    pub fn from_vec(vec: Vec<u8>) -> serde_cbor::Result<Self> {
        serde_cbor::from_slice(&vec[..])
    }
}

pub struct EnvelopeCipher<K, R: SafeRng = ChaChaRng> {
    pub provider: K,
    pub rng: AsyncMutex<R>,
}

impl<K, R: SafeRng> EnvelopeCipher<K, R> {
    pub fn init(provider: K) -> Self {
        Self {
            provider,
            rng: AsyncMutex::new(R::from_entropy()),
        }
    }
}

impl<K: KeyProvider<U16>, R: SafeRng> EnvelopeCipher<K, R> {
    pub async fn decrypt(
        &self,
        encrypted_record: &EncryptedRecord,
    ) -> Result<Vec<u8>, DecryptionError> {
        let key = self
            .provider
            .decrypt_data_key(encrypted_record.encrypted_key.as_ref())
            .await?;

        let aad = &encrypted_record.key_id;
        let msg = encrypted_record.ciphertext.as_ref();
        let payload = Payload {
            msg,
            aad: aad.as_bytes(),
        };

        let cipher = Aes128Gcm::new(&key);
        let message = cipher.decrypt(Nonce::from_slice(&encrypted_record.nonce), payload)?;

        Ok(message)
    }

    pub async fn encrypt(&self, msg: &[u8]) -> Result<EncryptedRecord, EncryptionError> {
        let mut nonce_data = [0u8; 12];

        let data_key = self.provider.generate_data_key(msg.len()).await?;

        let key_id = data_key.key_id;

        {
            let mut rng = self.rng.lock().await;
            rng.try_fill_bytes(&mut nonce_data)?;
        }

        let payload = Payload {
            msg,
            aad: key_id.as_bytes(),
        };

        let nonce = Nonce::from_slice(&nonce_data);

        // TODO: Use Zeroize for the drop
        let key = Key::from_slice(&data_key.key);
        let cipher = Aes128Gcm::new(key);
        let ciphertext = cipher.encrypt(nonce, payload)?;

        Ok(EncryptedRecord {
            ciphertext,
            nonce: nonce_data,
            encrypted_key: data_key.encrypted_key,
            key_id,
        })
    }
}

// Ensure that all supported EnvelopeCiphers can be shared between threads
assert_impl_all!(EnvelopeCipher<SimpleKeyProvider<U16>>: Send, Sync);
assert_impl_all!(EnvelopeCipher<SimpleKeyProvider<U32>>: Send, Sync);
assert_impl_all!(EnvelopeCipher<Box<dyn KeyProvider<U16>>>: Send, Sync);
assert_impl_all!(EnvelopeCipher<Box<dyn KeyProvider<U32>>>: Send, Sync);

#[cfg(feature = "aws-kms")]
assert_impl_all!(EnvelopeCipher<KMSKeyProvider<U16>>: Send, Sync);
#[cfg(feature = "aws-kms")]
assert_impl_all!(EnvelopeCipher<KMSKeyProvider<U32>>: Send, Sync);

#[cfg(feature = "cache")]
assert_impl_all!(EnvelopeCipher<CachingKeyWrapper<SimpleKeyProvider<U16>>>: Send, Sync);
#[cfg(feature = "cache")]
assert_impl_all!(EnvelopeCipher<CachingKeyWrapper<SimpleKeyProvider<U32>, U32>>: Send, Sync);

#[cfg(all(feature = "cache", feature = "aws-kms"))]
assert_impl_all!(EnvelopeCipher<CachingKeyWrapper<KMSKeyProvider<U16>>>: Send, Sync);
#[cfg(all(feature = "cache", feature = "aws-kms"))]
assert_impl_all!(EnvelopeCipher<CachingKeyWrapper<KMSKeyProvider<U32>, U32>>: Send, Sync);

#[cfg(test)]
mod tests {
    use crate::{CacheOptions, CachingKeyWrapper, EnvelopeCipher, KeyProvider, SimpleKeyProvider};

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let provider: SimpleKeyProvider<_> = SimpleKeyProvider::init(&[1; 16]);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);

        let message = "hello".as_bytes();

        let record = cipher.encrypt(message).await.unwrap();
        let decrypted = cipher.decrypt(&record).await.unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_boxed() {
        let provider: SimpleKeyProvider<_> = SimpleKeyProvider::init(&[1; 16]);
        let cipher: EnvelopeCipher<Box<dyn KeyProvider<_>>> =
            EnvelopeCipher::init(Box::new(provider));

        let message = "hello".as_bytes();

        let record = cipher.encrypt(message).await.unwrap();
        let decrypted = cipher.decrypt(&record).await.unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_cache() {
        let provider: CachingKeyWrapper<SimpleKeyProvider<_>> =
            CachingKeyWrapper::new(SimpleKeyProvider::init(&[1; 16]), CacheOptions::default());

        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);

        let message = "hello".as_bytes();

        let record = cipher.encrypt(message).await.unwrap();
        let decrypted = cipher.decrypt(&record).await.unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "hello");
    }
}
