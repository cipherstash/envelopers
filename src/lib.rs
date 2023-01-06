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
//! use envelopers::{
//!     Aes128Gcm, // or Aes256Gcm, Aes128GcmSiv, Aes256GcmSiv
//!     EnvelopeCipher,
//!     SimpleKeyProvider,
//! };
//!
//! # use tokio::runtime::Runtime;
//! # let rt = Runtime::new().unwrap();
//! # rt.block_on(async {
//! #
//! use hex_literal::hex;
//! let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! let key_provider = SimpleKeyProvider::<Aes128Gcm>::init(kek);
//!
//! let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(key_provider);
//! let er = cipher.encrypt(b"hey there monkey boy").await.unwrap();
//! #
//! # });
//! ```
//!
//! ## Encoding a CipherText
//!
//! ```rust
//! # use envelopers::{Aes128Gcm, EnvelopeCipher, SimpleKeyProvider};
//! #
//! # use tokio::runtime::Runtime;
//! # let rt = Runtime::new().unwrap();
//! # rt.block_on(async {
//! #
//! # use hex_literal::hex;
//! # let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let key_provider = SimpleKeyProvider::<Aes128Gcm>::init(kek);
//! #
//! # let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(key_provider);
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
//! use envelopers::{Aes128Gcm, EnvelopeCipher, SimpleKeyProvider, EncryptedRecord};
//!
//! #
//! # use tokio::runtime::Runtime;
//! # let rt = Runtime::new().unwrap();
//! # rt.block_on(async {
//! #
//! # use hex_literal::hex;
//! # let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let key_provider = SimpleKeyProvider::<Aes128Gcm>::init(kek);
//! #
//! # let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(key_provider);
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
pub use crate::simple_key_provider::SimpleKeyProvider;

#[cfg(feature = "cache")]
pub use crate::caching_key_wrapper::{CacheOptions, CachingKeyWrapper};

#[cfg(feature = "aws-kms")]
pub use crate::kms_key_provider::KMSKeyProvider;

pub use aes_gcm::{Aes128Gcm, Aes256Gcm, Key};
pub use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};

pub use errors::{DecryptionError, EncryptionError, KeyDecryptionError, KeyGenerationError};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{KeyInit, KeySizeUser, Nonce};
use async_mutex::Mutex as AsyncMutex;
use rand_chacha::ChaChaRng;
use safe_rng::SafeRng;
use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use std::marker::PhantomData;

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

pub struct EnvelopeCipher<K, S = Aes128Gcm, R: SafeRng = ChaChaRng> {
    aes: PhantomData<S>,
    pub provider: K,
    pub rng: AsyncMutex<R>,
}

impl<K, S, R: SafeRng> EnvelopeCipher<K, S, R> {
    pub fn init(provider: K) -> Self {
        Self {
            aes: PhantomData,
            provider,
            rng: AsyncMutex::new(R::from_entropy()),
        }
    }
}

impl<K: KeyProvider<S>, S: KeyInit + KeySizeUser + Aead, R: SafeRng> EnvelopeCipher<K, S, R> {
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

        let cipher = S::new(&key);
        let message = cipher.decrypt(Nonce::from_slice(&encrypted_record.nonce), payload)?;

        Ok(message)
    }

    pub async fn encrypt(&self, msg: &[u8]) -> Result<EncryptedRecord, EncryptionError> {
        let data_key = self.provider.generate_data_key(msg.len()).await?;
        let key_id = data_key.key_id.clone();

        let mut nonce_data = [0u8; 12];
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
        let key = Key::<S>::from_slice(&data_key.key);
        let cipher = S::new(key);
        let ciphertext = cipher.encrypt(nonce, payload)?;

        Ok(EncryptedRecord {
            ciphertext,
            nonce: nonce_data,
            encrypted_key: data_key.encrypted_key.clone(),
            key_id,
        })
    }
}

// Ensure that all supported EnvelopeCiphers can be shared between threads
assert_impl_all!(EnvelopeCipher<Aes128Gcm, SimpleKeyProvider<Aes128Gcm>>: Send, Sync);
assert_impl_all!(EnvelopeCipher<Aes128Gcm, Box<dyn KeyProvider<Aes128Gcm>>>: Send, Sync);

#[cfg(feature = "aws-kms")]
assert_impl_all!(EnvelopeCipher<Aes128Gcm, KMSKeyProvider<Aes128Gcm>>: Send, Sync);

#[cfg(feature = "cache")]
assert_impl_all!(EnvelopeCipher<Aes128Gcm, CachingKeyWrapper<Aes128Gcm, SimpleKeyProvider<Aes128Gcm>>>: Send, Sync);

#[cfg(all(feature = "cache", feature = "aws-kms"))]
assert_impl_all!(EnvelopeCipher<Aes128Gcm, CachingKeyWrapper<Aes128Gcm, KMSKeyProvider<Aes128Gcm>>>: Send, Sync);

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit, KeySizeUser};
    use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};

    use crate::{CacheOptions, CachingKeyWrapper, EnvelopeCipher, KeyProvider, SimpleKeyProvider};

    async fn test_encrypt_decrypt<K: KeyProvider<S>, S: KeyInit + KeySizeUser + Aead>(
        cipher: EnvelopeCipher<K, S>,
    ) {
        let message = "hello".as_bytes();

        let record = cipher.encrypt(message).await.unwrap();
        let decrypted = cipher.decrypt(&record).await.unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_128_gcm() {
        let provider: SimpleKeyProvider = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<_>> = Box::new(provider);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_256_gcm() {
        let provider: SimpleKeyProvider<Aes256Gcm> = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes256Gcm> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<_>> = Box::new(provider);
        let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_128_gcm_siv() {
        let provider: SimpleKeyProvider<Aes128GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes128GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<_>> = Box::new(provider);
        let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_256_gcm_siv() {
        let provider: SimpleKeyProvider<Aes256GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes256GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<_>> = Box::new(provider);
        let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_cache() {
        let provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([1; 16]);
        let provider = CachingKeyWrapper::new(provider, CacheOptions::default());
        let cipher: EnvelopeCipher<_, _> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }
}
