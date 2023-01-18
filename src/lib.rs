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
//! let key_provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init(kek);
//!
//! let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(key_provider);
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
//! # let key_provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init(kek);
//! #
//! # let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(key_provider);
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
//! # let key_provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init(kek);
//! #
//! # let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(key_provider);
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

pub use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, KeySizeUser};
pub use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};

pub use crate::errors::{DecryptionError, EncryptionError, KeyDecryptionError, KeyGenerationError};
pub use crate::key_provider::{DataKey, KeyProvider};
pub use crate::simple_key_provider::SimpleKeyProvider;

#[cfg(feature = "aws-kms")]
pub use crate::kms_key_provider::KMSKeyProvider;

#[cfg(feature = "cache")]
pub use crate::caching_key_wrapper::{CacheOptions, CachingKeyWrapper};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{KeyInit, Nonce};
use async_mutex::Mutex as AsyncMutex;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;

use crate::safe_rng::SafeRng;

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

pub struct Encrypt<'a, K: KeyProvider, R: SafeRng> {
    cipher: &'a EnvelopeCipher<K, R>,
    msg: &'a [u8],
    aad: Option<&'a str>,
    key_aad: Option<&'a str>,
}

impl<'a, K: KeyProvider, R: SafeRng> Encrypt<'a, K, R>
where
    K::Cipher: Aead + KeyInit,
{
    fn new(cipher: &'a EnvelopeCipher<K, R>, msg: &'a [u8]) -> Self {
        Self {
            cipher,
            msg,
            aad: None,
            key_aad: None,
        }
    }

    pub fn aad(mut self, aad: &'a str) -> Self {
        self.aad.replace(aad);
        self
    }

    pub fn key_aad(mut self, aad: &'a str) -> Self {
        self.aad.replace(aad);
        self
    }

    pub async fn encrypt(&self) -> Result<EncryptedRecord, EncryptionError> {
        let data_key = self
            .cipher
            .provider
            .generate_data_key(self.msg.len(), self.key_aad)
            .await?;

        let aad = match self.aad {
            Some(a) => [data_key.key_id.as_bytes(), a.as_bytes()].concat(),
            None => data_key.key_id.as_bytes().to_vec(),
        };

        let nonce = {
            let mut bytes = [0u8; 12];
            let mut rng = self.cipher.rng.lock().await;
            rng.try_fill_bytes(&mut bytes)?;

            bytes
        };

        let key_id = data_key.key_id.clone();
        let payload = Payload {
            msg: self.msg,
            aad: &aad,
        };

        // TODO: Use Zeroize for the drop
        let key = Key::<K::Cipher>::from_slice(&data_key.key);
        let cipher = K::Cipher::new(key);
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), payload)?;

        Ok(EncryptedRecord {
            ciphertext,
            nonce,
            encrypted_key: data_key.encrypted_key.clone(),
            key_id,
        })
    }
}

pub struct Decrypt<'a, K: KeyProvider, R: SafeRng> {
    cipher: &'a EnvelopeCipher<K, R>,
    encrypted_record: &'a EncryptedRecord,
    aad: Option<&'a str>,
    key_aad: Option<&'a str>,
}

impl<'a, K: KeyProvider, R: SafeRng> Decrypt<'a, K, R>
where
    K::Cipher: Aead + KeyInit,
{
    fn new(cipher: &'a EnvelopeCipher<K, R>, encrypted_record: &'a EncryptedRecord) -> Self {
        Self {
            cipher,
            encrypted_record,
            aad: None,
            key_aad: None,
        }
    }

    pub fn aad(mut self, aad: &'a str) -> Self {
        self.aad.replace(aad);
        self
    }

    pub fn key_aad(mut self, aad: &'a str) -> Self {
        self.aad.replace(aad);
        self
    }

    pub async fn decrypt(&self) -> Result<Vec<u8>, DecryptionError> {
        let key = self
            .cipher
            .provider
            .decrypt_data_key(&self.encrypted_record.encrypted_key, self.key_aad)
            .await?;

        let aad = match self.aad {
            Some(a) => [self.encrypted_record.key_id.as_bytes(), a.as_bytes()].concat(),
            None => self.encrypted_record.key_id.as_bytes().to_vec(),
        };

        let msg = self.encrypted_record.ciphertext.as_ref();
        let payload = Payload { msg, aad: &aad };

        let cipher = K::Cipher::new(&key);
        let message = cipher.decrypt(Nonce::from_slice(&self.encrypted_record.nonce), payload)?;

        Ok(message)
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

impl<'a, K: KeyProvider, R: SafeRng> EnvelopeCipher<K, R>
where
    K::Cipher: Aead + KeyInit,
{
    pub async fn decrypt(
        &self,
        encrypted_record: &EncryptedRecord,
    ) -> Result<Vec<u8>, DecryptionError> {
        Decrypt::new(self, encrypted_record).decrypt().await
    }

    pub async fn encrypt(&self, msg: &[u8]) -> Result<EncryptedRecord, EncryptionError> {
        Encrypt::new(self, msg).encrypt().await
    }

    pub fn encrypt_with(&'a self, msg: &'a [u8]) -> Encrypt<K, R> {
        Encrypt::new(self, msg)
    }

    pub fn decrypt_with(&'a self, encrypted_record: &'a EncryptedRecord) -> Decrypt<K, R> {
        Decrypt::new(self, encrypted_record)
    }
}

// Ensure that all supported EnvelopeCiphers can be shared between threads
assert_impl_all!(EnvelopeCipher<SimpleKeyProvider<Aes128Gcm>>: Send, Sync);
assert_impl_all!(EnvelopeCipher<Box<dyn KeyProvider<Cipher = Aes128Gcm>>>: Send, Sync);

#[cfg(feature = "aws-kms")]
assert_impl_all!(EnvelopeCipher<KMSKeyProvider<Aes128Gcm>>: Send, Sync);

#[cfg(feature = "cache")]
assert_impl_all!(EnvelopeCipher<CachingKeyWrapper<Aes128Gcm, SimpleKeyProvider<Aes128Gcm>>>: Send, Sync);

#[cfg(all(feature = "cache", feature = "aws-kms"))]
assert_impl_all!(EnvelopeCipher<CachingKeyWrapper<Aes128Gcm, KMSKeyProvider<Aes128Gcm>>>: Send, Sync);

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
    use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};

    use crate::{CacheOptions, CachingKeyWrapper, EnvelopeCipher, KeyProvider, SimpleKeyProvider};

    async fn test_encrypt_decrypt<K: KeyProvider>(cipher: EnvelopeCipher<K>)
    where
        K::Cipher: Aead + KeyInit,
    {
        // encrypt without aad
        let message = "hello".as_bytes();

        let record = cipher.encrypt(message).await.unwrap();
        let decrypted = cipher.decrypt(&record).await.unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "hello");

        // encrypt with aad
        let message = "hello".as_bytes();
        let aad = "world";

        let record = cipher
            .encrypt_with(message)
            .aad(aad)
            .encrypt()
            .await
            .unwrap();
        let decrypted = cipher
            .decrypt_with(&record)
            .aad(aad)
            .decrypt()
            .await
            .unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "hello");

        // encrypt with data_key aad
        let message = "hello".as_bytes();
        let aad = "world";

        let record = cipher
            .encrypt_with(message)
            .key_aad(aad)
            .encrypt()
            .await
            .unwrap();
        let decrypted = cipher
            .decrypt_with(&record)
            .key_aad(aad)
            .decrypt()
            .await
            .unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_128_gcm() {
        let provider: SimpleKeyProvider = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<Cipher = _>> = Box::new(provider);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_256_gcm() {
        let provider: SimpleKeyProvider<Aes256Gcm> = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes256Gcm> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<Cipher = _>> = Box::new(provider);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_128_gcm_siv() {
        let provider: SimpleKeyProvider<Aes128GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes128GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<Cipher = _>> = Box::new(provider);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_256_gcm_siv() {
        let provider: SimpleKeyProvider<Aes256GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;

        let provider: SimpleKeyProvider<Aes256GcmSiv> = SimpleKeyProvider::init([1; 16]);
        let provider: Box<dyn KeyProvider<Cipher = _>> = Box::new(provider);
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_cache() {
        let provider: SimpleKeyProvider<Aes128Gcm> = SimpleKeyProvider::init([1; 16]);
        let provider = CachingKeyWrapper::new(provider, CacheOptions::default());
        let cipher: EnvelopeCipher<_> = EnvelopeCipher::init(provider);
        test_encrypt_decrypt(cipher).await;
    }
}
