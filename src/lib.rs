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
//! use envelope::{EnvelopeCipher, SimpleKeyProvider};
//!
//! use hex_literal::hex;
//! let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! let key_provider = SimpleKeyProvider::init(kek);
//!
//! let cipher: EnvelopeCipher<SimpleKeyProvider> = EnvelopeCipher::init(key_provider);
//! let er = cipher.encrypt(b"hey there monkey boy").unwrap();
//! ```
//!
//! ## Encoding a CipherText
//!
//! ```rust
//! # use envelope::{EnvelopeCipher, SimpleKeyProvider};
//! #
//! # use hex_literal::hex;
//! # let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let key_provider = SimpleKeyProvider::init(kek);
//! #
//! # let cipher: EnvelopeCipher<SimpleKeyProvider> = EnvelopeCipher::init(key_provider);
//! # let er = cipher.encrypt(b"hey there monkey boy").unwrap();
//!
//! let bytes = er.to_vec().unwrap();
//! hex::encode(&bytes);
//! ```
//!
//! ## Decrypting a CipherText
//! ```rust
//! use envelope::{EnvelopeCipher, SimpleKeyProvider, EncryptedRecord};
//! #
//! # use hex_literal::hex;
//! # let kek: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let key_provider = SimpleKeyProvider::init(kek);
//! #
//! # let cipher: EnvelopeCipher<SimpleKeyProvider> = EnvelopeCipher::init(key_provider);
//! # let er = cipher.encrypt(b"hey there monkey boy").unwrap();
//! # let bytes = er.to_vec().unwrap();
//! # hex::encode(&bytes);
//!
//! let dec = EncryptedRecord::from_vec(bytes).unwrap();
//! let pt = cipher.decrypt(dec).unwrap();
//!
//! assert!(std::str::from_utf8(&pt).unwrap() == "hey there monkey boy");
//! ```

mod errors;
mod key_provider;

mod kms_key_provider;
mod simple_key_provider;

pub use crate::key_provider::KeyProvider;

pub use crate::kms_key_provider::KMSKeyProvider;
pub use crate::simple_key_provider::SimpleKeyProvider;

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use key_provider::DataKey;
// Or `Aes256Gcm`
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

use errors::{DecryptionError, EncryptionError};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub ciphertext: Vec<u8>,
    pub encrypted_key: Vec<u8>,
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

pub struct EnvelopeCipher<K, R = ChaChaRng>
where
    R: SeedableRng + RngCore,
{
    pub key_provider: K,
    pub rng: RefCell<R>,
}

impl<K, R> EnvelopeCipher<K, R>
where
    R: SeedableRng + RngCore,
{
    pub fn init(key_provider: K) -> Self {
        Self {
            key_provider,
            rng: RefCell::new(R::from_entropy()),
        }
    }
}

impl<K, R> EnvelopeCipher<K, R>
where
    K: KeyProvider,
    R: SeedableRng + RngCore,
{
    pub async fn decrypt(
        &self,
        encrypted_record: EncryptedRecord,
    ) -> Result<Vec<u8>, DecryptionError> {
        let key = self
            .key_provider
            .decrypt_data_key(encrypted_record.encrypted_key.as_ref())
            .await?;

        let aad = encrypted_record.key_id;
        let msg = encrypted_record.ciphertext.as_ref();
        let payload = Payload {
            msg,
            aad: &aad.as_bytes(),
        };

        let cipher = Aes128Gcm::new(&key);
        let message = cipher.decrypt(&Nonce::from_slice(&encrypted_record.nonce), payload)?;

        return Ok(message);
    }

    pub async fn encrypt(&self, msg: &[u8]) -> Result<EncryptedRecord, EncryptionError> {
        let mut nonce_data = [0u8; 12];

        let data_key = self.key_provider.generate_data_key().await?;
        let key_id = data_key.key_id;

        self.rng.borrow_mut().try_fill_bytes(&mut nonce_data)?;

        let payload = Payload {
            msg,
            aad: key_id.as_bytes(),
        };

        let nonce = Nonce::from_slice(&nonce_data);

        // TODO: Use Zeroize for the drop
        let key = Key::from_slice(&data_key.key);
        let cipher = Aes128Gcm::new(key);
        let ciphertext = cipher.encrypt(&nonce, payload)?;

        return Ok(EncryptedRecord {
            ciphertext,
            nonce: nonce_data,
            encrypted_key: data_key.encrypted_key,
            key_id,
        });
    }
}
