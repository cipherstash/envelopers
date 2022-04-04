mod key_provider;
pub use crate::key_provider::KeyProvider;
pub use crate::key_provider::SimpleKeyProvider;
use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or `Aes256Gcm`
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::cell::RefCell;
use serde::{Serialize, Deserialize};

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

#[derive(Debug)]
pub struct EncryptionError;

#[derive(Debug)]
pub struct DecryptionError;

pub struct EnvelopeCipher<K, R = ChaChaRng>
where
    K: KeyProvider,
    R: SeedableRng + RngCore,
{
    pub key_provider: K,
    pub rng: RefCell<R>,
}

impl<K, R> EnvelopeCipher<K, R>
where
    K: KeyProvider,
    R: SeedableRng + RngCore,
{
    pub fn init(key_provider: K) -> Self {
        Self {
            key_provider,
            rng: RefCell::new(R::from_entropy()),
        }
    }

    pub fn decrypt(&self, encrypted_record: EncryptedRecord) -> Result<Vec<u8>, DecryptionError> {
        let key = self
            .key_provider
            .decrypt_data_key(encrypted_record.encrypted_key.as_ref())
            .map_err(|_| DecryptionError)?;

        let aad = encrypted_record.key_id;
        let msg = encrypted_record.ciphertext.as_ref();
        let payload = Payload { msg, aad: &aad.as_bytes() };

        let cipher = Aes128Gcm::new(&key);
        let message = cipher
            .decrypt(&Nonce::from_slice(&encrypted_record.nonce), payload)
            .map_err(|_| DecryptionError)?;

        return Ok(message);
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<EncryptedRecord, EncryptionError> {
        let mut nonce_data = [0u8; 12];
        let data_key = self
            .key_provider
            .generate_data_key()
            .map_err(|_| EncryptionError)?;

        let key_id = data_key.key_id;

        self.rng
            .borrow_mut()
            .try_fill_bytes(&mut nonce_data)
            .map_err(|_| EncryptionError)?;

        let payload = Payload { msg, aad: key_id.as_bytes() };

        let nonce = Nonce::from_slice(&nonce_data);

        // TODO: Use Zeroize for the drop
        let key = Key::from_slice(&data_key.key);
        let cipher = Aes128Gcm::new(key);
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| EncryptionError)?;

        return Ok(EncryptedRecord {
            ciphertext,
            nonce: nonce_data,
            encrypted_key: data_key.encrypted_key,
            key_id,
        });
    }
}
