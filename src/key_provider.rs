use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or `Aes256Gcm`
use aes_gcm::aead::{Aead, NewAead, Payload};
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;

#[derive(Debug)]
pub struct DataKey<'keyid> {
    pub key: [u8; 16],
    pub encrypted_key: Vec<u8>,
    pub key_id: &'keyid str
}

#[derive(Debug)]
pub struct KeyGenerationError;

pub trait KeyProvider {
    fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError>;
}

pub struct SimpleKeyProvider<R: SeedableRng + RngCore> {
    kek: [u8; 16],
    rng: RefCell<R>
}

impl<R: SeedableRng + RngCore> SimpleKeyProvider<R> {
    pub fn init(kek: [u8; 16]) -> Self {
        Self {
            kek,
            rng: RefCell::new(R::from_entropy())
        }
    }
}

impl<R: SeedableRng + RngCore> KeyProvider for SimpleKeyProvider<R> {
    fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
        let key = Key::from_slice(&self.kek);
        let cipher = Aes128Gcm::new(key);
        let mut data_key = [0u8; 16];
        self.rng.borrow_mut().try_fill_bytes(&mut data_key).map_err(|_| KeyGenerationError)?;

        // FIXME: Don't use a fixed nonce
        let nonce = Nonce::from_slice(b"unique bonce");

        let payload = Payload { msg: &data_key, aad: b"" };
        let ciphertext = cipher.encrypt(nonce, payload).map_err(|_| KeyGenerationError)?;

        return Ok(DataKey {
            key: data_key,
            encrypted_key: ciphertext,
            key_id: &"simplekey"
        })
    }
}
