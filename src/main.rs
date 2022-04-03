mod key_provider;

use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead, Payload};
use crate::key_provider::*;
use rand::prelude::*;
use rand::Rng;
use rand_chacha::ChaChaRng;

/* TODO
 * - Key Provider trait
 * - KMS Implementation
 * - Version header
 * - Serde
 * - Random nonce
 * - Result type
 * - Key caching
 * - Decryption
 * - Bulk encrypt (could be used in conjunction with keu caching)
 *   - i.e. encrypt a bunch of records with 1 data-key
 */

/*#[derive(Debug)]
struct EncryptedRecord<'nonce, 'aad> {
    pub ciphertext: Vec<u8>,
    // Use a Vec here because the AWS Blob uses a Vec
    pub encrypted_key: Vec<u8>,
    pub nonce: &'nonce [u8],
    pub aad: &'aad [u8]
}

// TODO: Define a return type and wrap in a Result
fn encrypt<'nonce, 'aad>(wkey: DataKey<'_, 'aad>, plaintext: &[u8]) -> EncryptedRecord<'nonce, 'aad> {
    let key = Key::from_slice(wkey.key);
    let cipher = Aes256Gcm::new(key);

    // TODO: Use a RNG (pass a mutable RNG as an arg)
    let nonce = Nonce::from_slice(b"unique bonce"); // 96-bits; unique per message

    let payload = Payload { msg: plaintext, aad: wkey.key_id };

    let ciphertext = cipher.encrypt(nonce, payload)
      .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    return EncryptedRecord {
        ciphertext: ciphertext,
        nonce: nonce.as_slice(),
        encrypted_key: wkey.encrypted_key,
        aad: wkey.key_id
    }
}*/

fn main() {
    let key_provider = SimpleKeyProvider::<ChaChaRng>::init([0u8; 16]);
    let data_key = key_provider.generate_data_key();

    println!("DK: {:?}", data_key.unwrap());
}
