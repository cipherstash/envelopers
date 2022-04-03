use envelope::{EnvelopeCipher, KeyProvider, SimpleKeyProvider};

/* TODO
 * - KMS Implementation
 * - Version header
 * - Serde
 * - Key caching
 * - Decryption
 * - Bulk encrypt (could be used in conjunction with keu caching)
 *   - i.e. encrypt a bunch of records with 1 data-key
 */

fn main() {
    let key_provider = SimpleKeyProvider::init([0u8; 16]);

    let cipher: EnvelopeCipher<SimpleKeyProvider> = EnvelopeCipher::init(key_provider);
    let er = cipher.encrypt(b"hey there monkey boy").unwrap();

    println!("ER: {:?}", er);
}
