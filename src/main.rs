use envelope::{EnvelopeCipher, SimpleKeyProvider};

/* TODO
 * - KMS Implementation
 * - Version header
 * - Serde (for ciphertexts. BSON plaintexts to vector should be in a separate library)
 * - Key caching
 * - Zeroize
 * - Bulk encrypt (could be used in conjunction with key caching)
 *   - i.e. encrypt a bunch of records with 1 data-key
 */

fn main() {
    let key_provider = SimpleKeyProvider::init([0u8; 16]);

    let cipher: EnvelopeCipher<SimpleKeyProvider> = EnvelopeCipher::init(key_provider);
    let er = cipher.encrypt(b"hey there monkey boy").unwrap();

    println!("ER: {:?}", er);

    let pt = cipher.decrypt(er).unwrap();

    println!("PT {:?}", std::str::from_utf8(&pt).unwrap());
}
