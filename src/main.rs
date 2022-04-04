use envelope::{EnvelopeCipher, SimpleKeyProvider, EncryptedRecord};
use serde::{Serialize, Deserialize};

/* TODO
 * - KMS Implementation
 * - Version header (alg used, key provider used)
 * - Key caching
 * - Zeroize
 * - Bulk encrypt (could be used in conjunction with key caching)
 *   - i.e. encrypt a bunch of records with 1 data-key
 */

#[derive(Debug, Serialize, Deserialize)]
struct Foo {
    a: u32,
    b: u32,
    c: Vec<u8>,
    d: [u8; 16],
    e: String
}

fn main() {
    let key_provider = SimpleKeyProvider::init([0u8; 16]);

    let cipher: EnvelopeCipher<SimpleKeyProvider> = EnvelopeCipher::init(key_provider);
    let er = cipher.encrypt(b"hey there monkey boy").unwrap();

    /*let bytes = er.to_vec();
    let decoded: EncryptedRecord = ciborium::de::from_reader(&bytes[..]).unwrap();
    println!("ER: {:?}", decoded);*/
    //let aad = "foo";
    //let foo = Foo { a: 1, b: 100, c: vec![90, 100], d: [4u8; 16], e: String::from(aad) };
    let vec = er.to_vec().unwrap();
    println!("Bytes: {:?}", vec);

    let dec = EncryptedRecord::from_vec(vec).unwrap();
    println!("FOO: {:?}", dec);

    let pt = cipher.decrypt(dec).unwrap();

    println!("PT {:?}", std::str::from_utf8(&pt).unwrap());
}
