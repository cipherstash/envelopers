use envelopers::{ViturKeyProvider, EnvelopeCipher};
use std::error::Error;

async fn encrypt_and_generate(cipher: &EnvelopeCipher<ViturKeyProvider>, input: &str) {
    let encrypted = cipher
        .encrypt(input.as_bytes())
        .await
        .unwrap();

    println!(
        "INSERT INTO test (plaintext, ciphertext) VALUES ('{}', '\\x{}');",
        input,
        hex::encode(encrypted.to_vec().unwrap())
    );
} 

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let host = "https://e9d9-27-33-69-101.au.ngrok.io";
    let key_id = "70442f1d-630f-4546-8109-b1e6521860d3";
    let provider = ViturKeyProvider::new(host.into(), key_id.into());
    let cipher: EnvelopeCipher<ViturKeyProvider> = EnvelopeCipher::init(provider);

    for i in 0..100 {
        encrypt_and_generate(&cipher, &format!("Value {}", i)).await;
    }

    Ok(())
}