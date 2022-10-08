use envelopers::{ViturKeyProvider, EnvelopeCipher};
use std::error::Error;

async fn encrypt_and_generate(cipher: &EnvelopeCipher<ViturKeyProvider>, id: u32) {
    let tag = format!("user-{}", id).to_string();

    let encrypted = cipher
        .encrypt_with_tag(format!("user{}@example.net", id).as_bytes(), Some(tag))
        .await
        .unwrap();

    println!(
        "INSERT INTO test (user_id, email) VALUES ('{}', '\\x{}');",
        id,
        hex::encode(encrypted.to_vec().unwrap())
    );
} 

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let host = "http://localhost:4000";
    let key_id = "70442f1d-630f-4546-8109-b1e6521860d3";
    let provider = ViturKeyProvider::new(host.into(), key_id.into());
    let cipher: EnvelopeCipher<ViturKeyProvider> = EnvelopeCipher::init(provider);

    for i in 0..100 {
        encrypt_and_generate(&cipher, i).await;
    }

    Ok(())
}