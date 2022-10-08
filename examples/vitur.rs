use envelopers::{ViturKeyProvider, EnvelopeCipher};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let host = "http://localhost:4000";
    let key_id = "70442f1d-630f-4546-8109-b1e6521860d3";
    let provider = ViturKeyProvider::new(host.into(), key_id.into());

    let cipher: EnvelopeCipher<ViturKeyProvider> = EnvelopeCipher::init(provider);

    let encrypted = cipher
        .encrypt_with_tag(
            "This is a great test string!".as_bytes(),
            Some("user-123".to_string())
        )
        .await?;

    println!("Encrypted: {:?}", encrypted);

    let decrypted = cipher.decrypt(&encrypted).await?;

    println!("Decrypted: {}", String::from_utf8(decrypted)?);

    Ok(())
}