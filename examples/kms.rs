use aws_sdk_kms::Client;
use enveloper::{EnvelopeCipher, KMSKeyProvider};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new(&aws_config::from_env().load().await);

    let provider = KMSKeyProvider::new(client, std::env::var("CS_KEY_ID")?);

    let cipher: EnvelopeCipher<KMSKeyProvider> = EnvelopeCipher::init(provider);

    let encrypted = cipher.encrypt("This is a great test string!".as_bytes()).await?;

    let decrypted = cipher.decrypt(&encrypted).await?;

    println!("Decrypted: {}", String::from_utf8(decrypted)?);

    Ok(())
}
