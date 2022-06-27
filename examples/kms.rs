use aws_sdk_kms::Client;
use envelopers::{CacheOptions, EnvelopeCipher, KMSKeyProvider};
use std::error::Error;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load the AWS KMS client from the local environment.
    //
    // If using AWS secret keys, ensure your credentials are set in ~/.aws/credentials,
    // or set the following environment variables:
    // - AWS_ACCESS_KEY_ID
    // - AWS_SECRET_ACCESS_KEY
    //
    // Alternatively, if using AWS STS set the following environment variables:
    // - AWS_SECRET_ACCESS_KEY
    // - AWS_SESSION_TOKEN
    // - AWS_ACCESS_KEY_ID
    // - AWS_REGION
    let client = Client::new(&aws_config::from_env().load().await);

    let provider = KMSKeyProvider::new(client, std::env::var("CS_KEY_ID")?);

    let cipher: EnvelopeCipher<KMSKeyProvider> = EnvelopeCipher::init(
        provider,
        CacheOptions::default()
            .with_max_age(Duration::from_secs(30))
            .with_max_bytes(100 * 1024)
            .with_max_messages(10)
            .with_max_entries(10),
    );

    let encrypted = cipher
        .encrypt("This is a great test string!".as_bytes())
        .await?;

    let decrypted = cipher.decrypt(&encrypted).await?;

    println!("Decrypted: {}", String::from_utf8(decrypted)?);

    Ok(())
}
