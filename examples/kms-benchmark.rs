use aws_sdk_kms::Client;
use envelopers::{CacheOptions, EnvelopeCipher, KMSKeyProvider};
use futures::future::join_all;
use itertools::Itertools;
use rand::{distributions::Alphanumeric, Rng};
use std::{error::Error, fmt::Debug, future::Future, iter::IntoIterator, time::Duration};

// The number of messages to be encrypted and decrypted
const MESSAGE_COUNT: usize = 1_000;

// The size of the message in characters of each message
const MESSAGE_SIZE_CHARS: usize = 1024;

// The number of futures to be joined at the same time. Practically this represents the number of
// parallel requests to KMS.
//
// Note: If this number is set too high it can exceed the number of concurrent requests that the
// KMS client can handle.
const MAX_PARALLEL_REQS: usize = 10;

async fn join_all_with_chunks<T, U: Debug, F: Future<Output = Result<T, U>>>(
    futures: Vec<F>,
    chunk_size: usize,
) -> Vec<T> {
    let mut output = Vec::with_capacity(futures.len());

    for chunk in futures.into_iter().chunks(chunk_size).into_iter() {
        output.extend(join_all(chunk).await.into_iter().map(|x| x.unwrap()));
    }

    output
}

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

    // Create a new KMSKeyProvider using the KMS key specified by the CS_KEY_ID environment
    // variable.
    let provider = KMSKeyProvider::new(
        client,
        std::env::var("CS_KEY_ID")
            .expect("Please export CS_KEY_ID environment variable with your AWS KMS key id."),
    );

    let cipher: EnvelopeCipher<KMSKeyProvider> = EnvelopeCipher::init(
        provider,
        CacheOptions::default()
            .with_max_age(Duration::from_secs(30))
            .with_max_bytes(10 * 1024)
            .with_max_messages(100)
            .with_max_entries(100),
    );

    let data: Vec<String> = (0..MESSAGE_COUNT)
        .map(|_| {
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(MESSAGE_SIZE_CHARS)
                .map(char::from)
                .collect()
        })
        .collect();

    let encryption_start = std::time::Instant::now();

    println!("Starting encryptions!");

    let encrypted = join_all_with_chunks(
        data.iter()
            .map(|message| cipher.encrypt(message.as_bytes()))
            .collect(),
        MAX_PARALLEL_REQS,
    )
    .await;

    println!(
        "Encryption took {} seconds",
        encryption_start.elapsed().as_secs()
    );

    let decryption_start = std::time::Instant::now();

    let decrypted = join_all_with_chunks(
        encrypted
            .iter()
            .map(|record| cipher.decrypt(record))
            .collect(),
        MAX_PARALLEL_REQS,
    )
    .await
    .into_iter()
    .map(|x| String::from_utf8(x).unwrap())
    .collect::<Vec<_>>();

    println!(
        "Decryption took {} seconds",
        decryption_start.elapsed().as_secs()
    );

    assert_eq!(data.len(), decrypted.len());

    assert_eq!(data, decrypted);

    Ok(())
}
