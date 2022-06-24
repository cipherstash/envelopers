use aws_sdk_kms::Client;
use envelopers::{EnvelopeCipher, KMSKeyProvider};
use futures::future::join_all;
use itertools::Itertools;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::error::Error;
use std::{fmt::Debug, future::Future, iter::IntoIterator};

const MESSAGE_COUNT: usize = 1_000;
const MESSAGE_SIZE_BYTES: usize = 1_000;
const MAX_PARALLEL_REQS: usize = 10;

async fn join_all_with_chunks<T, U: Debug, F: Future<Output = Result<T, U>>>(
    futures: Vec<F>,
) -> Vec<T> {
    let mut output = Vec::with_capacity(futures.len());

    for chunk in futures.into_iter().chunks(MAX_PARALLEL_REQS).into_iter() {
        output.extend(join_all(chunk).await.into_iter().map(|x| x.unwrap()));
    }

    output
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting benchmark, generating data.");
    let bench_start = std::time::Instant::now();

    let mut rng = ChaCha20Rng::from_entropy();
    let mut data = Vec::with_capacity(MESSAGE_COUNT);

    for _ in 0..MESSAGE_COUNT {
        let mut bytes: Vec<u8> = vec![0; MESSAGE_SIZE_BYTES];
        rng.try_fill_bytes(&mut bytes[..]).unwrap();
        data.push(bytes);
    }

    println!(
        "Data generation took {} seconds",
        bench_start.elapsed().as_secs()
    );

    let encryption_start = std::time::Instant::now();

    let client = Client::new(&aws_config::from_env().load().await);
    let provider = KMSKeyProvider::new(
        client,
        std::env::var("CS_KEY_ID").expect("Expected CS_KEY_ID env var to be present"),
    );

    let cipher: EnvelopeCipher<KMSKeyProvider> = EnvelopeCipher::init(provider);

    let encrypted = join_all_with_chunks(
        data.iter()
            .map(|message| cipher.encrypt(&message[..]))
            .collect(),
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
    )
    .await
    .into_iter()
    .collect::<Vec<Vec<u8>>>();

    println!(
        "Decryption took {} seconds",
        decryption_start.elapsed().as_secs()
    );

    println!(
        "Benchmark completed in {} seconds",
        bench_start.elapsed().as_secs()
    );

    assert_eq!(data.len(), decrypted.len());

    assert_eq!(data, decrypted);

    Ok(())
}
