use envelopers::{ViturKeyProvider, EnvelopeCipher};
use std::error::Error;

async fn encrypt_and_generate(cipher: &EnvelopeCipher<ViturKeyProvider>, id: u32) {
    let tag = format!("user-{}", id).to_string();

    let encrypted = cipher
        .encrypt_with_tag(format!("user{}@example.net", id).as_bytes(), &Some(tag))
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
    let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ijg4TnNqZjNFR1JCOWs2QVZyU21wcyJ9.eyJpc3MiOiJodHRwczovL2NpcGhlcnN0YXNoLWRldi5hdS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NjEyYWViYjRjMmFkMWMwMDcxNmMxNWJlIiwiYXVkIjoiaHR0cHM6Ly92aXR1ci5hdS5uZ3Jvay5pbyIsImlhdCI6MTY2NTMxNjQ1OSwiZXhwIjoxNjY1NDAyODU5LCJhenAiOiJ0ejVkYUNIRlFMSlJzaGxrOXhyMlRsMUcyblZKUDVudiJ9.LFedxMWJ_L5NoGf5gXWrWITijDvyfjA1bkGsD9lnhq80Y5ODO5KvUT-_4TYQvPSeJbfGkLu_cJ-mxO-zRqVgfo1qhTRaQndFRQgqsHwXyrdgbZQYdhx1MGKT1f2pI80YCHed-zN2BuPW4GQMONQnYOGvkL8f4LllXhGQJGeVoMf7QHqpmS3AFi4tWXRS9z5ONb6yB5W45dUwTgbFItreSa1L2e32MGAAnQNqkKWZhLCTxXXgtBA7NNkqFivBgOq1i8utzeyQRpJTfPUnczGgYpkCB-EKeGV0EW6qYdhVFIT3yTI09jrsFzS023VvZocwLb0nmhqO1SNKbhd2KJXQ7g";
    let provider = ViturKeyProvider::new(host.into(), key_id.into(), access_token.into());
    let cipher: EnvelopeCipher<ViturKeyProvider> = EnvelopeCipher::init(provider);

    for i in 0..100 {
        encrypt_and_generate(&cipher, i).await;
    }

    Ok(())
}