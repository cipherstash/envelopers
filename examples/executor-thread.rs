use aws_sdk_kms::Client;
use bmrng::unbounded::UnboundedRequestSender;
use enveloper::{
    DecryptionError, EncryptedRecord, EncryptionError, EnvelopeCipher, KMSKeyProvider,
};

#[derive(Debug)]
enum Request {
    Encryption(Vec<u8>),
    Decryption(EncryptedRecord),
    Shutdown,
}

#[derive(Debug)]
enum Response {
    Encryption(Result<EncryptedRecord, EncryptionError>),
    Decryption(Result<Vec<u8>, DecryptionError>),
    Shutdown,
}

struct SyncCipherProxy {
    runtime: tokio::runtime::Runtime,
    tx: UnboundedRequestSender<Request, Response>,
}

impl SyncCipherProxy {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let (tx, mut rx) = bmrng::unbounded_channel::<Request, Response>();

        let proxy_runtime = tokio::runtime::Runtime::new()?;
        let inner_runtime = tokio::runtime::Runtime::new()?;

        let client =
            proxy_runtime.block_on(async { Client::new(&aws_config::from_env().load().await) });

        let key_id = std::env::var("CS_KEY_ID").expect("Please export CS_KEY_ID");

        std::thread::spawn(move || {
            inner_runtime.block_on(async {
                let provider = KMSKeyProvider::new(client, key_id);
                let cipher: EnvelopeCipher<KMSKeyProvider> = EnvelopeCipher::init(provider);

                loop {
                    if let Ok((request, responder)) = rx.recv().await {
                        let response = match request {
                            Request::Encryption(x) => {
                                Response::Encryption(cipher.encrypt(&x).await)
                            }
                            Request::Decryption(x) => Response::Decryption(cipher.decrypt(x).await),
                            Request::Shutdown => Response::Shutdown,
                        };

                        if let Response::Shutdown = response {
                            responder.respond(Response::Shutdown).unwrap_or(());
                            break;
                        }

                        if let Err(_) = responder.respond(response) {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            });
        });

        Ok(Self {
            runtime: proxy_runtime,
            tx,
        })
    }
}

impl SyncCipherProxy {
    fn encrypt(&self, message: Vec<u8>) -> Result<EncryptedRecord, EncryptionError> {
        let tx = self.tx.clone();

        self.runtime.block_on(async move {
            if let Response::Encryption(result) = tx
                .send_receive(Request::Encryption(message))
                .await
                .unwrap_or(Response::Encryption(Err(EncryptionError::Unknown)))
            {
                result
            } else {
                Err(EncryptionError::Unknown)
            }
        })
    }

    fn decrypt(&self, record: EncryptedRecord) -> Result<Vec<u8>, DecryptionError> {
        let tx = self.tx.clone();

        self.runtime.block_on(async move {
            if let Response::Decryption(result) = tx
                .send_receive(Request::Decryption(record))
                .await
                .unwrap_or(Response::Decryption(Err(DecryptionError::Unknown)))
            {
                result
            } else {
                Err(DecryptionError::Unknown)
            }
        })
    }

    fn shutdown(&self) {
        let tx = self.tx.clone();

        self.runtime.block_on(async {
            tx.send_receive(Request::Shutdown)
                .await
                .expect("Failed to shut down");
        });
    }
}

impl Drop for SyncCipherProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn main() {
    let cipher = SyncCipherProxy::new().expect("Failed to create proxy");

    let encrypted = cipher
        .encrypt("This is a great test string!".as_bytes().into())
        .expect("Failed to encrypt string");

    let decrypted = cipher.decrypt(encrypted).expect("Failed to decrypt");

    println!(
        "Decrypted: {}",
        String::from_utf8(decrypted).expect("Invalid utf8")
    );

    let encrypted = cipher
        .encrypt("This is a great test string!".as_bytes().into())
        .expect("Failed to encrypt string");

    let decrypted = cipher.decrypt(encrypted).expect("Failed to decrypt");

    println!(
        "Decrypted: {}",
        String::from_utf8(decrypted).expect("Invalid utf8")
    );

    let encrypted = cipher
        .encrypt("This is a great test string!".as_bytes().into())
        .expect("Failed to encrypt string");

    let decrypted = cipher.decrypt(encrypted).expect("Failed to decrypt");

    println!(
        "Decrypted: {}",
        String::from_utf8(decrypted).expect("Invalid utf8")
    );

    let encrypted = cipher
        .encrypt("This is a great test string!".as_bytes().into())
        .expect("Failed to encrypt string");

    let decrypted = cipher.decrypt(encrypted).expect("Failed to decrypt");

    println!(
        "Decrypted: {}",
        String::from_utf8(decrypted).expect("Invalid utf8")
    );

}
