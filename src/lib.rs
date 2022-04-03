
use rand::Rng;

pub struct EnvelopeCipher<K, R: Rng> {
    pub key_provider: K,
    pub rng: R
}

impl<K, R: Rng> EnvelopeCipher<K, R> {
    pub fn init(key_provider: K, rng: R) -> Self {
        Self { key_provider, rng }
    }
}

