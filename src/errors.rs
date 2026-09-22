use aes_gcm::aead;
use thiserror::Error;

#[derive(Default, Error, Debug)]
pub enum EncryptionError {
    #[error("failed to encrypt payload")]
    AesEncryption,
    #[error("failed to generate data key")]
    KeyGeneration(#[from] KeyGenerationError),
    #[error("failed to generate random bytes")]
    RngGeneration(#[from] rand::Error),
    #[default]
    #[error("an unknown encryption error ocurred")]
    Unknown,
}

impl From<aead::Error> for EncryptionError {
    fn from(_: aead::Error) -> Self {
        Self::AesEncryption
    }
}

#[derive(Default, Error, Debug)]
pub enum DecryptionError {
    #[error("failed to decrypt payload")]
    AesDecryption,
    #[error("failed to decrypt data key")]
    KeyDecryption(#[from] KeyDecryptionError),
    #[default]
    #[error("an unknown decryption error ocurred")]
    Unknown,
}

impl From<aead::Error> for DecryptionError {
    fn from(_: aead::Error) -> Self {
        Self::AesDecryption
    }
}

#[derive(Debug, Default, Error)]
pub enum KeyGenerationError {
    #[error("failed to generate random bytes")]
    RngGeneration(#[from] rand::Error),
    #[error("failed to encrypt key payload")]
    AesEncryption,
    #[error("{0}")]
    Other(String),
    #[default]
    #[error("an unknown key generation error ocurred")]
    Unknown,
}

impl From<aead::Error> for KeyGenerationError {
    fn from(_: aead::Error) -> Self {
        Self::AesEncryption
    }
}

#[derive(Default, Error, Debug)]
pub enum KeyDecryptionError {
    #[error("failed to decrypt key")]
    AesDecryption,
    #[error("{0}")]
    Other(String),
    #[default]
    #[error("an unknown key decryption error ocurred")]
    Unknown,
}

impl From<aead::Error> for KeyDecryptionError {
    fn from(_: aead::Error) -> Self {
        Self::AesDecryption
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ERFromBytesError(#[from] serde_cbor::Error);

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ERToBytesError(#[from] serde_cbor::Error);
