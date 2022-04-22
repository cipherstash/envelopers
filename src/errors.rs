use aes_gcm::aead;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("failed to encrypt payload")]
    AesEncryption,
    #[error("failed to generate data key")]
    KeyGeneration(#[from] KeyGenerationError),
    #[error("failed to generate random bytes")]
    RngGeneration(#[from] rand::Error),
    #[error("an unknown encryption error ocurred")]
    Unknown,
    #[error("{0}")]
    Other(String),
}

impl Default for EncryptionError {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<aead::Error> for EncryptionError {
    fn from(_: aead::Error) -> Self {
        Self::AesEncryption
    }
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("failed to decrypt payload")]
    AesDecryption,
    #[error("failed to decrypt data key")]
    KeyDecryption(#[from] KeyDecryptionError),
    #[error("an unknown decryption error ocurred")]
    Unknown,
    #[error("{0}")]
    Other(String),
}

impl Default for DecryptionError {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<aead::Error> for DecryptionError {
    fn from(_: aead::Error) -> Self {
        Self::AesDecryption
    }
}

#[derive(Debug, Error)]
pub enum KeyGenerationError {
    #[error("failed to generate random bytes")]
    RngGeneration(#[from] rand::Error),
    #[error("failed to encrypt key payload")]
    AesEncryption,
    #[error("{0}")]
    Other(String),
    #[error("an unknown key generation error ocurred")]
    Unknown,
}

impl From<aead::Error> for KeyGenerationError {
    fn from(_: aead::Error) -> Self {
        Self::AesEncryption
    }
}

impl Default for KeyGenerationError {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Error, Debug)]
pub enum KeyDecryptionError {
    #[error("failed to decrypt key")]
    AesDecryption,
    #[error("{0}")]
    Other(String),
    #[error("an unknown key decryption error ocurred")]
    Unknown,
}

impl From<aead::Error> for KeyDecryptionError {
    fn from(_: aead::Error) -> Self {
        Self::AesDecryption
    }
}

impl Default for KeyDecryptionError {
    fn default() -> Self {
        Self::Unknown
    }
}
