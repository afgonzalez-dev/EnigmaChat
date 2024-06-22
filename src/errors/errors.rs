use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid length for secret key")]
    InvalidSecretKeyLength,
    #[error("Invalid length for public key")]
    InvalidPublicKeyLength,
    #[error("Decryption failure")]
    DecryptionFailure,
    #[error("UTF-8 conversion error")]
    Utf8ConversionError,
}
