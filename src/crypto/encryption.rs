use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::errors::errors::CryptoError;

pub fn encrypt_message(
    nonce: String,
    message: &str,
    other_public_key: &[u8],
    user_secret: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let user_secret: [u8; 32] = user_secret
        .try_into()
        .map_err(|_| CryptoError::InvalidSecretKeyLength)?;

    let other_public_key: [u8; 32] = other_public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKeyLength)?;

    let user_secret = StaticSecret::from(user_secret);
    let other_public_key = PublicKey::from(other_public_key);

    let shared_secret = user_secret.diffie_hellman(&other_public_key);

    let nonce_bytes = nonce.as_bytes();
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    Ok(cipher
        .encrypt(nonce, message.as_bytes())
        .expect("encryption failure!"))
}
