use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub struct UserKey {
    pub public_key: Vec<u8>,
    pub user_secret: Vec<u8>,
}

pub struct EncryptParams<'a> {
    pub message: &'a [u8],
    pub other_public_key: [u8; 32],
    pub user_secret: [u8; 32],
    pub nonce: &'a [u8],
}

pub struct DecryptParams<'a> {
    pub ciphertext: &'a [u8],
    pub other_public_key: [u8; 32],
    pub user_secret: [u8; 32],
    pub nonce: &'a [u8],
}

pub fn generate_user_key() -> UserKey {
    let user_secret: StaticSecret = StaticSecret::random_from_rng(OsRng);
    let user_public = PublicKey::from(&user_secret);

    UserKey {
        public_key: user_public.as_bytes().to_vec(),
        user_secret: user_secret.to_bytes().to_vec(),
    }
}

pub fn encrypt(params: EncryptParams) -> Vec<u8> {
    let user_secret = StaticSecret::from(params.user_secret);
    let other_public_key = PublicKey::from(params.other_public_key);

    let shared_secret = user_secret.diffie_hellman(&other_public_key);

    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(params.nonce);

    cipher
        .encrypt(nonce, params.message)
        .expect("encryption failure!")
}

pub fn decrypt(params: DecryptParams) -> Vec<u8> {
    let user_secret = StaticSecret::from(params.user_secret);
    let other_public_key = PublicKey::from(params.other_public_key);

    let shared_secret = user_secret.diffie_hellman(&other_public_key);

    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(params.nonce);

    cipher
        .decrypt(nonce, params.ciphertext)
        .expect("decryption failure!")
}
