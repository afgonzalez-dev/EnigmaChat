#[macro_use]
extern crate rocket;

use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use hex;
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(Serialize)]
struct UserKeyResponse {
    public_key: Vec<u8>,
    user_secret: Vec<u8>,
}

#[derive(Deserialize)]
struct EncryptRequest {
    message: String,
    other_public_key: Vec<u8>,
    user_secret: Vec<u8>,
    nonce: String,
}

#[derive(Serialize)]
struct EncryptResponse {
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct DecryptRequest {
    ciphertext: Vec<u8>,
    other_public_key: Vec<u8>,
    user_secret: Vec<u8>,
    nonce: String,
}

#[derive(Serialize)]
struct DecryptResponse {
    message: String,
}

#[post("/create_user_key")]
fn create_user_key() -> Json<UserKeyResponse> {
    let user_secret: StaticSecret = StaticSecret::random_from_rng(OsRng);
    let user_public = PublicKey::from(&user_secret);

    Json(UserKeyResponse {
        public_key: user_public.as_bytes().to_vec(),
        user_secret: user_secret.as_bytes().to_vec(),
    })
}

#[post("/encrypt", format = "json", data = "<request>")]
fn encrypt(request: Json<EncryptRequest>) -> Json<EncryptResponse> {
    let user_secret: [u8; 32] = request.user_secret.clone().try_into().unwrap();
    let other_public_key: [u8; 32] = request.other_public_key.clone().try_into().unwrap();
    let user_secret = StaticSecret::from(user_secret);
    let other_public_key = PublicKey::from(other_public_key);

    let shared_secret = user_secret.diffie_hellman(&other_public_key);

    let message = request.message.as_bytes();
    let nonce_bytes = hex::decode(&request.nonce).expect("Invalid hex string for nonce");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher.encrypt(nonce, message).expect("encryption failure!");

    Json(EncryptResponse { ciphertext })
}

#[post("/decrypt", format = "json", data = "<request>")]
fn decrypt(request: Json<DecryptRequest>) -> Json<DecryptResponse> {
    let user_secret: [u8; 32] = request.user_secret.clone().try_into().unwrap();
    let other_public_key: [u8; 32] = request.other_public_key.clone().try_into().unwrap();
    let user_secret = StaticSecret::from(user_secret);
    let other_public_key = PublicKey::from(other_public_key);

    let shared_secret = user_secret.diffie_hellman(&other_public_key);

    let ciphertext = request.ciphertext.as_slice();
    let nonce_bytes = hex::decode(&request.nonce).expect("Invalid hex string for nonce");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failure!");

    Json(DecryptResponse {
        message: String::from_utf8_lossy(&plaintext).to_string(),
    })
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![create_user_key, encrypt, decrypt])
}
