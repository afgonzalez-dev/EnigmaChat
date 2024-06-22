use aes_gcm::aead::OsRng;
use log::info;
use rocket::serde::{json::Json, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize)]
pub struct UserKeyResponse {
    public_key: Vec<u8>,
    user_secret: Vec<u8>,
}

#[post("/create_user_key")]
pub fn create_user_key() -> Json<UserKeyResponse> {
    let user_secret: StaticSecret = StaticSecret::random_from_rng(OsRng);
    let user_public = PublicKey::from(&user_secret);

    info!("Generated new user key pair");

    Json(UserKeyResponse {
        public_key: user_public.as_bytes().to_vec(),
        user_secret: user_secret.to_bytes().to_vec(),
    })
}
