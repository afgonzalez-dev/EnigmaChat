use rocket::serde::{json::Json, Deserialize, Serialize};

use crate::crypto::decryption::decrypt_message;

#[derive(Deserialize)]
pub struct DecryptRequest {
    ciphertext: Vec<u8>,
    other_public_key: Vec<u8>,
    user_secret: Vec<u8>,
    nonce: String,
}

#[derive(Serialize)]
pub struct DecryptResponse {
    pub message: String,
}

#[post("/decrypt", format = "json", data = "<request>")]
pub fn decrypt(request: Json<DecryptRequest>) -> Json<DecryptResponse> {
    let message = decrypt_message(
        &request.ciphertext,
        &request.other_public_key,
        &request.user_secret,
        &request.nonce,
    );

    Json(DecryptResponse { message })
}
