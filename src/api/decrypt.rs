use log::info;
use rocket::response::status::BadRequest;
use rocket::serde::{json::Json, Deserialize, Serialize};

use crate::crypto::decryption::decrypt_message;
use crate::validators::validation::ErrorResponse;

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
pub fn decrypt(
    request: Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, BadRequest<Json<ErrorResponse>>> {
    info!("Received decryption request");

    match decrypt_message(
        &request.ciphertext,
        &request.other_public_key,
        &request.user_secret,
        &request.nonce,
    ) {
        Ok(message) => {
            info!("Message decrypted successfully");
            Ok(Json(DecryptResponse { message }))
        }
        Err(e) => {
            error!("Decryption error: {:?}", e);
            Err(BadRequest(Json(ErrorResponse {
                error: e.to_string(),
            })))
        }
    }
}
