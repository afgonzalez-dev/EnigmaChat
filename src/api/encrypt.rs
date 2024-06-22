use rocket::response::status::BadRequest;
use rocket::serde::{json::Json, Deserialize, Serialize};
use validator::Validate;
use validator_derive::Validate;

use crate::crypto::encryption::encrypt_message;
use crate::validators::validation::ErrorResponse;

#[derive(Debug, Validate, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct EncryptRequest {
    #[validate(length(equal = 12))]
    nonce: String,
    message: String,
    other_public_key: Vec<u8>,
    user_secret: Vec<u8>,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub ciphertext: Vec<u8>,
}

#[post("/encrypt", format = "json", data = "<request>")]
pub fn encrypt(
    request: Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, BadRequest<Json<ErrorResponse>>> {
    match request.validate() {
        Ok(_) => (),
        Err(e) => {
            return Err(BadRequest(Json(ErrorResponse {
                error: format!("Validation errors: {:?}", e),
            })))
        }
    };

    let ciphertext = encrypt_message(
        request.nonce.clone(),
        &request.message,
        &request.other_public_key,
        &request.user_secret,
    );

    Ok(Json(EncryptResponse { ciphertext }))
}
