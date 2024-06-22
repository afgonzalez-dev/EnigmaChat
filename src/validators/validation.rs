use rocket::serde::{json::Json, Serialize};
use rocket::{response::status::BadRequest, Request};

#[derive(Serialize)]
pub struct ErrorResponse {
    pub(crate) error: String,
}

#[catch(400)]
pub fn validation_catcher(req: &Request) -> BadRequest<Json<ErrorResponse>> {
    let error = format!("Invalid request: {:?}", req);
    BadRequest(Json(ErrorResponse { error }))
}
