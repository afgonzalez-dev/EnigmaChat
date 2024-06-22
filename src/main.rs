#[macro_use]
extern crate rocket;

mod api;
mod crypto;
mod validators;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount(
            "/",
            routes![
                api::user_key::create_user_key,
                api::encrypt::encrypt,
                api::decrypt::decrypt
            ],
        )
        .register("/", catchers![validators::validation::validation_catcher])
}
