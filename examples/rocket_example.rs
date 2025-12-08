//! Example usage of the Keyrunes SDK with Rocket

#[macro_use]
extern crate rocket;

use keyrunes_rust_sdk::{
    middleware::rocket::{AuthenticatedUser, KeyrunesState, RequireAdmin, RequireGroup},
    KeyrunesClient,
};
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
}

#[launch]
fn rocket() -> _ {
    let client = KeyrunesClient::new("https://keyrunes.example.com")
        .expect("Failed to create Keyrunes client");

    let state = KeyrunesState::new(client);

    rocket::build()
        .manage(state)
        .mount("/", routes![get_current_user, admin_only, require_group])
}

/// Route that requires authentication (current user)
#[get("/me")]
fn get_current_user(user: AuthenticatedUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": user.user.id,
        "username": user.user.username,
        "email": user.user.email,
        "groups": user.user.groups,
    }))
}

/// Route that requires administrator privileges
#[get("/admin")]
fn admin_only(_admin: RequireAdmin) -> Json<Message> {
    Json(Message {
        message: "Administrative access granted".to_string(),
    })
}

/// Route that requires a specific group
#[get("/group?<group_id>")]
fn require_group(group: RequireGroup) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": format!("User belongs to group: {}", group.group_id),
        "user": group.user.username,
    }))
}
