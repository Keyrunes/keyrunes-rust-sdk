//! Example usage of the Keyrunes SDK with Axum

use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use keyrunes_rust_sdk::{
    middleware::axum::{AuthenticatedUser, KeyrunesState, RequireAdmin, RequireGroup},
    KeyrunesClient,
};
use serde_json::{json, Value};

#[tokio::main]
async fn main() {
    let client = KeyrunesClient::new("https://keyrunes.example.com")
        .expect("Failed to create Keyrunes client");

    let state = KeyrunesState::new(client);

    let app = Router::new()
        .route("/me", get(get_current_user))
        .route("/admin", get(admin_only))
        .route("/group", get(require_group))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running at http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

/// Route that requires authentication (current user)
async fn get_current_user(
    State(_state): State<KeyrunesState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "user_id": user.user.id,
        "username": user.user.username,
        "email": user.user.email,
        "groups": user.user.groups,
    })))
}

/// Route that requires administrator privileges
async fn admin_only(
    State(_state): State<KeyrunesState>,
    admin: RequireAdmin,
) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "message": "Administrative access granted",
        "user": admin.user.username,
    })))
}

/// Route that requires a specific group
async fn require_group(
    State(_state): State<KeyrunesState>,
    group: RequireGroup,
) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "message": format!("User belongs to group: {}", group.group_id),
        "user": group.user.username,
    })))
}
