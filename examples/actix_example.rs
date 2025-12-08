//! Example usage of the Keyrunes SDK with Actix Web

use actix_web::{
    get, middleware, web, App, HttpResponse, HttpServer, Responder, Result as ActixResult,
};
use keyrunes_rust_sdk::{
    middleware::actix::{require_admin, AuthenticatedUser, KeyrunesState},
    KeyrunesClient,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = KeyrunesClient::new("https://keyrunes.example.com")
        .expect("Failed to create Keyrunes client");

    let state = KeyrunesState::new(client);

    println!("Server running at http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(middleware::Logger::default())
            .service(get_current_user)
            .service(admin_only)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

/// Route that requires authentication (current user)
#[get("/me")]
async fn get_current_user(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.user.id,
        "username": user.user.username,
        "email": user.user.email,
        "groups": user.user.groups,
    }))
}

/// Route that requires administrator privileges
#[get("/admin")]
async fn admin_only(req: actix_web::HttpRequest) -> actix_web::Result<impl Responder> {
    let admin = require_admin(&req).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Administrative access granted",
        "user": admin.user.username,
    })))
}
