# Keyrunes Rust SDK

A Rust library for integrating with the Keyrunes authentication and authorization service.

## Features

- ✅ Complete authentication (login, registration, admin registration)
- ✅ User management
- ✅ Group verification
- ✅ Integration with popular web frameworks: Axum, Actix Web, Rocket, and Loco
- ✅ Custom and descriptive error types
- ✅ Data models with serde
- ✅ Fully asynchronous with Tokio

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
keyrunes-rust-sdk = { version = "0.1.0", features = ["axum"] }  # or "actix", "rocket", etc.
```

### Available Features

- `axum` - Support for the Axum framework
- `actix` - Support for the Actix Web framework
- `rocket` - Support for the Rocket framework
- `loco` - Helper functions for the Loco framework

You can enable multiple features:

```toml
keyrunes-rust-sdk = { version = "0.1.0", features = ["axum", "actix"] }
```

## Basic Usage

```rust
use keyrunes_rust_sdk::KeyrunesClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new client instance
    let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    
    // Perform login
    let token = client.login("user@example.com", "password").await?;
    println!("Token: {}", token.token);
    
    // Get current user
    let user = client.get_current_user().await?;
    println!("User: {:?}", user);
    
    // Verify groups
    let groups = client.get_user_groups(None).await?;
    println!("Groups: {:?}", groups);
    
    Ok(())
}
```

## Web Framework Integration

### Axum

```rust
use axum::{
    extract::State,
    routing::get,
    Router,
};
use keyrunes_rust_sdk::{
    middleware::axum::{AuthenticatedUser, KeyrunesState},
    KeyrunesClient,
};

#[tokio::main]
async fn main() {
    let client = KeyrunesClient::new("https://keyrunes.example.com").unwrap();
    let state = KeyrunesState::new(client);
    
    let app = Router::new()
        .route("/me", get(|user: AuthenticatedUser| async move {
            format!("Hello, {}!", user.user.username)
        }))
        .with_state(state);
    
    // ... start server
}
```

### Actix Web

```rust
use actix_web::{get, web, App, HttpServer, Responder};
use keyrunes_rust_sdk::{
    middleware::actix::{AuthenticatedUser, KeyrunesState},
    KeyrunesClient,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = KeyrunesClient::new("https://keyrunes.example.com").unwrap();
    let state = KeyrunesState::new(client);
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(get_me)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[get("/me")]
async fn get_me(user: AuthenticatedUser) -> impl Responder {
    format!("Hello, {}!", user.user.username)
}
```

### Rocket

```rust
#[macro_use]
extern crate rocket;

use keyrunes_rust_sdk::{
    middleware::rocket::{AuthenticatedUser, KeyrunesState},
    KeyrunesClient,
};

#[launch]
fn rocket() -> _ {
    let client = KeyrunesClient::new("https://keyrunes.example.com").unwrap();
    let state = KeyrunesState::new(client);
    
    rocket::build()
        .manage(state)
        .mount("/", routes![get_me])
}

#[get("/me")]
fn get_me(user: AuthenticatedUser) -> String {
    format!("Hello, {}!", user.user.username)
}
```

### Loco

```rust
use keyrunes_rust_sdk::{
    middleware::loco::{
        extract_token_from_headers,
        get_user_from_token,
        KeyrunesState,
        require_admin,
    },
    KeyrunesClient,
};

async fn my_controller(
    headers: &http::HeaderMap,
    state: &KeyrunesState,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let token = extract_token_from_headers(headers)
        .ok_or("Token missing")?;
    
    let user = get_user_from_token(&state.client, &token).await?;
    require_admin(&state.client, &user).await?;
    
    Ok(serde_json::json!({"message": "Admin access granted"}))
}
```

## Client API

### Authentication

- `login(email, password)` - Performs login and returns token
- `register(username, email, password)` - Registers new user
- `register_admin(username, email, password, admin_key)` - Registers administrator
- `set_token(token)` - Sets token manually
- `clear_token()` - Clears the token

### Users

- `get_current_user()` - Gets current authenticated user
- `get_user(user_id)` - Gets user by ID

### Groups

- `has_group(user_id, group_id)` - Verifies if user belongs to group
- `get_user_groups(user_id)` - Gets list of user groups

## Data Models

- `User` - User model
- `Group` - Group model
- `Token` - Authentication token model
- `UserRegistration` - User registration data
- `AdminRegistration` - Administrator registration data
- `LoginCredentials` - Login credentials

## Error Handling

The library uses custom error types:

- `KeyrunesError::AuthenticationError` - Authentication error
- `KeyrunesError::AuthorizationError` - Authorization error
- `KeyrunesError::UserNotFoundError` - User not found
- `KeyrunesError::GroupNotFoundError` - Group not found
- `KeyrunesError::NetworkError` - Network error
- `KeyrunesError::HttpError` - HTTP error

## Examples

See the `examples/` folder for complete usage examples with each framework:

- `basic_usage.rs` - Basic client usage
- `axum_example.rs` - Axum integration
- `actix_example.rs` - Actix Web integration
- `rocket_example.rs` - Rocket integration
- `loco_example.rs` - Loco integration

To run an example:

```bash
cargo run --example basic_usage --features axum
```

## Requirements

- Rust 1.70+
- Tokio runtime (for async functionality)

## License

MIT OR Apache-2.0

## Contributing

Contributions are welcome! Please:

1. Fork the project
2. Create a branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Links

- [Keyrunes Main Repository](https://github.com/Keyrunes/keyrunes)
- [Python SDK](https://github.com/Keyrunes/keyrunes-python-sdk)
- [Complete Documentation](https://keyrunes.com/docs)

---

Made with ❤️ for the Keyrunes community
