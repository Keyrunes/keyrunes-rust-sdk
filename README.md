# Keyrunes Rust SDK

A Rust library for integrating with the Keyrunes authentication and authorization service.
[crates.io](https://crates.io/crates/keyrunes-rust-sdk)

## Features

- ✅ Complete authentication (login, registration, admin registration)
- ✅ User management
- ✅ Group verification
- ✅ Integration with popular web frameworks: Axum, Actix Web, Rocket, and Loco
- ✅ Custom and descriptive error types
- ✅ Data models with serde
- ✅ Fully asynchronous with Tokio
- ✅ Password management (forgot, reset, change, admin reset)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
keyrunes-rust-sdk = { version = "0.2", features = ["axum"] }  # or "actix", "rocket", etc.
```

### Available Features

- `axum` - Support for the Axum framework
- `actix` - Support for the Actix Web framework
- `rocket` - Support for the Rocket framework
- `loco` - Helper functions for the Loco framework

You can enable multiple features:

```toml
keyrunes-rust-sdk = { version = "0.2", features = ["axum", "actix"] }
```

## Basic Usage

```rust
use keyrunes_rust_sdk::KeyrunesClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new client instance
    let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    
    // Perform login. The last argument is the namespace; `None` means
    // "public", which the server requires and the client always sends.
    let token = client.login("user@example.com", "password", None).await?;
    println!("Token: {}", token.token);
    
    // Get current user
    let user = client.get_current_user().await?;
    println!("User: {:?}", user);
    
    // Groups of the current user. `None` asks about whoever the token
    // belongs to; the turbofish names the string type that is being
    // omitted, which nothing else in the call can tell the compiler.
    let groups = client.get_user_groups(None::<&str>).await?;
    println!("Groups: {:?}", groups);
    
    Ok(())
}
```

### Organization Key

If you need to access specific organization data in a multi-tenant environment, you can set the `KEYRUNES_ORG_KEY` environment variable. The client will automatically inject the `X-Organization-Key` header into requests.

```bash
export KEYRUNES_ORG_KEY=your-org-uuid
```

## Web Framework Integration

### Axum

```rust
use axum::{routing::get, Router};
use keyrunes_rust_sdk::{
    middleware::axum::{AuthenticatedUser, KeyrunesState},
    KeyrunesClient,
};

#[tokio::main]
async fn main() {
    let client = KeyrunesClient::new("https://keyrunes.example.com").unwrap();
    let state = KeyrunesState::new(client);

    let app = Router::new().route("/me", get(get_me)).with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// The extractor pulls the caller out of the request, so a route that names
// `AuthenticatedUser` cannot be reached without a valid token.
async fn get_me(user: AuthenticatedUser) -> String {
    format!("Hello, {}!", user.user.username)
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

Every `namespace` argument is an `Option`: `None` sends the default,
`"public"`. The field is always serialised, because the server rejects a
payload without it.

### Authentication

- `login(identity, password, namespace)` - Performs login and returns token
- `register(username, email, password, namespace)` - Registers new user
- `register_admin(username, email, password, admin_key, namespace)` - Registers administrator
- `set_token(token)` - Sets token manually
- `clear_token()` - Clears the token

### Users

- `get_current_user()` - Gets current authenticated user
- `get_user(user_id)` - Gets user by ID
- `base_url()` - The normalised base URL this client targets

### Groups

- `current_user_has_group(group_name)` - Whether the current user is in the named group
- `get_user_groups(user_id)` - Gets group names; pass `None::<&str>` for the current user
- `has_group(user_id, group_id)` - **Deprecated.** The route it calls was removed
  from the server; use `current_user_has_group` instead

### Password Management

- `forgot_password(email, namespace)` - Requests a password reset email
- `reset_password(token, new_password, namespace)` - Resets password using token from email
- `change_password(current_password, new_password)` - Changes password for authenticated user
- `admin_reset_user_password(user_id)` - Admin resets user password, returns temporary password
- `admin_send_password_reset(user_id)` - Admin sends password reset email to user

## Data Models

- `User` - User model
- `Group` - Group model
- `Token` - Authentication token model
- `UserRegistration` - User registration data
- `AdminRegistration` - Administrator registration data
- `LoginCredentials` - Login credentials
- `ForgotPasswordRequest` - Forgot password request data
- `ForgotPasswordResponse` - Forgot password response (message + reset URL)
- `ResetPasswordRequest` - Reset password request data
- `ChangePasswordRequest` - Change password request data
- `MessageResponse` - Generic message response
- `PasswordResetResponse` - Admin password reset response (temporary password)
- `GroupCheck` - Membership answer, read from either `has_group` or `has_access`
- `GroupVerificationResponse` - Full group verification response
- `DEFAULT_NAMESPACE` - The namespace used when a call is given `None`: `"public"`

## Error Handling

The library uses custom error types:

- `KeyrunesError::AuthenticationError` - Authentication error
- `KeyrunesError::AuthorizationError` - Authorization error
- `KeyrunesError::UserNotFoundError` - User not found
- `KeyrunesError::GroupNotFoundError` - Group not found
- `KeyrunesError::NetworkError` - Network error
- `KeyrunesError::HttpError` - HTTP error
- `KeyrunesError::SerializationError` - The response body was not what was expected
- `KeyrunesError::InvalidUrl` - The base URL given to `KeyrunesClient::new` is not a URL
- `KeyrunesError::InvalidToken` - A call needing a token was made without one
- `KeyrunesError::Other` - Anything uncategorised

A 404 is reported as `UserNotFoundError` or `GroupNotFoundError` when the
server's own message names one, and as `Other` otherwise. Only the message
decides: the request URL is appended for context and is not read.

## Examples

See the `examples/` folder for complete usage examples with each framework:

- `basic_usage.rs` - Basic client usage
- `axum_example.rs` - Axum integration
- `actix_example.rs` - Actix Web integration
- `rocket_example.rs` - Rocket integration
- `loco_example.rs` - Loco integration
- `password_management.rs` - Password management flow

To run an example:

```bash
cargo run --example basic_usage --features axum
```

## Testing

```bash
cargo test --all-features        # the whole suite
./scripts/coverage-check.sh      # coverage, gated at 90% of lines
./scripts/audit.sh               # advisories, with the h2 exception guarded
./scripts/mutants.sh core        # mutation testing, library
./scripts/mutants.sh middleware  # mutation testing, framework adapters
```

Four kinds of test sit behind those commands.

**Example-based** tests (`tests/client_test.rs`, `tests/models_test.rs`, the
per-framework suites) pin the behaviour of one call against a mocked server.

**Property-based** tests (`tests/property_test.rs`, `tests/fuzz_test.rs`) state
what must hold for any input and let `proptest` search for a counter-example.

**Exhaustive** tests (`tests/exhaustive_test.rs`, and the module at the end of
`src/client.rs`) enumerate a modelled input space in full rather than sampling
it: every combination of the three ID fields a Keyrunes response may carry,
every shape an error body may arrive in, every way a base URL may be typed. The
cases that break a parser are rarely the ones a test author thinks to write
down — a field present but `null`, an ID that is the empty string, a body
sitting exactly on the preview limit — so they are not left to chance.

**Mutation** testing closes the loop. Coverage says a line ran; `cargo-mutants`
rewrites one expression at a time and reruns the suite, so a surviving mutant
marks a line that ran without anything checking what it did. The gate fails on
any survivor.

Every one of these gates also runs as a pre-commit hook, so the pipeline holds
no surprises. Installing them:

```bash
pre-commit install
cargo install cargo-mutants cargo-audit cargo-llvm-cov --locked
```

The Rust hooks are scoped to `*.rs` and the manifest, so a documentation commit
still costs nothing. If the full set is too slow for your loop, move the
`cargo-coverage` and `cargo-mutants` hooks to `stages: [pre-push]`.

## Requirements

- Rust 1.88+ — declared as `rust-version` in `Cargo.toml`, so cargo says so
  rather than failing somewhere inside a dependency
- Tokio runtime (for async functionality)

## License

AGPL-3.0. The full text is in [LICENSE](LICENSE).

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
