//! Example usage of the Keyrunes SDK with Loco
//!
//! Note: Loco has a different structure. This example shows how to use
//! the helper functions from the library within Loco controllers.
//!
//! To use this example, you would need to import:
//! ```rust
//! use keyrunes_rust_sdk::KeyrunesClient;
//! use keyrunes_rust_sdk::middleware::loco::*;
//! ```

// Example of how to use in a Loco controller
//
// In a real Loco controller, you would use:
// use keyrunes_rust_sdk::middleware::loco::*;
//
// pub async fn get_current_user_controller(
//     headers: &http::HeaderMap,
//     state: &KeyrunesState,
// ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
//     let token = extract_token_from_headers(headers)
//         .ok_or("Authentication token missing")?;
//     let user = get_user_from_token(&state.client, &token).await?;
//     Ok(serde_json::json!({
//         "user_id": user.user.id,
//         "username": user.user.username,
//         "email": user.user.email,
//         "groups": user.user.groups,
//     }))
// }

#[tokio::main]
async fn main() {
    println!("This is an example of how to use the Keyrunes SDK with Loco.");
    println!("See the comments in the code to understand how to integrate.");
}
