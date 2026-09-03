use keyrunes_rust_sdk::KeyrunesClient;

fn generate_random_user() -> (String, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let random_id = timestamp % 1000000;
    let username = format!("user_{}", random_id);
    let email = format!("user_{}@example.com", random_id);

    (username, email)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let base_url =
        std::env::var("KEYRUNES_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    println!("Connecting to Keyrunes at: {}", base_url);

    let client = KeyrunesClient::new(&base_url)?;

    // Create a user to demonstrate password operations
    let (username, email) = generate_random_user();
    let password = "password123".to_string();
    let new_password = "newPassword456".to_string();

    println!("\nRegistering new user for password demo...");
    println!("Username: {}", username);
    println!("Email: {}", email);

    let user_id = match client.register(&username, &email, &password, None).await {
        Ok(user) => {
            println!("User registered: {} ({})", user.username, user.id);
            user.id
        }
        Err(e) => {
            println!("x Error registering: {}", e);
            return Ok(());
        }
    };

    // Login to get a token for authenticated operations
    println!("\nLogging in to get token...");
    match client.login(&username, &password, None).await {
        Ok(_token) => {
            println!("Login successful! Token obtained.");

            // 1. forgot_password - Request password reset
            println!("\n1. Testing forgot_password...");
            match client.forgot_password(&email, None).await {
                Ok(response) => println!("   Reset URL: {}", response.reset_url),
                Err(e) => println!("   x Error: {}", e),
            }

            // 2. change_password - Change password while logged in
            println!("\n2. Testing change_password...");
            match client.change_password(&password, &new_password).await {
                Ok(response) => println!("   Success: {}", response.message),
                Err(e) => println!("   x Error: {}", e),
            }

            // Login with new password to verify change worked
            println!("\n   Verifying password change by logging in with new password...");
            match client.login(&username, &new_password, None).await {
                Ok(_) => println!("   Password change verified!"),
                Err(e) => println!("   x Password change failed: {}", e),
            }
        }
        Err(e) => println!("x Login error: {}", e),
    }

    // 3. reset_password - Reset with token (would normally come from email)
    println!("\n3. Testing reset_password (with dummy token)...");
    match client
        .reset_password("dummy-token", "anotherNewPassword", None)
        .await
    {
        Ok(response) => println!("   Success: {}", response.message),
        Err(e) => println!("   x Expected error (invalid token): {}", e),
    }

    // Admin operations require admin token - demonstrate with placeholder
    println!("\n4. Testing admin_reset_user_password (requires admin token)...");
    println!("   Note: This requires an admin token to be set first");
    match client.admin_reset_user_password(&user_id).await {
        Ok(response) => println!("   Temporary password: {}", response.temporary_password),
        Err(e) => println!("   x Expected error (no admin token): {}", e),
    }

    println!("\n5. Testing admin_send_password_reset (requires admin token)...");
    println!("   Note: This requires an admin token to be set first");
    match client.admin_send_password_reset(&user_id).await {
        Ok(response) => println!("   Success: {}", response.message),
        Err(e) => println!("   x Expected error (no admin token): {}", e),
    }

    println!("\nPassword management demo complete!");
    println!("User ID for admin testing: {}", user_id);

    Ok(())
}
