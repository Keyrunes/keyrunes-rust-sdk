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
    dotenv::dotenv().ok();

    let base_url =
        std::env::var("KEYRUNES_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    println!("Connecting to Keyrunes at: {}", base_url);

    let client = KeyrunesClient::new(&base_url)?;

    let (username, email) = generate_random_user();
    let password = "password123".to_string();

    println!("\nRegistering new user...");
    println!("Username: {}", username);
    println!("Email: {}", email);

    match client.register(&username, &email, &password).await {
        Ok(user) => println!("User registered: {} ({})", user.username, user.email),
        Err(e) => println!("x Error registering: {}", e),
    }

    println!("\nLogging in...");
    match client.login(&username, &password).await {
        Ok(token) => {
            println!("Login successful! Token: {}", token.token);

            println!("\nGetting current user...");
            match client.get_current_user().await {
                Ok(user) => println!("Current user: {} ({})", user.username, user.email),
                Err(e) => println!("x Error getting current user: {}", e),
            }
        }
        Err(e) => println!("x Login error: {}", e),
    }

    Ok(())
}
