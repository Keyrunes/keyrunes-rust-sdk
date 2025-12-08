use keyrunes_rust_sdk::{KeyrunesClient, KeyrunesError};
use mockito::Server;

#[tokio::test]
async fn test_client_new() {
    let client = KeyrunesClient::new("https://example.com");
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_client_new_invalid_url() {
    let client = KeyrunesClient::new("not-a-url");
    assert!(client.is_err());
}

#[tokio::test]
async fn test_login_success() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"token":"test-token-123"}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user@example.com", "password").await;

    // #assert
    assert!(result.is_ok());
    let token = result.unwrap();
    assert_eq!(token.token, "test-token-123");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_login_failure() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Invalid credentials"}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user@example.com", "wrong").await;

    // #assert
    assert!(result.is_err());
    match result.unwrap_err() {
        KeyrunesError::AuthenticationError(_) => {}
        _ => panic!("Expected AuthenticationError"),
    }

    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_success() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user":{"user_id":123,"username":"john","email":"john@example.com","groups":[]},"token":"test-token","requires_password_change":false}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client
        .register("john", "john@example.com", "password123")
        .await;

    // #assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.id, "123");
    assert_eq!(user.username, "john");
    assert_eq!(user.email, "john@example.com");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_failure() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Email already exists"}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client
        .register("john", "john@example.com", "password123")
        .await;

    // #assert
    assert!(result.is_err());

    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_and_login_flow() {
    // #setup
    let mut server = Server::new_async().await;

    let register_mock = server
        .mock("POST", "/api/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user":{"user_id":123,"username":"john","email":"john@example.com","groups":[]},"token":"test-token","requires_password_change":false}"#)
        .create_async()
        .await;

    let login_mock = server
        .mock("POST", "/api/login")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"token":"test-token-456"}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let user = client
        .register("john", "john@example.com", "password123")
        .await
        .unwrap();
    let token = client
        .login("john@example.com", "password123")
        .await
        .unwrap();

    // #assert
    assert_eq!(user.username, "john");
    assert_eq!(token.token, "test-token-456");

    register_mock.assert_async().await;
    login_mock.assert_async().await;
}

#[tokio::test]
async fn test_set_token() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user_id":999,"username":"test","email":"test@example.com","groups":[]}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();

    // #act
    client.set_token("test-token-123").await;
    let user = client.get_current_user().await;

    // #assert
    assert!(user.is_ok());
    assert_eq!(user.unwrap().username, "test");
    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_current_user_success() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token-456")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":123,"username":"john","email":"john@example.com","groups":["users"]}"#,
        )
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-456").await;

    // #act
    let result = client.get_current_user().await;

    // #assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.id, "123");
    assert_eq!(user.username, "john");
    assert_eq!(user.email, "john@example.com");
    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_current_user_no_token() {
    // #setup
    let client = KeyrunesClient::new("https://example.com").unwrap();

    // #act
    let result = client.get_current_user().await;

    // #assert
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::InvalidToken));
}

#[tokio::test]
async fn test_get_current_user_unauthorized() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer invalid-token")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Invalid token"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("invalid-token").await;

    // #act
    let result = client.get_current_user().await;

    // #assert
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        KeyrunesError::AuthenticationError(_)
    ));
    mock.assert_async().await;
}
