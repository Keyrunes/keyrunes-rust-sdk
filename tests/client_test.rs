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
    let result = client.login("user@example.com", "password", None).await;

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
    let result = client.login("user@example.com", "wrong", None).await;

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
        .register("john", "john@example.com", "password123", None)
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
        .register("john", "john@example.com", "password123", None)
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
        .register("john", "john@example.com", "password123", None)
        .await
        .unwrap();
    let token = client
        .login("john@example.com", "password123", None)
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

#[tokio::test]
async fn test_register_admin_success() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user":{"user_id":999,"username":"admin","email":"admin@example.com","groups":["admins"]},"token":"admin-token","requires_password_change":false}"#,
        )
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();

    // #act
    let result = client
        .register_admin(
            "admin",
            "admin@example.com",
            "password123",
            "admin-key",
            None,
        )
        .await;

    // #assert
    assert!(result.is_ok());
    let admin = result.unwrap();
    assert_eq!(admin.username, "admin");
    assert_eq!(admin.email, "admin@example.com");
    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_user_success() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/users/123")
        .match_header("authorization", "Bearer test-token-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":123,"username":"john","email":"john@example.com","groups":["users"]}"#,
        )
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-789").await;

    // #act
    let result = client.get_user("123").await;

    // #assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.id, "123");
    assert_eq!(user.username, "john");
    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_user_not_found() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/users/999")
        .match_header("authorization", "Bearer test-token-789")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"User not found"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-789").await;

    // #act
    let result = client.get_user("999").await;

    // #assert
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        KeyrunesError::UserNotFoundError(_)
    ));
    mock.assert_async().await;
}

#[tokio::test]
async fn test_has_group_true() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/users/123/groups/admins")
        .match_header("authorization", "Bearer test-token-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"has_group":true}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-789").await;

    // #act
    let result = client.has_group("123", "admins").await;

    // #assert
    assert!(result.is_ok());
    assert!(result.unwrap());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_has_group_false() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/users/123/groups/admins")
        .match_header("authorization", "Bearer test-token-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"has_group":false}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-789").await;

    // #act
    let result = client.has_group("123", "admins").await;

    // #assert
    assert!(result.is_ok());
    assert!(!result.unwrap());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_user_groups_from_current_user() {
    // #setup
    let mut server = Server::new_async().await;
    let me_mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":123,"username":"john","email":"john@example.com","groups":["users","admins"]}"#,
        )
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-789").await;

    // #act
    let result = client.get_user_groups(None::<&str>).await;

    // #assert
    assert!(result.is_ok());
    let groups = result.unwrap();
    assert_eq!(groups.len(), 2);
    assert!(groups.contains(&"users".to_string()));
    assert!(groups.contains(&"admins".to_string()));
    me_mock.assert_async().await;
}

#[tokio::test]
async fn test_get_user_groups_from_user_id() {
    // #setup
    let mut server = Server::new_async().await;
    let user_mock = server
        .mock("GET", "/api/users/123")
        .match_header("authorization", "Bearer test-token-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":123,"username":"john","email":"john@example.com","groups":["users"]}"#,
        )
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-789").await;

    // #act
    let result = client.get_user_groups(Some("123")).await;

    // #assert
    assert!(result.is_ok());
    let groups = result.unwrap();
    assert_eq!(groups.len(), 1);
    assert!(groups.contains(&"users".to_string()));
    user_mock.assert_async().await;
}

#[tokio::test]
async fn test_clear_token() {
    // #setup
    let client = KeyrunesClient::new("https://example.com").unwrap();
    client.set_token("test-token-123").await;

    // #act
    client.clear_token().await;
    let result = client.get_current_user().await;

    // #assert
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::InvalidToken));
}
