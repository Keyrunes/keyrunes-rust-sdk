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

#[tokio::test]
async fn test_forgot_password_success() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/forgot-password")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"If the email is registered, you will receive a reset link.","reset_url":"?forgot_password=abc123"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.forgot_password("user@example.com", None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.message.contains("reset link"));
    assert!(response.reset_url.contains("abc123"));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_forgot_password_failure() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/forgot-password")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Invalid request"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.forgot_password("bad@example.com", None).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::HttpError(_)));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_reset_password_success() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/reset-password")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Password reset successfully"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.reset_password("reset-token-abc", "newPassword123", None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.message.contains("reset successfully"));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_reset_password_failure() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/reset-password")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Invalid or expired token"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.reset_password("expired-token", "newPassword123", None).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::HttpError(_)));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_change_password_success() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/user/change-password")
        .match_header("authorization", "Bearer test-token-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Password changed successfully"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-123").await;
    let result = client.change_password("oldPass123", "newPass456").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.message.contains("changed"));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_change_password_failure() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/user/change-password")
        .match_header("authorization", "Bearer test-token-123")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Invalid current password"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-123").await;
    let result = client.change_password("wrongPass", "newPass456").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::HttpError(_)));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_change_password_no_token() {
    let client = KeyrunesClient::new("https://example.com").unwrap();

    let result = client.change_password("oldPass123", "newPass456").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::InvalidToken));
}

#[tokio::test]
async fn test_admin_reset_user_password_success() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/admin/users/42/reset-password")
        .match_header("authorization", "Bearer admin-token-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"temporary_password":"tempAbc123XYZ!"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("admin-token-789").await;
    let result = client.admin_reset_user_password("42").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.temporary_password, "tempAbc123XYZ!");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_admin_reset_user_password_forbidden() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/admin/users/42/reset-password")
        .match_header("authorization", "Bearer user-token-789")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Admin access required"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("user-token-789").await;
    let result = client.admin_reset_user_password("42").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::AuthorizationError(_)));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_admin_send_password_reset_success() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/admin/users/42/send-reset")
        .match_header("authorization", "Bearer admin-token-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Reset email sent"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("admin-token-789").await;
    let result = client.admin_send_password_reset("42").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.message.contains("Reset email sent"));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_admin_send_password_reset_forbidden() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/admin/users/42/send-reset")
        .match_header("authorization", "Bearer user-token-789")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Admin access required"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("user-token-789").await;
    let result = client.admin_send_password_reset("42").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::AuthorizationError(_)));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_handle_error_html_response() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .with_status(500)
        .with_header("content-type", "text/html")
        .with_body("<html>Error</html>")
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user@example.com", "password", None).await;

    // #assert
    assert!(result.is_err());
    match result.unwrap_err() {
        KeyrunesError::HttpError(msg) => {
            assert!(msg.contains("HTML response"), "Expected HTML response error, got: {}", msg);
        }
        _ => panic!("Expected HttpError for HTML response"),
    }

    mock.assert_async().await;
}

#[tokio::test]
async fn test_handle_error_long_body_truncation() {
    // #setup
    let mut server = Server::new_async().await;
    let long_body = "x".repeat(300);
    let mock = server
        .mock("POST", "/api/login")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(&long_body)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user@example.com", "password", None).await;

    // #assert
    assert!(result.is_err());
    match result.unwrap_err() {
        KeyrunesError::HttpError(msg) => {
            assert!(msg.contains("..."), "Expected truncated body with ..., got: {}", msg);
            assert!(msg.len() < 350, "Message should be truncated, got length: {}", msg.len());
        }
        _ => panic!("Expected HttpError for long body"),
    }

    mock.assert_async().await;
}



#[tokio::test]
async fn test_handle_error_not_found_other() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/forgot-password")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Resource missing"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();

    // #act
    let result = client.forgot_password("test@example.com", None).await;

    // #assert
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        KeyrunesError::Other(msg) => {
            assert!(msg.contains("Resource not found"), "Expected Other error with 'Resource not found', got: {}", msg);
        }
        _ => panic!("Expected Other error for generic not found, got: {:?}", err),
    }

    mock.assert_async().await;
}

#[tokio::test]
async fn test_client_new_with_org_key_env_var() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token")
        .match_header("x-organization-key", "test-org-key-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user_id":1,"username":"test","email":"test@example.com","groups":[]}"#)
        .create_async()
        .await;

    // #act - set env var before creating client
    std::env::set_var("KEYRUNES_ORG_KEY", "test-org-key-123");
    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token").await;
    let result = client.get_current_user().await;

    // #assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap().username, "test");

    mock.assert_async().await;

    // Cleanup
    std::env::remove_var("KEYRUNES_ORG_KEY");
}

#[tokio::test]
async fn test_admin_reset_user_password_no_token() {
    // #setup
    let client = KeyrunesClient::new("https://example.com").unwrap();

    // #act
    let result = client.admin_reset_user_password("42").await;

    // #assert
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::InvalidToken));
}

#[tokio::test]
async fn test_admin_send_password_reset_no_token() {
    // #setup
    let client = KeyrunesClient::new("https://example.com").unwrap();

    // #act
    let result = client.admin_send_password_reset("42").await;

    // #assert
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeyrunesError::InvalidToken));
}

#[tokio::test]
async fn test_register_response_parsing() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user":{"user_id":456,"username":"parseduser","email":"parsed@example.com","groups":["users","testers"]},"token":"parsed-token","requires_password_change":true}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.register("parseduser", "parsed@example.com", "password123", None).await;

    // #assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.id, "456");
    assert_eq!(user.username, "parseduser");
    assert_eq!(user.email, "parsed@example.com");
    assert_eq!(user.groups.len(), 2);
    assert!(user.groups.contains(&"users".to_string()));
    assert!(user.groups.contains(&"testers".to_string()));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_admin_response_parsing() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user":{"user_id":789,"username":"adminparsed","email":"adminparsed@example.com","groups":["admins","superusers"]},"token":"admin-token-parsed","requires_password_change":false}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.register_admin("adminparsed", "adminparsed@example.com", "password123", "admin-key", None).await;

    // #assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.id, "789");
    assert_eq!(user.username, "adminparsed");
    assert_eq!(user.email, "adminparsed@example.com");
    assert_eq!(user.groups.len(), 2);
    assert!(user.groups.contains(&"admins".to_string()));
    assert!(user.groups.contains(&"superusers".to_string()));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_get_user_full_response_parsing() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/users/555")
        .match_header("authorization", "Bearer test-token-full")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user_id":555,"username":"fulluser","email":"full@example.com","groups":["group1","group2","group3"]}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-full").await;

    // #act
    let result = client.get_user("555").await;

    // #assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.id, "555");
    assert_eq!(user.username, "fulluser");
    assert_eq!(user.email, "full@example.com");
    assert_eq!(user.groups.len(), 3);
    assert!(user.groups.contains(&"group1".to_string()));
    assert!(user.groups.contains(&"group2".to_string()));
    assert!(user.groups.contains(&"group3".to_string()));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_has_group_has_access_alias() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/users/123/groups/test-group")
        .match_header("authorization", "Bearer test-token-alias")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"has_access":true}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token-alias").await;

    // #act
    let result = client.has_group("123", "test-group").await;

    // #assert
    assert!(result.is_ok());
    assert!(result.unwrap());

    mock.assert_async().await;
}
