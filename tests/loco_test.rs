#![cfg(feature = "loco")]
use http::{HeaderMap, HeaderValue};
use keyrunes_rust_sdk::{
    middleware::loco::{
        extract_token_from_headers, get_user_from_token, require_admin, require_group,
        AuthenticatedUser,
    },
    KeyrunesClient,
};
use mockito::Server;

#[allow(dead_code)]
fn create_mock_user(username: &str, groups: Vec<&str>) -> AuthenticatedUser {
    let now = chrono::Utc::now();
    AuthenticatedUser {
        user: keyrunes_rust_sdk::User {
            id: "123".to_string(),
            username: username.to_string(),
            email: format!("{}@example.com", username),
            groups: groups.into_iter().map(|g| g.to_string()).collect(),
            created_at: Some(now),
            updated_at: Some(now),
        },
    }
}

#[test]
fn test_extract_token_from_headers_valid() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer token123"));

    let token = extract_token_from_headers(&headers).unwrap();
    assert_eq!(token, "token123");
}

#[test]
fn test_extract_token_from_headers_missing() {
    let headers = HeaderMap::new();
    let token = extract_token_from_headers(&headers);
    assert!(token.is_none());
}

#[test]
fn test_extract_token_from_headers_wrong_format() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Basic abc123"));

    let token = extract_token_from_headers(&headers);
    assert!(token.is_none());
}

#[tokio::test]
async fn test_get_user_from_token_success() {
    let mut server = Server::new_async().await;
    let server_url = server.url();

    let mock_user_body = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users","admins"]}"#;
    let _mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_user_body)
        .create_async()
        .await;

    let client = KeyrunesClient::new(&server_url).unwrap();
    let user = get_user_from_token(&client, "test-token").await.unwrap();

    assert_eq!(user.user.username, "testuser");
    assert_eq!(user.user.id, "123");
}

#[tokio::test]
async fn test_get_user_from_token_auth_error() {
    let mut server = Server::new_async().await;
    let server_url = server.url();

    let _mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer invalid-token")
        .with_status(401)
        .create_async()
        .await;

    let client = KeyrunesClient::new(&server_url).unwrap();
    let result = get_user_from_token(&client, "invalid-token").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_require_group_success() {
    let mut server = Server::new_async().await;
    let server_url = server.url();

    let mock_user_body = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users","admins"]}"#;
    let _mock_me = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_user_body)
        .create_async()
        .await;

    let _mock_group = server
        .mock("GET", "/api/users/123/groups/admins")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"has_group":true}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(&server_url).unwrap();
    let user = get_user_from_token(&client, "test-token").await.unwrap();

    let result = require_group(&client, &user, "admins").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_require_group_not_in_group() {
    let mut server = Server::new_async().await;
    let server_url = server.url();

    let mock_user_body =
        r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users"]}"#;
    let _mock_me = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_user_body)
        .create_async()
        .await;

    let _mock_group = server
        .mock("GET", "/api/users/123/groups/admins")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"has_group":false}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(&server_url).unwrap();
    let user = get_user_from_token(&client, "test-token").await.unwrap();

    let result = require_group(&client, &user, "admins").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_require_admin_success() {
    let mut server = Server::new_async().await;
    let server_url = server.url();

    let mock_user_body = r#"{"user_id":123,"username":"adminuser","email":"admin@example.com","groups":["users","admins"]}"#;
    let _mock_me = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer admin-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_user_body)
        .create_async()
        .await;

    let _mock_group = server
        .mock("GET", "/api/users/123/groups/admins")
        .match_header("authorization", "Bearer admin-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"has_group":true}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(&server_url).unwrap();
    let user = get_user_from_token(&client, "admin-token").await.unwrap();

    let result = require_admin(&client, &user).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_require_admin_not_admin() {
    let mut server = Server::new_async().await;
    let server_url = server.url();

    let mock_user_body =
        r#"{"user_id":123,"username":"regularuser","email":"user@example.com","groups":["users"]}"#;
    let _mock_me = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer user-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_user_body)
        .create_async()
        .await;

    let _mock_group = server
        .mock("GET", "/api/users/123/groups/admins")
        .match_header("authorization", "Bearer user-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"has_group":false}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(&server_url).unwrap();
    let user = get_user_from_token(&client, "user-token").await.unwrap();

    let result = require_admin(&client, &user).await;
    assert!(result.is_err());
}
