//! Contract tests against the VERIFIED server API shapes (keyrunes server):
//!
//! - `POST /api/login` requires `{identity, password, namespace}`.
//! - `POST /api/register` returns 201 with a FLAT `UserResponse`
//!   `{user_id: i64, external_id: Uuid, id: Uuid, email, username,
//!     groups: Vec<String>, first_login, organization_id, namespace}`.
//! - `GET /api/me` returns the same `UserResponse` (groups are NAMES).
//! - `GET /api/users/{uid}/groups/{gid}` does NOT exist on the server (404).

use keyrunes_rust_sdk::{KeyrunesClient, KeyrunesError};
use mockito::{Matcher, Server};

/// Real `UserResponse` shape returned by the server (password_hash is skipped server-side).
const REAL_USER_RESPONSE: &str = r#"{"user_id":42,"external_id":"0b3f6d5a-7c1e-4f2a-9d3b-1a2b3c4d5e6f","id":"8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d","email":"john@example.com","username":"john","groups":["users"],"first_login":true,"organization_id":1,"namespace":"public"}"#;

#[tokio::test]
async fn test_login_payload_defaults_namespace_to_public_when_none() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .match_body(Matcher::JsonString(
            r#"{"identity":"user@example.com","password":"password123","namespace":"public"}"#
                .to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user":{"user_id":42,"email":"user@example.com","username":"user","groups":[],"first_login":false,"organization_id":1,"namespace":"public"},"token":"test-token","requires_password_change":false}"#,
        )
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user@example.com", "password123", None).await;

    // #assert
    assert!(result.is_ok());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_login_payload_serializes_explicit_namespace() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .match_body(Matcher::JsonString(
            r#"{"identity":"user@example.com","password":"password123","namespace":"corp"}"#
                .to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"token":"test-token"}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client
        .login("user@example.com", "password123", Some("corp"))
        .await;

    // #assert
    assert!(result.is_ok());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_payload_defaults_namespace_to_public_when_none() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .match_body(Matcher::JsonString(
            r#"{"username":"john","email":"john@example.com","password":"password123","namespace":"public"}"#
                .to_string(),
        ))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(REAL_USER_RESPONSE)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client
        .register("john", "john@example.com", "password123", None)
        .await;

    // #assert
    assert!(result.is_ok());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_parses_flat_user_response() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(REAL_USER_RESPONSE)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client
        .register("john", "john@example.com", "password123", None)
        .await;

    // #assert
    let user = result.unwrap();
    assert_eq!(user.id, "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d");
    assert_eq!(user.username, "john");
    assert_eq!(user.email, "john@example.com");
    assert_eq!(user.groups, vec!["users".to_string()]);

    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_malformed_response_returns_clear_parse_error() {
    // #setup — 201 missing required fields (no username/email): must be a
    // clear SerializationError, never a panic.
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"user_id":42}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client
        .register("john", "john@example.com", "password123", None)
        .await;

    // #assert
    let err = result.unwrap_err();
    assert!(matches!(err, KeyrunesError::SerializationError(_)));
    assert!(err.to_string().contains("username"));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_current_user_has_group_returns_true() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":42,"external_id":"0b3f6d5a-7c1e-4f2a-9d3b-1a2b3c4d5e6f","id":"8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d","email":"john@example.com","username":"john","groups":["monitor","users"],"first_login":true,"organization_id":1,"namespace":"public"}"#,
        )
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token").await;

    // #act
    let result = client.current_user_has_group("monitor").await;

    // #assert
    assert!(result.unwrap());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_current_user_has_group_returns_false() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user_id":42,"external_id":"0b3f6d5a-7c1e-4f2a-9d3b-1a2b3c4d5e6f","id":"8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d","email":"john@example.com","username":"john","groups":["users"],"first_login":true,"organization_id":1,"namespace":"public"}"#,
        )
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token").await;

    // #act
    let result = client.current_user_has_group("monitor").await;

    // #assert
    assert!(!result.unwrap());
    mock.assert_async().await;
}

#[tokio::test]
#[allow(deprecated)]
async fn test_has_group_deprecated_returns_clear_error_on_missing_route() {
    // #setup — GET /api/users/{uid}/groups/{gid} does not exist on the
    // server: every call must fail with a clear 404-flavored error.
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/api/users/123/groups/admins")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"Not Found"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    client.set_token("test-token").await;

    // #act
    let result = client.has_group("123", "admins").await;

    // #assert
    let err = result.unwrap_err();
    assert!(err.to_string().contains("users/123/groups"));

    mock.assert_async().await;
}
