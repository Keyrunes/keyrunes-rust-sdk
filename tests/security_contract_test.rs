//! Contract tests for the security-sensitive parts of the client.
//!
//! These cover the gaps that were found while integrating the SDK into a
//! multi-tenant application:
//!
//! - `register` must be able to pin the group of the new user, so the caller
//!   does not inherit the server's bootstrap-admin behaviour for the first
//!   user of an empty namespace.
//! - `User` must expose the namespace and organization it came from, so the
//!   caller can assert that it is talking to the tenant it expects.
//! - `login_with_user` must return the user and the token in a single round
//!   trip, so authorization decisions do not depend on a second call that
//!   could observe a different session.
//! - Every request must carry a timeout.

use keyrunes_rust_sdk::KeyrunesClient;
use mockito::{Matcher, Server};
use std::time::Duration;

/// Real `UserResponse` shape returned by the server.
const REAL_USER_RESPONSE: &str = r#"{"user_id":42,"external_id":"0b3f6d5a-7c1e-4f2a-9d3b-1a2b3c4d5e6f","id":"8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d","email":"john@example.com","username":"john","groups":["users"],"first_login":true,"organization_id":7,"namespace":"pixie"}"#;

#[tokio::test]
async fn test_register_sends_the_requested_group() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .match_body(Matcher::JsonString(
            r#"{"username":"john","email":"john@example.com","password":"password123","namespace":"pixie","group":"users"}"#
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
        .register(
            "john",
            "john@example.com",
            "password123",
            Some("pixie"),
            Some("users"),
            None,
        )
        .await;

    // #assert
    assert!(result.is_ok());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_omits_group_when_none_is_given() {
    // #setup — the payload must not carry a `group` key at all, so the
    // server applies its own default.
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/register")
        .match_body(Matcher::JsonString(
            r#"{"username":"john","email":"john@example.com","password":"password123","namespace":"pixie"}"#
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
        .register(
            "john",
            "john@example.com",
            "password123",
            Some("pixie"),
            None,
            None,
        )
        .await;

    // #assert
    assert!(result.is_ok());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_register_exposes_namespace_and_organization() {
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
    let user = client
        .register(
            "john",
            "john@example.com",
            "password123",
            Some("pixie"),
            Some("users"),
            None,
        )
        .await
        .unwrap();

    // #assert
    assert_eq!(user.namespace.as_deref(), Some("pixie"));
    assert_eq!(user.organization_id, Some(7));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_login_with_user_returns_user_and_token_in_one_call() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .match_body(Matcher::JsonString(
            r#"{"identity":"john@example.com","password":"password123","namespace":"pixie"}"#
                .to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user":{"user_id":42,"external_id":"0b3f6d5a-7c1e-4f2a-9d3b-1a2b3c4d5e6f","id":"8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d","email":"john@example.com","username":"john","groups":["users"],"first_login":false,"organization_id":7,"namespace":"pixie"},"token":"test-token","requires_password_change":false}"#,
        )
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let (token, user) = client
        .login_with_user("john@example.com", "password123", Some("pixie"), None)
        .await
        .unwrap();

    // #assert
    assert_eq!(token.token, "test-token");
    assert_eq!(user.username, "john");
    assert_eq!(user.groups, vec!["users".to_string()]);
    assert_eq!(user.namespace.as_deref(), Some("pixie"));
    assert_eq!(user.organization_id, Some(7));

    mock.assert_async().await;
}

#[tokio::test]
async fn test_login_with_user_stores_the_token_for_later_calls() {
    // #setup
    let mut server = Server::new_async().await;
    let login_mock = server
        .mock("POST", "/api/login")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"user":{"user_id":42,"email":"john@example.com","username":"john","groups":["users"],"first_login":false,"organization_id":7,"namespace":"pixie"},"token":"stored-token","requires_password_change":false}"#,
        )
        .create_async()
        .await;
    let me_mock = server
        .mock("GET", "/api/me")
        .match_header("authorization", "Bearer stored-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(REAL_USER_RESPONSE)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    client
        .login_with_user("john@example.com", "password123", Some("pixie"), None)
        .await
        .unwrap();
    let me = client.get_current_user().await.unwrap();

    // #assert
    assert_eq!(me.username, "john");
    login_mock.assert_async().await;
    me_mock.assert_async().await;
}

#[tokio::test]
async fn test_request_times_out_when_the_server_does_not_answer() {
    // #setup — a server that accepts the connection but never answers must
    // not hold the caller forever.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // Accept and drop every connection without writing a response.
        for stream in listener.incoming() {
            drop(stream);
        }
    });

    // #act
    let client =
        KeyrunesClient::with_timeout(format!("http://{}", address), Duration::from_millis(200))
            .unwrap();
    let result = client
        .login("john@example.com", "password123", Some("pixie"), None)
        .await;

    // #assert
    assert!(
        result.is_err(),
        "the request must not succeed after the timeout"
    );
}

#[tokio::test]
async fn test_user_agent_reports_the_crate_version() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .match_header(
            "user-agent",
            Matcher::Regex(format!(
                "^keyrunes-rust-sdk/{}$",
                env!("CARGO_PKG_VERSION").replace('.', "\\.")
            )),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"token":"test-token"}"#)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client
        .login("john@example.com", "password123", None, None)
        .await;

    // #assert
    assert!(result.is_ok());
    mock.assert_async().await;
}
