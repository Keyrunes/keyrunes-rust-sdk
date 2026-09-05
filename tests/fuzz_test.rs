//! Fuzz ("spider") tests for the Keyrunes Rust SDK.
//!
//! Where `property_test.rs` asserts invariants over *valid* inputs, this
//! module crawls the *hostile* input space: arbitrary JSON payloads, malformed
//! bodies, unexpected status codes and multi-byte error responses. The
//! contract under test is a robustness one — the SDK may reject an input, but
//! it must return a [`KeyrunesError`] rather than panic.

use keyrunes_rust_sdk::models::*;
use keyrunes_rust_sdk::{KeyrunesClient, KeyrunesError};
use mockito::Server;
use proptest::prelude::*;

/// Arbitrary JSON values, including nested objects and arrays.
fn arbitrary_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i32>().prop_map(serde_json::Value::from),
        "[a-zA-Z0-9 _.@-]{0,20}".prop_map(serde_json::Value::from),
    ];
    leaf.prop_recursive(3, 12, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::from),
            proptest::collection::hash_map("[a-z_]{1,10}", inner, 0..4)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    // ------------------------------------------------------- deserialization

    /// Deserializing an arbitrary JSON value into a `User` must either
    /// succeed or fail cleanly — never panic.
    #[test]
    fn user_deserialization_never_panics(value in arbitrary_json()) {
        let _: std::result::Result<User, _> = serde_json::from_value(value);
    }

    /// Same contract for `Token`, whose untagged enum does the most work.
    #[test]
    fn token_deserialization_never_panics(value in arbitrary_json()) {
        let _: std::result::Result<Token, _> = serde_json::from_value(value);
    }

    /// Same contract for the remaining response models.
    #[test]
    fn response_models_deserialization_never_panics(value in arbitrary_json()) {
        let _: std::result::Result<Group, _> = serde_json::from_value(value.clone());
        let _: std::result::Result<GroupCheck, _> = serde_json::from_value(value.clone());
        let _: std::result::Result<GroupVerificationResponse, _> =
            serde_json::from_value(value.clone());
        let _: std::result::Result<MessageResponse, _> = serde_json::from_value(value.clone());
        let _: std::result::Result<ForgotPasswordResponse, _> =
            serde_json::from_value(value.clone());
        let _: std::result::Result<PasswordResetResponse, _> = serde_json::from_value(value);
    }

    /// Whatever survives deserialization must survive a re-serialization and
    /// a second parse with the same identity.
    #[test]
    fn user_round_trip_is_stable(value in arbitrary_json()) {
        if let Ok(user) = serde_json::from_value::<User>(value) {
            let encoded = serde_json::to_string(&user).unwrap();
            let decoded: User = serde_json::from_str(&encoded).unwrap();
            prop_assert_eq!(decoded.id, user.id);
            prop_assert_eq!(decoded.username, user.username);
            prop_assert_eq!(decoded.email, user.email);
            prop_assert_eq!(decoded.groups, user.groups);
        }
    }

    /// Parsing arbitrary text as any model must never panic either.
    #[test]
    fn arbitrary_text_bodies_never_panic(body in ".{0,200}") {
        let _: std::result::Result<User, _> = serde_json::from_str(&body);
        let _: std::result::Result<Token, _> = serde_json::from_str(&body);
        let _: std::result::Result<GroupCheck, _> = serde_json::from_str(&body);
    }

    // --------------------------------------------------------------- errors

    /// Rendering any error variant with any payload must never panic and
    /// must produce a non-empty message.
    #[test]
    fn error_rendering_never_panics(payload in ".{0,200}") {
        let variants = vec![
            KeyrunesError::AuthenticationError(payload.clone()),
            KeyrunesError::AuthorizationError(payload.clone()),
            KeyrunesError::GroupNotFoundError(payload.clone()),
            KeyrunesError::UserNotFoundError(payload.clone()),
            KeyrunesError::NetworkError(payload.clone()),
            KeyrunesError::SerializationError(payload.clone()),
            KeyrunesError::HttpError(payload.clone()),
            KeyrunesError::InvalidUrl(payload.clone()),
            KeyrunesError::InvalidToken,
            KeyrunesError::Other(payload.clone()),
        ];
        for variant in variants {
            prop_assert!(!variant.to_string().is_empty());
        }
    }
}

// ---------------------------------------------------------------- transport
//
// These crawl the SDK through a real (local) HTTP server, so they need the
// tokio runtime and cannot live inside the `proptest!` macro. Each one covers
// a body shape that the error-formatting path has to survive.

/// A body longer than the 200-byte truncation limit whose 200th byte falls in
/// the middle of a multi-byte character. Slicing a `String` on a non-boundary
/// panics, so this is the regression guard for the truncation path.
fn multibyte_body_straddling_the_truncation_limit() -> String {
    // 198 ASCII bytes, then a 3-byte character spanning bytes 198..201.
    format!("{}{}", "a".repeat(198), "€".repeat(20))
}

#[tokio::test]
async fn error_body_with_multibyte_boundary_does_not_panic() {
    // #setup
    let mut server = Server::new_async().await;
    let body = multibyte_body_straddling_the_truncation_limit();
    let mock = server
        .mock("POST", "/api/login")
        .with_status(500)
        .with_header("content-type", "text/plain")
        .with_body(&body)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user", "password", None).await;

    // #assert
    assert!(matches!(result, Err(KeyrunesError::HttpError(_))));
    mock.assert_async().await;
}

#[tokio::test]
async fn long_ascii_error_body_is_truncated_not_dropped() {
    // #setup
    let mut server = Server::new_async().await;
    let body = "z".repeat(500);
    let mock = server
        .mock("POST", "/api/login")
        .with_status(500)
        .with_header("content-type", "text/plain")
        .with_body(&body)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user", "password", None).await;

    // #assert
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("..."),
        "expected truncation marker: {message}"
    );
    assert!(message.len() < body.len(), "body was not truncated");
    mock.assert_async().await;
}

#[tokio::test]
async fn error_body_exactly_at_the_preview_limit_is_reported_verbatim() {
    // #setup
    // The preview limit is 200 bytes and the truncation branch is guarded by a
    // strict `>`: a body of exactly 200 bytes still fits and must come back
    // whole, with no ellipsis appended.
    let mut server = Server::new_async().await;
    let body = "z".repeat(200);
    let mock = server
        .mock("POST", "/api/login")
        .with_status(500)
        .with_header("content-type", "text/plain")
        .with_body(&body)
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user", "password", None).await;

    // #assert
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains(&body),
        "the whole body should be present: {message}"
    );
    assert!(
        !message.contains("z..."),
        "a body at the limit must not be truncated: {message}"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn html_error_body_is_reported_as_a_wrong_endpoint() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .with_status(502)
        .with_header("content-type", "text/html")
        .with_body("<html><body>Bad Gateway</body></html>")
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user", "password", None).await;

    // #assert
    let message = result.unwrap_err().to_string();
    assert!(message.contains("HTML response"), "got: {message}");
    mock.assert_async().await;
}

#[tokio::test]
async fn empty_error_body_does_not_panic() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .with_status(500)
        .with_body("")
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user", "password", None).await;

    // #assert
    assert!(result.is_err());
    mock.assert_async().await;
}

#[tokio::test]
async fn success_status_with_malformed_body_is_a_serialization_error() {
    // #setup
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/api/login")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{not json at all")
        .create_async()
        .await;

    // #act
    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user", "password", None).await;

    // #assert
    assert!(matches!(result, Err(KeyrunesError::SerializationError(_))));
    mock.assert_async().await;
}

#[tokio::test]
async fn not_found_is_classified_by_the_message_content() {
    // #setup — a 404 mentioning a user maps to UserNotFoundError.
    let mut server = Server::new_async().await;
    let user_mock = server
        .mock("POST", "/api/login")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"user does not exist"}"#)
        .create_async()
        .await;

    let client = KeyrunesClient::new(server.url()).unwrap();
    let result = client.login("user", "password", None).await;
    assert!(matches!(result, Err(KeyrunesError::UserNotFoundError(_))));
    user_mock.assert_async().await;

    // #setup — a 404 mentioning a group maps to GroupNotFoundError.
    let group_mock = server
        .mock("POST", "/api/login")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"group is missing"}"#)
        .create_async()
        .await;

    let result = client.login("user", "password", None).await;
    assert!(matches!(result, Err(KeyrunesError::GroupNotFoundError(_))));
    group_mock.assert_async().await;

    // #setup — an unclassifiable 404 falls through to Other.
    let other_mock = server
        .mock("POST", "/api/login")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"nothing here"}"#)
        .create_async()
        .await;

    let result = client.login("user", "password", None).await;
    assert!(matches!(result, Err(KeyrunesError::Other(_))));
    other_mock.assert_async().await;
}
