//! Property-based tests for the Keyrunes Rust SDK.
//!
//! These tests use [`proptest`] to assert invariants that must hold for every
//! input in a domain, rather than for a handful of hand-picked examples. They
//! are the counterpart of the Hypothesis suite in the Python SDK, and the main
//! oracle for the `cargo mutants` runs.

use keyrunes_rust_sdk::models::*;
use keyrunes_rust_sdk::{KeyrunesClient, KeyrunesError};
use proptest::prelude::*;

/// Hostname labels that always produce a parseable URL.
fn hostname() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z][a-z0-9]{0,10}", 1..3).prop_map(|labels| labels.join("."))
}

/// Text that is safe to embed in a JSON string literal.
fn json_safe_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 _.@-]{0,40}"
}

// Building a `KeyrunesClient` constructs a full reqwest `Client` (TLS backend
// included), which costs milliseconds rather than microseconds. These
// properties are cheap to falsify, so a smaller case count keeps the suite
// usable as the oracle for a `cargo mutants` run.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    // ---------------------------------------------------------------- client

    /// The base URL must never keep a trailing slash, no matter how many
    /// the caller supplied.
    #[test]
    fn base_url_trailing_slashes_are_always_stripped(
        host in hostname(),
        slashes in 0usize..8,
    ) {
        let raw = format!("https://{}{}", host, "/".repeat(slashes));
        let client = KeyrunesClient::new(raw).unwrap();
        prop_assert!(!client.base_url().ends_with('/'));
        prop_assert_eq!(client.base_url(), format!("https://{}", host));
    }

    /// Normalizing an already-normalized URL must be a no-op.
    #[test]
    fn base_url_normalization_is_idempotent(
        host in hostname(),
        slashes in 0usize..8,
    ) {
        let raw = format!("https://{}{}", host, "/".repeat(slashes));
        let once = KeyrunesClient::new(raw).unwrap();
        let twice = KeyrunesClient::new(once.base_url().to_string()).unwrap();
        prop_assert_eq!(once.base_url(), twice.base_url());
    }

    /// A string with no scheme is never a valid base URL.
    #[test]
    fn schemeless_base_urls_are_rejected(host in hostname()) {
        let result = KeyrunesClient::new(host);
        prop_assert!(matches!(result, Err(KeyrunesError::InvalidUrl(_))));
    }

    /// Construction must never panic, whatever the caller passes in.
    #[test]
    fn client_construction_never_panics(raw in ".{0,60}") {
        let _ = KeyrunesClient::new(raw);
    }

}

proptest! {
    // ------------------------------------------------------------ user model

    /// When `id` is present it wins over every other identifier field.
    #[test]
    fn user_id_field_takes_precedence(
        id in json_safe_text(),
        external in json_safe_text(),
        numeric in 1i64..1_000_000,
        username in json_safe_text(),
        email in json_safe_text(),
    ) {
        let json = serde_json::json!({
            "id": id,
            "external_id": external,
            "user_id": numeric,
            "username": username,
            "email": email,
        });
        let user: User = serde_json::from_value(json).unwrap();
        prop_assert_eq!(user.id, id);
    }

    /// With `id` absent, `external_id` is preferred over the numeric `user_id`.
    #[test]
    fn external_id_outranks_numeric_user_id(
        external in json_safe_text(),
        numeric in 1i64..1_000_000,
        username in json_safe_text(),
        email in json_safe_text(),
    ) {
        let json = serde_json::json!({
            "external_id": external,
            "user_id": numeric,
            "username": username,
            "email": email,
        });
        let user: User = serde_json::from_value(json).unwrap();
        prop_assert_eq!(user.id, external);
    }

    /// The numeric `user_id` is the last identifier consulted, and it is
    /// stringified rather than dropped.
    #[test]
    fn numeric_user_id_is_the_last_resort(
        numeric in 1i64..1_000_000,
        username in json_safe_text(),
        email in json_safe_text(),
    ) {
        let json = serde_json::json!({
            "user_id": numeric,
            "username": username,
            "email": email,
        });
        let user: User = serde_json::from_value(json).unwrap();
        prop_assert_eq!(user.id, numeric.to_string());
    }

    /// With no identifier at all the model still deserializes, using the
    /// documented `"unknown"` sentinel.
    #[test]
    fn missing_identifiers_fall_back_to_unknown(
        username in json_safe_text(),
        email in json_safe_text(),
    ) {
        let json = serde_json::json!({ "username": username, "email": email });
        let user: User = serde_json::from_value(json).unwrap();
        prop_assert_eq!(user.id, "unknown");
    }

    /// An omitted `groups` key must yield an empty vector, never an error.
    #[test]
    fn absent_groups_default_to_empty(
        username in json_safe_text(),
        email in json_safe_text(),
    ) {
        let json = serde_json::json!({
            "id": "u1", "username": username, "email": email,
        });
        let user: User = serde_json::from_value(json).unwrap();
        prop_assert!(user.groups.is_empty());
    }

    /// Groups survive deserialization in order and in full.
    #[test]
    fn groups_are_preserved_verbatim(
        groups in proptest::collection::vec("[a-z]{1,10}", 0..6),
    ) {
        let json = serde_json::json!({
            "id": "u1", "username": "u", "email": "u@e.com", "groups": groups,
        });
        let user: User = serde_json::from_value(json).unwrap();
        prop_assert_eq!(user.groups, groups);
    }

    // ----------------------------------------------------------- token model

    /// The current wire format stores `token` directly.
    #[test]
    fn new_token_format_is_read_from_token_field(
        token in json_safe_text(),
        expires in 0i64..100_000,
    ) {
        let json = serde_json::json!({ "token": token, "expires_in": expires });
        let parsed: Token = serde_json::from_value(json).unwrap();
        prop_assert_eq!(parsed.token, token);
        prop_assert_eq!(parsed.expires_in, Some(expires));
        prop_assert_eq!(parsed.expires_at, None);
    }

    /// The legacy wire format maps `access_token` onto `token` and leaves
    /// `expires_at` unset, since the legacy payload never carried it.
    #[test]
    fn legacy_token_format_maps_access_token(
        token in json_safe_text(),
        token_type in json_safe_text(),
        expires in 0i64..100_000,
    ) {
        let json = serde_json::json!({
            "access_token": token,
            "token_type": token_type,
            "expires_in": expires,
        });
        let parsed: Token = serde_json::from_value(json).unwrap();
        prop_assert_eq!(parsed.token, token);
        prop_assert_eq!(parsed.token_type, Some(token_type));
        prop_assert_eq!(parsed.expires_in, Some(expires));
        prop_assert_eq!(parsed.expires_at, None);
    }

    /// When both spellings are present the current one must win.
    #[test]
    fn new_format_wins_over_legacy_when_both_present(
        new_token in "[a-z]{5,20}",
        legacy_token in "[A-Z]{5,20}",
    ) {
        let json = serde_json::json!({
            "token": new_token, "access_token": legacy_token,
        });
        let parsed: Token = serde_json::from_value(json).unwrap();
        prop_assert_eq!(parsed.token, new_token);
    }

    /// A payload carrying neither spelling is not a token.
    #[test]
    fn token_payload_without_any_token_field_is_rejected(
        expires in 0i64..100_000,
    ) {
        let json = serde_json::json!({ "expires_in": expires });
        let parsed: std::result::Result<Token, _> = serde_json::from_value(json);
        prop_assert!(parsed.is_err());
    }

    // ------------------------------------------------------ namespace policy

    /// `namespace` is required on the wire: it must always be serialized,
    /// because the server answers 422 when it is missing.
    #[test]
    fn login_credentials_always_serialize_namespace(
        identity in json_safe_text(),
        password in json_safe_text(),
        namespace in "[a-z]{1,12}",
    ) {
        let creds = LoginCredentials {
            identity: identity.clone(),
            password,
            namespace: namespace.clone(),
        };
        let value: serde_json::Value = serde_json::to_value(&creds).unwrap();
        prop_assert_eq!(value.get("namespace").and_then(|v| v.as_str()), Some(namespace.as_str()));
        prop_assert_eq!(value.get("identity").and_then(|v| v.as_str()), Some(identity.as_str()));
    }

    /// An incoming payload without `namespace` falls back to the documented
    /// default rather than failing.
    #[test]
    fn absent_namespace_deserializes_to_the_default(
        identity in json_safe_text(),
        password in json_safe_text(),
    ) {
        let json = serde_json::json!({ "identity": identity, "password": password });
        let creds: LoginCredentials = serde_json::from_value(json).unwrap();
        prop_assert_eq!(creds.namespace, DEFAULT_NAMESPACE);
    }

    /// Registration payloads follow the same namespace policy.
    #[test]
    fn user_registration_always_serialize_namespace(
        username in json_safe_text(),
        email in json_safe_text(),
        password in json_safe_text(),
        namespace in "[a-z]{1,12}",
    ) {
        let registration = UserRegistration {
            username, email, password, namespace: namespace.clone(),
        };
        let value: serde_json::Value = serde_json::to_value(&registration).unwrap();
        prop_assert_eq!(value.get("namespace").and_then(|v| v.as_str()), Some(namespace.as_str()));
    }

    // ----------------------------------------------------------- group check

    /// Both the current and the legacy field spelling must be accepted.
    #[test]
    fn group_check_accepts_both_field_aliases(flag in any::<bool>()) {
        let via_alias: GroupCheck =
            serde_json::from_value(serde_json::json!({ "has_access": flag })).unwrap();
        let via_name: GroupCheck =
            serde_json::from_value(serde_json::json!({ "has_group": flag })).unwrap();
        prop_assert_eq!(via_alias.has_group, flag);
        prop_assert_eq!(via_name.has_group, flag);
    }

    /// The verification response carries the flag through untouched.
    #[test]
    fn group_verification_response_round_trips(
        user_id in json_safe_text(),
        group_id in json_safe_text(),
        has_group in any::<bool>(),
    ) {
        let response = GroupVerificationResponse {
            user_id: user_id.clone(), group_id: group_id.clone(), has_group,
        };
        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: GroupVerificationResponse = serde_json::from_str(&encoded).unwrap();
        prop_assert_eq!(decoded.user_id, user_id);
        prop_assert_eq!(decoded.group_id, group_id);
        prop_assert_eq!(decoded.has_group, has_group);
    }

    // ----------------------------------------------------------------- error

    /// Every error variant renders a non-empty message that embeds its payload.
    #[test]
    fn error_display_embeds_its_payload(message in "[a-zA-Z0-9 ]{1,40}") {
        let variants = vec![
            KeyrunesError::AuthenticationError(message.clone()),
            KeyrunesError::AuthorizationError(message.clone()),
            KeyrunesError::GroupNotFoundError(message.clone()),
            KeyrunesError::UserNotFoundError(message.clone()),
            KeyrunesError::NetworkError(message.clone()),
            KeyrunesError::SerializationError(message.clone()),
            KeyrunesError::HttpError(message.clone()),
            KeyrunesError::InvalidUrl(message.clone()),
            KeyrunesError::Other(message.clone()),
        ];
        for variant in variants {
            let rendered = variant.to_string();
            prop_assert!(!rendered.is_empty());
            prop_assert!(rendered.contains(&message), "{} lost its payload", rendered);
        }
    }

    /// A malformed JSON body always becomes a `SerializationError`.
    #[test]
    fn serde_errors_convert_to_serialization_error(body in "[a-z]{1,20}") {
        let err = serde_json::from_str::<serde_json::Value>(&body).unwrap_err();
        prop_assert!(matches!(KeyrunesError::from(err), KeyrunesError::SerializationError(_)));
    }

    /// A malformed URL always becomes an `InvalidUrl`.
    #[test]
    fn url_errors_convert_to_invalid_url(raw in "[a-z]{1,20}") {
        let err = url::Url::parse(&raw).unwrap_err();
        prop_assert!(matches!(KeyrunesError::from(err), KeyrunesError::InvalidUrl(_)));
    }
}
