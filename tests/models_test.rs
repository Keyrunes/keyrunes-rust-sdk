use keyrunes_rust_sdk::models::*;

#[test]
fn test_user_serialization() {
    // #setup
    let user = User {
        id: "user123".to_string(),
        username: "john".to_string(),
        email: "john@example.com".to_string(),
        groups: vec!["users".to_string(), "admins".to_string()],
        created_at: None,
        updated_at: None,
    };

    // #act
    let json = serde_json::to_string(&user).unwrap();

    // #assert
    assert!(json.contains("user123"));
    assert!(json.contains("john"));
    assert!(json.contains("john@example.com"));
}

#[test]
fn test_user_deserialization() {
    // #setup
    let json = r#"{
        "id": "user123",
        "username": "john",
        "email": "john@example.com",
        "groups": ["users", "admins"]
    }"#;

    // #act
    let user: User = serde_json::from_str(json).unwrap();

    // #assert
    assert_eq!(user.id, "user123");
    assert_eq!(user.username, "john");
    assert_eq!(user.email, "john@example.com");
    assert_eq!(user.groups.len(), 2);
}

#[test]
fn test_token_serialization() {
    // #setup
    let token = Token {
        token: "test-token-123".to_string(),
        token_type: None,
        expires_in: None,
        refresh_token: None,
        expires_at: None,
    };

    // #act
    let json = serde_json::to_string(&token).unwrap();

    // #assert
    assert!(json.contains("test-token-123"));
}

#[test]
fn test_login_credentials() {
    // #setup
    let creds = LoginCredentials {
        identity: "user@example.com".to_string(),
        password: "password123".to_string(),
        namespace: "public".into(),
    };

    // #act
    let json = serde_json::to_string(&creds).unwrap();

    // #assert
    assert!(json.contains("user@example.com"));
    assert!(json.contains("password123"));
}

#[test]
fn test_user_registration() {
    // #setup
    let reg = UserRegistration {
        username: "john".to_string(),
        email: "john@example.com".to_string(),
        password: "password123".to_string(),
        namespace: "public".into(),
    };

    // #act
    let json = serde_json::to_string(&reg).unwrap();

    // #assert
    assert!(json.contains("john"));
    assert!(json.contains("john@example.com"));
    assert!(json.contains("password123"));
}

#[test]
fn test_admin_registration() {
    // #setup
    let reg = AdminRegistration {
        username: "admin".to_string(),
        email: "admin@example.com".to_string(),
        password: "password123".to_string(),
        admin_key: "admin-key-123".to_string(),
        namespace: "public".into(),
    };

    // #act
    let json = serde_json::to_string(&reg).unwrap();

    // #assert
    assert!(json.contains("admin"));
    assert!(json.contains("admin@example.com"));
    assert!(json.contains("admin-key-123"));
}

#[test]
fn test_group_serialization() {
    // #setup
    let group = Group {
        id: "group123".to_string(),
        name: "Admins".to_string(),
        description: Some("Administrator group".to_string()),
        created_at: None,
    };

    // #act
    let json = serde_json::to_string(&group).unwrap();

    // #assert
    assert!(json.contains("group123"));
    assert!(json.contains("Admins"));
    assert!(json.contains("Administrator group"));
}

#[test]
fn test_group_check() {
    // #setup
    let check = GroupCheck { has_group: true };

    // #act
    let json = serde_json::to_string(&check).unwrap();

    // #assert
    assert!(json.contains("true"));
}

#[test]
fn test_forgot_password_request() {
    let request = ForgotPasswordRequest {
        email: "user@example.com".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("email"));
    assert!(json.contains("namespace"));
}

#[test]
fn test_reset_password_request() {
    let request = ResetPasswordRequest {
        token: "reset-token-123".to_string(),
        new_password: "newPassword456".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("token"));
    assert!(json.contains("new_password"));
}

#[test]
fn test_change_password_request() {
    let request = ChangePasswordRequest {
        current_password: "oldPass123".to_string(),
        new_password: "newPass456".to_string(),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("current_password"));
    assert!(json.contains("new_password"));
}

#[test]
fn test_token_response_legacy_format_deserialization() {
    // Test legacy format with access_token field
    let json = r#"{"access_token":"legacy-token-xyz","token_type":"bearer"}"#;

    let token: Token = serde_json::from_str(json).unwrap();

    assert_eq!(token.token, "legacy-token-xyz");
    assert_eq!(token.token_type, Some("bearer".to_string()));
    assert_eq!(token.expires_at, None);
}

#[test]
fn test_token_new_format_deserialization_with_all_fields() {
    // Test new format with all fields
    let json = r#"{"token":"new-token-abc","token_type":"bearer","expires_in":3600,"refresh_token":"refresh-xyz"}"#;

    let token: Token = serde_json::from_str(json).unwrap();

    assert_eq!(token.token, "new-token-abc");
    assert_eq!(token.token_type, Some("bearer".to_string()));
    assert_eq!(token.expires_in, Some(3600));
    assert_eq!(token.refresh_token, Some("refresh-xyz".to_string()));
}

#[test]
fn test_user_response_with_numeric_user_id_only() {
    // Test UserResponse with only user_id (numeric) and no id/external_id
    let json = r#"{"user_id":42,"username":"john","email":"john@test.com","groups":[]}"#;

    let user: User = serde_json::from_str(json).unwrap();

    assert_eq!(user.id, "42");
    assert_eq!(user.username, "john");
    assert_eq!(user.email, "john@test.com");
}

#[test]
fn test_user_response_with_external_id() {
    // Test UserResponse with external_id field
    let json = r#"{"external_id":"ext-123","username":"john","email":"john@test.com","groups":[]}"#;

    let user: User = serde_json::from_str(json).unwrap();

    assert_eq!(user.id, "ext-123");
    assert_eq!(user.username, "john");
    assert_eq!(user.email, "john@test.com");
}

#[test]
fn test_user_response_no_id_fallback_to_unknown() {
    // Test UserResponse with no ID at all - should fallback to "unknown"
    let json = r#"{"username":"john","email":"john@test.com","groups":[]}"#;

    let user: User = serde_json::from_str(json).unwrap();

    assert_eq!(user.id, "unknown");
    assert_eq!(user.username, "john");
    assert_eq!(user.email, "john@test.com");
}

#[test]
fn test_group_verification_response_deserialization() {
    // Test GroupVerificationResponse deserialization
    let json = r#"{"user_id":"user-123","group_id":"group-456","has_group":true}"#;

    let response: GroupVerificationResponse = serde_json::from_str(json).unwrap();

    assert_eq!(response.user_id, "user-123");
    assert_eq!(response.group_id, "group-456");
    assert!(response.has_group);
}

#[test]
fn test_login_credentials_always_serializes_namespace() {
    // The server rejects login payloads without `namespace` (422), so the
    // field must ALWAYS be serialized, defaulting to DEFAULT_NAMESPACE.
    let creds = LoginCredentials {
        identity: "user@example.com".to_string(),
        password: "password123".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
    };

    let json = serde_json::to_value(&creds).unwrap();

    assert_eq!(json["namespace"], "public");
    assert_eq!(json["identity"], "user@example.com");
    assert_eq!(json["password"], "password123");
}

#[test]
fn test_user_registration_always_serializes_namespace() {
    let registration = UserRegistration {
        username: "john".to_string(),
        email: "john@example.com".to_string(),
        password: "password123".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
    };

    let json = serde_json::to_value(&registration).unwrap();

    assert_eq!(json["namespace"], "public");
    assert_eq!(json["username"], "john");
}

#[test]
fn test_group_check_has_access_alias() {
    // Test GroupCheck with has_access alias instead of has_group
    let json = r#"{"has_access":true}"#;

    let check: GroupCheck = serde_json::from_str(json).unwrap();

    assert!(check.has_group);
}
