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
