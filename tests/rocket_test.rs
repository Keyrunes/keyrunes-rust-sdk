#[cfg(feature = "rocket")]
mod rocket_tests {
    use keyrunes_rust_sdk::{
        middleware::rocket::{AuthenticatedUser, KeyrunesState},
        KeyrunesClient,
    };
    use std::sync::Arc;

    #[test]
    fn test_keyrunes_state_creation() {
        let client = KeyrunesClient::new("http://localhost:3000").unwrap();
        let state = KeyrunesState::new(client);

        assert!(Arc::strong_count(&state.client) == 1);
    }

    #[test]
    fn test_authenticated_user_clone() {
        use chrono::Utc;

        let user = keyrunes_rust_sdk::User {
            id: "123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            groups: vec!["users".to_string()],
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        let auth_user = AuthenticatedUser { user: user.clone() };
        let cloned = auth_user.clone();

        assert_eq!(cloned.user.id, "123");
        assert_eq!(cloned.user.username, "testuser");
    }

    #[test]
    fn test_authenticated_user_debug() {
        use chrono::Utc;

        let user = keyrunes_rust_sdk::User {
            id: "456".to_string(),
            username: "adminuser".to_string(),
            email: "admin@example.com".to_string(),
            groups: vec!["users".to_string(), "admins".to_string()],
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        let auth_user = AuthenticatedUser { user };

        let debug_str = format!("{:?}", auth_user);
        assert!(debug_str.contains("adminuser"));
    }
}
