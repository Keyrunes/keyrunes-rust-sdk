#[cfg(feature = "axum")]
mod axum_tests {
    use axum::{
        body::Body,
        extract::Request,
        http::{header::AUTHORIZATION, Method, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use keyrunes_rust_sdk::{
        middleware::axum::{KeyrunesRejection, KeyrunesState, RequireAdmin, RequireGroup},
        KeyrunesClient,
    };

    use mockito::Server;
    use tower::util::ServiceExt;

    /// Helper to build a test router with the given client
    fn build_router(client: KeyrunesClient) -> Router {
        async fn handle_group(user: RequireGroup) -> String {
            format!("User {} in group {}", user.user.username, user.group_id)
        }

        async fn handle_admin(user: RequireAdmin) -> String {
            format!("Admin user: {}", user.user.username)
        }

        Router::new()
            .route("/group", get(handle_group))
            .route("/admin", get(handle_admin))
            .with_state(KeyrunesState::new(client))
    }

    #[tokio::test]
    async fn test_authenticated_user_success() {
        let mut server = Server::new_async().await;
        let server_url = server.url();

        // Mock the /api/me endpoint
        let mock_user_body = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users","admins"]}"#;
        let _mock = server
            .mock("GET", "/api/me")
            .match_header("authorization", "Bearer valid-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_user_body)
            .create_async()
            .await;

        // Mock has_group("admins") = true
        let _mock_group = server
            .mock("GET", "/api/users/123/groups/admins")
            .match_header("authorization", "Bearer valid-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":true}"#)
            .create_async()
            .await;

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin")
            .header(AUTHORIZATION, "Bearer valid-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("testuser"));
    }

    #[tokio::test]
    async fn test_authenticated_user_missing_token() {
        let server = Server::new_async().await;
        let server_url = server.url();

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        // Request without Authorization header
        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authenticated_user_invalid_format() {
        let server = Server::new_async().await;
        let server_url = server.url();

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        // Request with "Basic" instead of "Bearer"
        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin")
            .header(AUTHORIZATION, "Basic abc123")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_require_group_success() {
        let mut server = Server::new_async().await;
        let server_url = server.url();

        // Mock /api/me
        let mock_user = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users","admins"]}"#;
        let _mock_me = server
            .mock("GET", "/api/me")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_user)
            .create_async()
            .await;

        // Mock has_group = true
        let _mock_group = server
            .mock("GET", "/api/users/123/groups/admins")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":true}"#)
            .create_async()
            .await;

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/group?group_id=admins")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_require_group_missing_group_id() {
        let mut server = Server::new_async().await;
        let server_url = server.url();

        let mock_user = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users"]}"#;
        let _mock_me = server
            .mock("GET", "/api/me")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_user)
            .create_async()
            .await;

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        // Request without group_id query param
        let request = Request::builder()
            .method(Method::GET)
            .uri("/group")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // Should return BAD_REQUEST for missing group_id
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn test_require_group_user_not_in_group() {
        let mut server = Server::new_async().await;
        let server_url = server.url();

        // Mock /api/me
        let mock_user = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users"]}"#;
        let _mock_me = server
            .mock("GET", "/api/me")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_user)
            .create_async()
            .await;

        // Mock has_group = false
        let _mock_group = server
            .mock("GET", "/api/users/123/groups/admins")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":false}"#)
            .create_async()
            .await;

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/group?group_id=admins")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_require_admin_success() {
        let mut server = Server::new_async().await;
        let server_url = server.url();

        // Mock /api/me
        let mock_user = r#"{"user_id":123,"username":"adminuser","email":"admin@example.com","groups":["users","admins"]}"#;
        let _mock_me = server
            .mock("GET", "/api/me")
            .match_header("authorization", "Bearer admin-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_user)
            .create_async()
            .await;

        // Mock has_group("admins") = true
        let _mock_group = server
            .mock("GET", "/api/users/123/groups/admins")
            .match_header("authorization", "Bearer admin-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":true}"#)
            .create_async()
            .await;

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin")
            .header(AUTHORIZATION, "Bearer admin-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_require_admin_not_admin() {
        let mut server = Server::new_async().await;
        let server_url = server.url();

        // Mock /api/me
        let mock_user = r#"{"user_id":123,"username":"regularuser","email":"user@example.com","groups":["users"]}"#;
        let _mock_me = server
            .mock("GET", "/api/me")
            .match_header("authorization", "Bearer user-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_user)
            .create_async()
            .await;

        // Mock has_group("admins") = false
        let _mock_group = server
            .mock("GET", "/api/users/123/groups/admins")
            .match_header("authorization", "Bearer user-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":false}"#)
            .create_async()
            .await;

        let client = KeyrunesClient::new(&server_url).unwrap();
        let router = build_router(client);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin")
            .header(AUTHORIZATION, "Bearer user-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_keyrunes_rejection_into_response() {
        // Test that KeyrunesRejection variants convert to proper responses
        // MissingToken
        let rejection = KeyrunesRejection::MissingToken;
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // InvalidToken
        let rejection = KeyrunesRejection::InvalidToken;
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // MissingGroup
        let rejection = KeyrunesRejection::MissingGroup;
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Forbidden
        let rejection = KeyrunesRejection::Forbidden("test".to_string());
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // AuthError
        let rejection = KeyrunesRejection::AuthError("Unauthorized".to_string());
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_from_keyrunes_error() {
        use keyrunes_rust_sdk::KeyrunesError;

        // AuthenticationError -> AuthError
        let error = KeyrunesError::AuthenticationError("auth failed".to_string());
        let rejection: KeyrunesRejection = error.into();
        assert!(matches!(rejection, KeyrunesRejection::AuthError(_)));

        // AuthorizationError -> Forbidden
        let error = KeyrunesError::AuthorizationError("forbidden".to_string());
        let rejection: KeyrunesRejection = error.into();
        assert!(matches!(rejection, KeyrunesRejection::Forbidden(_)));

        // InvalidToken -> InvalidToken
        let error = KeyrunesError::InvalidToken;
        let rejection: KeyrunesRejection = error.into();
        assert!(matches!(rejection, KeyrunesRejection::InvalidToken));

        // Other -> Other
        let error = KeyrunesError::Other("other error".to_string());
        let rejection: KeyrunesRejection = error.into();
        assert!(matches!(rejection, KeyrunesRejection::Other(_)));
    }
}
