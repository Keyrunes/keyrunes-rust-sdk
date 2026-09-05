#[cfg(feature = "actix")]
mod actix_tests {
    use actix_web::test::{call_service, TestRequest};
    use actix_web::{test, web::Data, App};
    use keyrunes_rust_sdk::{
        middleware::actix::{
            require_admin, require_group, AuthenticatedUser, KeyrunesAuthMiddleware,
        },
        KeyrunesClient,
    };
    use mockito::Server;

    fn create_mock_state(base_url: &str) -> keyrunes_rust_sdk::middleware::actix::KeyrunesState {
        let client = KeyrunesClient::new(base_url).unwrap();
        keyrunes_rust_sdk::middleware::actix::KeyrunesState::new(client)
    }

    #[actix_web::test]
    async fn test_authenticated_user_success() {
        let mut server = Server::new_async().await;
        let server_url = server.url();

        let mock_user_body = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users"]}"#;
        let _mock = server
            .mock("GET", "/api/me")
            .match_header("authorization", "Bearer valid-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_user_body)
            .create_async()
            .await;

        let state = create_mock_state(&server_url);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(state))
                .wrap(KeyrunesAuthMiddleware)
                .route(
                    "/test",
                    actix_web::web::get().to(|user: AuthenticatedUser| async move {
                        actix_web::HttpResponse::Ok().body(user.user.username.clone())
                    }),
                ),
        )
        .await;

        let req = TestRequest::get()
            .uri("/test")
            .insert_header(("Authorization", "Bearer valid-token"))
            .to_request();

        let resp = call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_authenticated_user_missing_token() {
        let server = Server::new_async().await;
        let state = create_mock_state(&server.url());

        let app = test::init_service(
            App::new()
                .app_data(Data::new(state))
                .wrap(KeyrunesAuthMiddleware)
                .route(
                    "/test",
                    actix_web::web::get().to(|_: AuthenticatedUser| async move {
                        actix_web::HttpResponse::Ok().body("ok")
                    }),
                ),
        )
        .await;

        let req = TestRequest::get().uri("/test").to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_authenticated_user_invalid_format() {
        let server = Server::new_async().await;
        let state = create_mock_state(&server.url());

        let app = test::init_service(
            App::new()
                .app_data(Data::new(state))
                .wrap(KeyrunesAuthMiddleware)
                .route(
                    "/test",
                    actix_web::web::get().to(|_: AuthenticatedUser| async move {
                        actix_web::HttpResponse::Ok().body("ok")
                    }),
                ),
        )
        .await;

        let req = TestRequest::get()
            .uri("/test")
            .insert_header(("Authorization", "Basic abc123"))
            .to_request();

        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_keyrunes_state_creation() {
        let server = Server::new_async().await;
        let _state = create_mock_state(&server.url());
    }

    #[actix_web::test]
    async fn test_authenticated_user_clone() {
        let user = keyrunes_rust_sdk::models::User {
            id: "123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            groups: vec!["users".to_string()],
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        };

        let auth_user = AuthenticatedUser { user: user.clone() };
        let cloned = auth_user.clone();

        assert_eq!(cloned.user.id, "123");
        assert_eq!(cloned.user.username, "testuser");
    }

    /// A user already put into the request by `KeyrunesAuthMiddleware`, which
    /// is what `require_group` picks up.
    fn sample_user() -> keyrunes_rust_sdk::models::User {
        keyrunes_rust_sdk::models::User {
            id: "123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            groups: vec!["users".to_string()],
            created_at: None,
            updated_at: None,
        }
    }

    /// A request carrying the state and an already-authenticated user, which is
    /// the situation `require_group` is called in.
    fn authenticated_request(
        state: keyrunes_rust_sdk::middleware::actix::KeyrunesState,
    ) -> actix_web::HttpRequest {
        use actix_web::HttpMessage;

        let req = TestRequest::default()
            .app_data(Data::new(state))
            .to_http_request();
        req.extensions_mut().insert(AuthenticatedUser {
            user: sample_user(),
        });
        req
    }

    /// A membership answer of `true` lets the caller through. Without this the
    /// deny path below would still pass with the check inverted.
    #[actix_web::test]
    async fn require_group_admits_a_member() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/api/users/123/groups/admins")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":true}"#)
            .create_async()
            .await;

        let state = create_mock_state(&server.url());
        state.client.set_token("valid-token").await;

        let admitted = require_group(&authenticated_request(state), "admins")
            .await
            .expect("a member must be admitted");

        assert_eq!(admitted.user.id, "123");
        mock.assert_async().await;
    }

    /// A membership answer of `false` is a 403, not a pass.
    #[actix_web::test]
    async fn require_group_refuses_a_non_member() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/api/users/123/groups/admins")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":false}"#)
            .create_async()
            .await;

        let state = create_mock_state(&server.url());
        state.client.set_token("valid-token").await;

        let refused = require_group(&authenticated_request(state), "admins")
            .await
            .expect_err("a non-member must be refused");

        assert_eq!(
            refused.error_response().status(),
            actix_web::http::StatusCode::FORBIDDEN
        );
        mock.assert_async().await;
    }

    /// An unreachable Keyrunes is a refusal too: an authorization check that
    /// cannot be made has not been passed.
    #[actix_web::test]
    async fn require_group_refuses_when_the_check_cannot_be_made() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("GET", "/api/users/123/groups/admins")
            .with_status(500)
            .with_body("boom")
            .create_async()
            .await;

        let state = create_mock_state(&server.url());
        state.client.set_token("valid-token").await;

        let refused = require_group(&authenticated_request(state), "admins")
            .await
            .expect_err("a failed check must not admit anybody");

        assert_eq!(
            refused.error_response().status(),
            actix_web::http::StatusCode::FORBIDDEN
        );
    }

    /// `require_admin` is `require_group` with one group name baked in; the
    /// mock asserts which name, since that is the whole of its behaviour.
    #[actix_web::test]
    async fn require_admin_asks_about_the_admins_group() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/api/users/123/groups/admins")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":true}"#)
            .create_async()
            .await;

        let state = create_mock_state(&server.url());
        state.client.set_token("valid-token").await;

        require_admin(&authenticated_request(state))
            .await
            .expect("an admin must be admitted");

        mock.assert_async().await;
    }
}
