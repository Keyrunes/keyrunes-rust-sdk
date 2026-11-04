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

    /// A request carrying an already-authenticated user with `groups`, which is
    /// the situation `require_group` is called in. No state or server is needed:
    /// the check reads the groups the auth middleware already fetched from
    /// `GET /api/me`.
    fn request_with_groups(groups: &[&str]) -> actix_web::HttpRequest {
        use actix_web::HttpMessage;

        let req = TestRequest::default().to_http_request();
        req.extensions_mut().insert(AuthenticatedUser {
            user: keyrunes_rust_sdk::models::User {
                id: "123".to_string(),
                username: "testuser".to_string(),
                email: "test@example.com".to_string(),
                groups: groups.iter().map(|g| g.to_string()).collect(),
                created_at: None,
                updated_at: None,
            },
        });
        req
    }

    /// A group the user actually carries admits the caller — checked against
    /// the groups list, not a mock of the removed HTTP route.
    #[actix_web::test]
    async fn require_group_admits_a_member() {
        let admitted = require_group(&request_with_groups(&["users", "admins"]), "admins")
            .await
            .expect("a member must be admitted");

        assert_eq!(admitted.user.id, "123");
    }

    /// A group the user does not carry is a 403, not a pass — and no request
    /// is made, so a stale claims list cannot be talked past the check.
    #[actix_web::test]
    async fn require_group_refuses_a_non_member() {
        let refused = require_group(&request_with_groups(&["users"]), "admins")
            .await
            .expect_err("a non-member must be refused");

        assert_eq!(
            refused.error_response().status(),
            actix_web::http::StatusCode::FORBIDDEN
        );
    }

    /// The deny path holds even when the user carries nothing at all.
    #[actix_web::test]
    async fn require_group_refuses_when_the_check_cannot_be_made() {
        let refused = require_group(&request_with_groups(&[]), "admins")
            .await
            .expect_err("an empty groups list must not admit anybody");

        assert_eq!(
            refused.error_response().status(),
            actix_web::http::StatusCode::FORBIDDEN
        );
    }

    /// `require_admin` admits the privileged names exactly. A group that merely
    /// contains "admin" as a substring (e.g. "non-admin") must NOT pass — that
    /// was the old heuristic's flaw.
    #[actix_web::test]
    async fn require_admin_asks_about_the_admins_group() {
        for name in ["admin", "admins", "superadmin"] {
            require_admin(&request_with_groups(&[name]))
                .await
                .unwrap_or_else(|_| panic!("{} must be admitted", name));
        }

        let refused = require_admin(&request_with_groups(&["non-admin", "users"]))
            .await
            .expect_err("a substring name must not grant admin");
        assert_eq!(
            refused.error_response().status(),
            actix_web::http::StatusCode::FORBIDDEN
        );
    }
}
