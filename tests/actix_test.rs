#[cfg(feature = "actix")]
mod actix_tests {
    use actix_web::test::{call_service, TestRequest};
    use actix_web::{test, web::Data, App};
    use keyrunes_rust_sdk::{
        middleware::actix::{AuthenticatedUser, KeyrunesAuthMiddleware},
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
}
