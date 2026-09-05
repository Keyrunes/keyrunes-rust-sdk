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

    /// A route behind the group guard. The guard reads `group_id` from the
    /// query string itself, so the handler only has to report what it got.
    #[rocket::get("/guarded")]
    fn guarded(require: keyrunes_rust_sdk::middleware::rocket::RequireGroup) -> String {
        format!("{}:{}", require.user.id, require.group_id)
    }

    const CURRENT_USER: &str =
        r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users"]}"#;

    /// A Rocket instance pointed at a mocked Keyrunes, with `/api/me` already
    /// answering: every case below has to get past authentication first.
    async fn guarded_app(server: &mut mockito::ServerGuard) -> rocket::local::asynchronous::Client {
        server
            .mock("GET", "/api/me")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(CURRENT_USER)
            .create_async()
            .await;

        let client = KeyrunesClient::new(server.url()).unwrap();
        let rocket = rocket::build()
            .manage(KeyrunesState::new(client))
            .mount("/", rocket::routes![guarded]);

        rocket::local::asynchronous::Client::tracked(rocket)
            .await
            .expect("the test rocket must launch")
    }

    fn bearer() -> rocket::http::Header<'static> {
        rocket::http::Header::new("authorization", "Bearer valid-token")
    }

    /// The path that matters: a named group, a membership answer of `true`,
    /// and the guard hands the route both the user and the group it checked.
    #[rocket::async_test]
    async fn a_member_reaches_the_guarded_route() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/users/123/groups/admins")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":true}"#)
            .create_async()
            .await;

        let app = guarded_app(&mut server).await;
        let response = app
            .get("/guarded?group_id=admins")
            .header(bearer())
            .dispatch()
            .await;

        assert_eq!(response.status(), rocket::http::Status::Ok);
        assert_eq!(response.into_string().await.unwrap(), "123:admins");
        mock.assert_async().await;
    }

    /// Without a group named in the query there is nothing to authorise
    /// against, and the guard says so rather than picking a default.
    #[rocket::async_test]
    async fn a_request_naming_no_group_is_a_bad_request() {
        let mut server = mockito::Server::new_async().await;
        let app = guarded_app(&mut server).await;

        let response = app.get("/guarded").header(bearer()).dispatch().await;

        assert_eq!(response.status(), rocket::http::Status::BadRequest);
    }

    /// A membership answer of `false` closes the route.
    #[rocket::async_test]
    async fn a_non_member_is_forbidden() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/api/users/123/groups/admins")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"has_group":false}"#)
            .create_async()
            .await;

        let app = guarded_app(&mut server).await;
        let response = app
            .get("/guarded?group_id=admins")
            .header(bearer())
            .dispatch()
            .await;

        assert_eq!(response.status(), rocket::http::Status::Forbidden);
    }

    /// Authentication is checked before the group is even read.
    #[rocket::async_test]
    async fn an_unauthenticated_request_never_reaches_the_group_check() {
        let mut server = mockito::Server::new_async().await;
        let app = guarded_app(&mut server).await;

        let response = app.get("/guarded?group_id=admins").dispatch().await;

        assert_eq!(response.status(), rocket::http::Status::Unauthorized);
    }
}
