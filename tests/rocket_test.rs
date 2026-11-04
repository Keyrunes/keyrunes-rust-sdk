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
            ..Default::default()
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
            ..Default::default()
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

    const MEMBER_USER: &str = r#"{"user_id":123,"username":"testuser","email":"test@example.com","groups":["users","admins"]}"#;

    /// A Rocket instance pointed at a mocked Keyrunes, with `/api/me` already
    /// answering: every case below has to get past authentication first.
    async fn guarded_app(server: &mut mockito::ServerGuard) -> rocket::local::asynchronous::Client {
        guarded_app_with(server, CURRENT_USER).await
    }

    /// Same, but choosing the `/api/me` payload so the guard sees whichever
    /// group membership the case needs.
    async fn guarded_app_with(
        server: &mut mockito::ServerGuard,
        current_user: &str,
    ) -> rocket::local::asynchronous::Client {
        server
            .mock("GET", "/api/me")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(current_user)
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

    /// The path that matters: the guard reads group names off the user
    /// `/api/me` returned, and a member reaches the route with both the user
    /// and the group it checked.
    #[rocket::async_test]
    async fn a_member_reaches_the_guarded_route() {
        let mut server = mockito::Server::new_async().await;

        let app = guarded_app_with(&mut server, MEMBER_USER).await;
        let response = app
            .get("/guarded?group_id=admins")
            .header(bearer())
            .dispatch()
            .await;

        assert_eq!(response.status(), rocket::http::Status::Ok);
        assert_eq!(response.into_string().await.unwrap(), "123:admins");
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

    /// A user without the named group in `/api/me`'s answer is closed out:
    /// the check is the group list itself, no separate membership route.
    #[rocket::async_test]
    async fn a_non_member_is_forbidden() {
        let mut server = mockito::Server::new_async().await;

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
