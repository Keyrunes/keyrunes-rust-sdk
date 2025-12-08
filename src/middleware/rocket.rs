//! Middleware for Rocket integration

use crate::{KeyrunesClient, KeyrunesError, User};
use rocket::{
    request::{FromRequest, Outcome, Request},
    State,
};
use std::sync::Arc;

/// Keyrunes client state for use in Rocket
#[derive(Clone)]
pub struct KeyrunesState {
    pub client: Arc<KeyrunesClient>,
}

impl KeyrunesState {
    pub fn new(client: KeyrunesClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }
}

/// Guard that gets the current authenticated user
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user: User,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = KeyrunesError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = match request.headers().get_one("authorization") {
            Some(header) => header,
            None => {
                return Outcome::Error((
                    rocket::http::Status::Unauthorized,
                    KeyrunesError::AuthenticationError("Token missing".to_string()),
                ))
            }
        };

        let token = match auth_header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => {
                return Outcome::Error((
                    rocket::http::Status::Unauthorized,
                    KeyrunesError::AuthenticationError("Invalid token format".to_string()),
                ))
            }
        };

        let state = match request.guard::<&State<KeyrunesState>>().await {
            Outcome::Success(s) => s,
            _ => {
                return Outcome::Error((
                    rocket::http::Status::InternalServerError,
                    KeyrunesError::Other("Keyrunes state not configured".to_string()),
                ))
            }
        };

        state.client.set_token(token.to_string()).await;
        match state.client.get_current_user().await {
            Ok(user) => Outcome::Success(AuthenticatedUser { user }),
            Err(e) => Outcome::Error((rocket::http::Status::Unauthorized, e)),
        }
    }
}

/// Guard that verifies if the user belongs to a specific group
#[derive(Debug, Clone)]
pub struct RequireGroup {
    pub user: User,
    pub group_id: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequireGroup {
    type Error = KeyrunesError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let authenticated_user = match AuthenticatedUser::from_request(request).await {
            Outcome::Success(user) => user,
            Outcome::Error(err) => return Outcome::Error(err),
            Outcome::Forward(_) => {
                return Outcome::Error((
                    rocket::http::Status::Unauthorized,
                    KeyrunesError::AuthenticationError("Not authenticated".to_string()),
                ))
            }
        };

        let group_id = match request.query_value::<String>("group_id") {
            Some(Ok(gid)) => gid,
            _ => {
                return Outcome::Error((
                    rocket::http::Status::BadRequest,
                    KeyrunesError::Other("Missing group_id parameter in query string".to_string()),
                ))
            }
        };

        let state = match request.guard::<&State<KeyrunesState>>().await {
            rocket::request::Outcome::Success(s) => s,
            _ => {
                return Outcome::Error((
                    rocket::http::Status::InternalServerError,
                    KeyrunesError::Other("Keyrunes state not configured".to_string()),
                ))
            }
        };

        match state
            .client
            .has_group(&authenticated_user.user.id, &group_id)
            .await
        {
            Ok(true) => Outcome::Success(RequireGroup {
                user: authenticated_user.user,
                group_id,
            }),
            Ok(false) => Outcome::Error((
                rocket::http::Status::Forbidden,
                KeyrunesError::AuthorizationError(format!(
                    "User does not belong to group: {}",
                    group_id
                )),
            )),
            Err(e) => Outcome::Error((rocket::http::Status::Unauthorized, e)),
        }
    }
}

/// Guard that verifies if the user is an administrator
#[derive(Debug, Clone)]
pub struct RequireAdmin {
    pub user: User,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequireAdmin {
    type Error = KeyrunesError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let authenticated_user = match AuthenticatedUser::from_request(request).await {
            Outcome::Success(user) => user,
            Outcome::Error(err) => return Outcome::Error(err),
            Outcome::Forward(_) => {
                return Outcome::Error((
                    rocket::http::Status::Unauthorized,
                    KeyrunesError::AuthenticationError("Not authenticated".to_string()),
                ))
            }
        };

        let state = match request.guard::<&State<KeyrunesState>>().await {
            rocket::request::Outcome::Success(s) => s,
            _ => {
                return Outcome::Error((
                    rocket::http::Status::InternalServerError,
                    KeyrunesError::Other("Keyrunes state not configured".to_string()),
                ))
            }
        };

        match state
            .client
            .has_group(&authenticated_user.user.id, "admins")
            .await
        {
            Ok(true) => Outcome::Success(RequireAdmin {
                user: authenticated_user.user,
            }),
            Ok(false) => Outcome::Error((
                rocket::http::Status::Forbidden,
                KeyrunesError::AuthorizationError(
                    "Access denied: administrator privileges required".to_string(),
                ),
            )),
            Err(e) => Outcome::Error((rocket::http::Status::Unauthorized, e)),
        }
    }
}
