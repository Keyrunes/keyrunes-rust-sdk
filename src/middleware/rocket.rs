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

        // Resolve the caller against /api/me with the request's own token:
        // storing it on the shared client (set_token) would let a concurrent
        // request read another user's identity.
        match state.client.get_current_user_with_token(token).await {
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

        // The guard already fetched /api/me server-side; `user.groups` is the
        // authoritative membership list. The old has_group call hit
        // GET /api/users/{uid}/groups/{gid}, a route the server no longer
        // exposes — every check answered 404 and was reported as a failure.
        if authenticated_user
            .user
            .groups
            .iter()
            .any(|g| g == &group_id)
        {
            Outcome::Success(RequireGroup {
                user: authenticated_user.user,
                group_id,
            })
        } else {
            Outcome::Error((
                rocket::http::Status::Forbidden,
                KeyrunesError::AuthorizationError(format!(
                    "User does not belong to group: {}",
                    group_id
                )),
            ))
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

        // Same reasoning as RequireGroup: answer from the server-verified
        // group names. "admins" alone was wrong — the server's admin group is
        // "admin", and global owners carry "superadmin".
        let is_admin = authenticated_user
            .user
            .groups
            .iter()
            .any(|g| matches!(g.as_str(), "admin" | "admins" | "superadmin"));
        if is_admin {
            Outcome::Success(RequireAdmin {
                user: authenticated_user.user,
            })
        } else {
            Outcome::Error((
                rocket::http::Status::Forbidden,
                KeyrunesError::AuthorizationError(
                    "Access denied: administrator privileges required".to_string(),
                ),
            ))
        }
    }
}
