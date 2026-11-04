//! Middleware for Axum integration

use crate::{KeyrunesClient, KeyrunesError, User};
use axum::{
    extract::{FromRequestParts, Query},
    http::request::Parts,
    http::StatusCode,
    response::{IntoResponse, Response},
    RequestPartsExt,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Keyrunes client state for use in Axum
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

/// Extractor that gets the current authenticated user.
///
/// Resolves against `/api/me` with the request's own token and never stores
/// it on the shared client, so concurrent requests cannot overwrite each
/// other's identity mid-flight.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user: User,
}

impl FromRequestParts<KeyrunesState> for AuthenticatedUser {
    type Rejection = KeyrunesRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &KeyrunesState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(KeyrunesRejection::MissingToken)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(KeyrunesRejection::InvalidToken)?;

        let keyrunes_state = state;

        let user = keyrunes_state
            .client
            .get_current_user_with_token(token)
            .await
            .map_err(|e| KeyrunesRejection::AuthError(e.to_string()))?;

        Ok(AuthenticatedUser { user })
    }
}

/// Extractor to verify if the user belongs to a specific group.
///
/// Checks the server-verified `groups` names fetched through `/api/me`; the
/// old `has_group` call targeted `GET /api/users/{uid}/groups/{gid}`, a route
/// current servers removed (it always answered 404).
#[derive(Clone, Debug)]
pub struct RequireGroup {
    pub user: User,
    pub group_id: String,
}

impl FromRequestParts<KeyrunesState> for RequireGroup {
    type Rejection = KeyrunesRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &KeyrunesState,
    ) -> Result<Self, Self::Rejection> {
        let authenticated_user = AuthenticatedUser::from_request_parts(parts, state).await?;

        let query_params = parts
            .extract::<Query<HashMap<String, String>>>()
            .await
            .map_err(|_| KeyrunesRejection::Other("Error processing query params".to_string()))?;

        let group_id = query_params
            .get("group_id")
            .ok_or(KeyrunesRejection::MissingGroup)?;

        if !authenticated_user.user.groups.iter().any(|g| g == group_id) {
            return Err(KeyrunesRejection::Forbidden(format!(
                "User does not belong to group: {}",
                group_id
            )));
        }

        Ok(RequireGroup {
            user: authenticated_user.user,
            group_id: group_id.clone(),
        })
    }
}

/// Extractor to verify if the user is an administrator.
///
/// Requires exact membership in the server's privileged group names
/// (`admin`, `admins`, `superadmin`); the old check ("admins" only, via the
/// removed `has_group` route) denied real admins and hit a 404.
#[derive(Clone, Debug)]
pub struct RequireAdmin {
    pub user: User,
}

impl FromRequestParts<KeyrunesState> for RequireAdmin {
    type Rejection = KeyrunesRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &KeyrunesState,
    ) -> Result<Self, Self::Rejection> {
        let authenticated_user = AuthenticatedUser::from_request_parts(parts, state).await?;

        if !authenticated_user
            .user
            .groups
            .iter()
            .any(|g| matches!(g.as_str(), "admin" | "admins" | "superadmin"))
        {
            return Err(KeyrunesRejection::Forbidden(
                "Access denied: administrator privileges required".to_string(),
            ));
        }

        Ok(RequireAdmin {
            user: authenticated_user.user,
        })
    }
}

/// Custom rejection for Keyrunes errors in Axum
#[derive(Debug)]
pub enum KeyrunesRejection {
    MissingToken,
    InvalidToken,
    MissingState,
    MissingGroup,
    AuthError(String),
    Forbidden(String),
    Other(String),
}

impl IntoResponse for KeyrunesRejection {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            KeyrunesRejection::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Authentication token missing".to_string(),
            ),
            KeyrunesRejection::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid authentication token".to_string(),
            ),
            KeyrunesRejection::MissingState => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Keyrunes state not configured".to_string(),
            ),
            KeyrunesRejection::MissingGroup => (
                StatusCode::BAD_REQUEST,
                "Missing group_id parameter".to_string(),
            ),
            KeyrunesRejection::AuthError(msg) => (StatusCode::UNAUTHORIZED, msg),
            KeyrunesRejection::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            KeyrunesRejection::Other(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, message).into_response()
    }
}

impl From<KeyrunesError> for KeyrunesRejection {
    fn from(err: KeyrunesError) -> Self {
        match err {
            KeyrunesError::AuthenticationError(msg) => KeyrunesRejection::AuthError(msg),
            KeyrunesError::AuthorizationError(msg) => KeyrunesRejection::Forbidden(msg),
            KeyrunesError::InvalidToken => KeyrunesRejection::InvalidToken,
            _ => KeyrunesRejection::Other(err.to_string()),
        }
    }
}
