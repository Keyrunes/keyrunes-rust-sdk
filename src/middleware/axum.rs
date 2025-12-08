//! Middleware for Axum integration

use crate::{KeyrunesClient, KeyrunesError, User};
use axum::{
    async_trait,
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

/// Extractor that gets the current authenticated user
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user: User,
}

#[async_trait]
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

        keyrunes_state.client.set_token(token.to_string()).await;
        let user = keyrunes_state
            .client
            .get_current_user()
            .await
            .map_err(|e| KeyrunesRejection::AuthError(e.to_string()))?;

        Ok(AuthenticatedUser { user })
    }
}

/// Extractor to verify if the user belongs to a specific group
#[derive(Clone, Debug)]
pub struct RequireGroup {
    pub user: User,
    pub group_id: String,
}

#[async_trait]
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

        let keyrunes_state = state;

        let has_group = keyrunes_state
            .client
            .has_group(&authenticated_user.user.id, group_id)
            .await
            .map_err(|e| KeyrunesRejection::AuthError(e.to_string()))?;

        if !has_group {
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

/// Extractor to verify if the user is an administrator
#[derive(Clone, Debug)]
pub struct RequireAdmin {
    pub user: User,
}

#[async_trait]
impl FromRequestParts<KeyrunesState> for RequireAdmin {
    type Rejection = KeyrunesRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &KeyrunesState,
    ) -> Result<Self, Self::Rejection> {
        let authenticated_user = AuthenticatedUser::from_request_parts(parts, state).await?;

        let keyrunes_state = state;

        let is_admin = keyrunes_state
            .client
            .has_group(&authenticated_user.user.id, "admins")
            .await
            .map_err(|e| KeyrunesRejection::AuthError(e.to_string()))?;

        if !is_admin {
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
