//! Middleware for Loco integration (Rails-like framework for Rust)

use crate::{KeyrunesClient, KeyrunesError, User};
use std::sync::Arc;

/// Keyrunes client state for use in Loco
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

/// Structure representing an authenticated user in Loco
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user: User,
}

/// Helper to extract token from Authorization header
pub fn extract_token_from_headers(
    headers: &impl std::borrow::Borrow<http::HeaderMap>,
) -> Option<String> {
    headers
        .borrow()
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

/// Helper to get authenticated user from a token
///
/// Resolves against `/api/me` with the supplied token without storing it on
/// the client: the client is shared across requests, and `set_token` from one
/// request could make another request answer with the wrong identity.
pub async fn get_user_from_token(
    client: &KeyrunesClient,
    token: &str,
) -> Result<AuthenticatedUser, KeyrunesError> {
    let user = client.get_current_user_with_token(token).await?;
    Ok(AuthenticatedUser { user })
}

/// Helper to verify if the user belongs to a group
///
/// Checks the server-verified group names carried by `user`. The old
/// `has_group` call hit `GET /api/users/{uid}/groups/{gid}`, a route the
/// server no longer exposes.
pub async fn require_group(
    _client: &KeyrunesClient,
    user: &AuthenticatedUser,
    group_id: &str,
) -> Result<(), KeyrunesError> {
    if !user.user.groups.iter().any(|g| g == group_id) {
        return Err(KeyrunesError::AuthorizationError(format!(
            "User does not belong to group: {}",
            group_id
        )));
    }
    Ok(())
}

/// Helper to verify if the user is an administrator
///
/// The server's admin group is "admin"; global owners carry "superadmin";
/// "admins" is kept for legacy fixtures.
pub async fn require_admin(
    client: &KeyrunesClient,
    user: &AuthenticatedUser,
) -> Result<(), KeyrunesError> {
    let is_admin = user
        .user
        .groups
        .iter()
        .any(|g| matches!(g.as_str(), "admin" | "admins" | "superadmin"));
    if !is_admin {
        return Err(KeyrunesError::AuthorizationError(
            "Access denied: administrator privileges required".to_string(),
        ));
    }
    let _ = client;
    Ok(())
}
