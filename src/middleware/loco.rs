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
pub async fn get_user_from_token(
    client: &KeyrunesClient,
    token: &str,
) -> Result<AuthenticatedUser, KeyrunesError> {
    client.set_token(token.to_string()).await;
    let user = client.get_current_user().await?;
    Ok(AuthenticatedUser { user })
}

/// Helper to verify if the user belongs to a group
pub async fn require_group(
    client: &KeyrunesClient,
    user: &AuthenticatedUser,
    group_id: &str,
) -> Result<(), KeyrunesError> {
    let has_group = client.has_group(&user.user.id, group_id).await?;
    if !has_group {
        return Err(KeyrunesError::AuthorizationError(format!(
            "User does not belong to group: {}",
            group_id
        )));
    }
    Ok(())
}

/// Helper to verify if the user is an administrator
pub async fn require_admin(
    client: &KeyrunesClient,
    user: &AuthenticatedUser,
) -> Result<(), KeyrunesError> {
    require_group(client, user, "admins").await
}
