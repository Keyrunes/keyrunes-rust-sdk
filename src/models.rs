//! Data models for the Keyrunes API
//!
//! This module contains all data structures used for communication
//! with the Keyrunes API. All models implement [`Serialize`] and
//! [`Deserialize`] from serde for JSON conversion.
//!
//! ## Quick Start
//!
//! ```
//! use keyrunes_rust_sdk::models::*;
//!
//! let creds = LoginCredentials {
//!     identity: "user@example.com".to_string(),
//!     password: "password123".to_string(),
//! };
//!
//! let json = serde_json::to_string(&creds).unwrap();
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User model
///
/// Represents a user in the Keyrunes system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "UserResponse")]
pub struct User {
    /// Unique user ID
    pub id: String,
    /// Username
    pub username: String,
    /// User email
    pub email: String,
    /// List of groups the user belongs to
    #[serde(default)]
    pub groups: Vec<String>,
    /// User creation date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Last update date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// User response from API (handles different ID formats)
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UserResponse {
    #[serde(default, rename = "id")]
    id_str: Option<String>,
    #[serde(default, rename = "user_id")]
    user_id_num: Option<u64>,
    #[serde(default, rename = "external_id")]
    external_id_str: Option<String>,
    username: String,
    email: String,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    updated_at: Option<DateTime<Utc>>,
}

impl From<UserResponse> for User {
    fn from(response: UserResponse) -> Self {
        let id = response
            .id_str
            .or(response.external_id_str)
            .unwrap_or_else(|| {
                response
                    .user_id_num
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            });
        User {
            id,
            username: response.username,
            email: response.email,
            groups: response.groups,
            created_at: response.created_at,
            updated_at: response.updated_at,
        }
    }
}

/// Registration response wrapper
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    #[doc(hidden)]
    pub(crate) user: UserResponse,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub requires_password_change: Option<bool>,
}

/// Group model
///
/// Represents a group in the Keyrunes system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique group ID
    pub id: String,
    /// Group name
    pub name: String,
    /// Group description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Group creation date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Authentication token model
///
/// Represents a JWT token returned after successful authentication.
/// Accepts both legacy format (access_token) and current format (token).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "TokenResponse")]
pub struct Token {
    /// JWT token
    pub token: String,
    /// Token type (e.g., "bearer")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token_type: Option<String>,
    /// Token expiration in seconds (optional)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_in: Option<i64>,
    /// Refresh token (optional)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    /// Token expiration date (optional)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TokenResponse {
    NewFormat {
        token: String,
        #[serde(default)]
        token_type: Option<String>,
        #[serde(default)]
        expires_in: Option<i64>,
        #[serde(default)]
        refresh_token: Option<String>,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
    },
    LegacyFormat {
        access_token: String,
        #[serde(default)]
        token_type: Option<String>,
        #[serde(default)]
        expires_in: Option<i64>,
        #[serde(default)]
        refresh_token: Option<String>,
    },
}

impl From<TokenResponse> for Token {
    fn from(response: TokenResponse) -> Self {
        match response {
            TokenResponse::NewFormat {
                token,
                token_type,
                expires_in,
                refresh_token,
                expires_at,
            } => Token {
                token,
                token_type,
                expires_in,
                refresh_token,
                expires_at,
            },
            TokenResponse::LegacyFormat {
                access_token,
                token_type,
                expires_in,
                refresh_token,
            } => Token {
                token: access_token,
                token_type,
                expires_in,
                refresh_token,
                expires_at: None,
            },
        }
    }
}

/// User registration data
///
/// Used to register a new user in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistration {
    /// Username
    pub username: String,
    /// User email
    pub email: String,
    /// User password (minimum 8 characters)
    pub password: String,
}

/// Administrator registration data
///
/// Used to register a new administrator in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRegistration {
    /// Username
    pub username: String,
    /// Administrator email
    pub email: String,
    /// Administrator password
    pub password: String,
    /// Administrator key
    pub admin_key: String,
}

/// Login credentials
///
/// Used to perform login in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCredentials {
    /// Username or email
    pub identity: String,
    /// User password
    pub password: String,
}

/// Group verification result
///
/// Represents the result of a group membership verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCheck {
    /// Indicates whether the user belongs to the group
    #[serde(alias = "has_access", alias = "has_group")]
    pub has_group: bool,
}

/// Group verification response
///
/// Complete API response for group verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupVerificationResponse {
    /// Verified user ID
    pub user_id: String,
    /// Verified group ID
    pub group_id: String,
    /// Indicates whether the user belongs to the group
    pub has_group: bool,
}
