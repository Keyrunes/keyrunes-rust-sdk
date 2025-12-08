//! Error types for the Keyrunes library
//!
//! This module contains the error types used by the library.
//! The main type is [`KeyrunesError`], an enum that represents
//! all possible errors that can occur during interaction
//! with the Keyrunes API.
//!
//! ## Quick Start
//!
//! ```
//! use keyrunes_rust_sdk::KeyrunesError;
//!
//! let error = KeyrunesError::AuthenticationError("Invalid credentials".to_string());
//! println!("Error: {}", error);
//! ```

pub type Result<T> = std::result::Result<T, KeyrunesError>;

/// Base error type for the Keyrunes library
///
/// This enum represents all types of errors that can occur
/// during interaction with the Keyrunes API.
#[derive(Debug, thiserror::Error)]
pub enum KeyrunesError {
    /// Authentication error (invalid credentials, expired token, etc.)
    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    /// Authorization error (access denied, insufficient permissions, etc.)
    #[error("Authorization error: {0}")]
    AuthorizationError(String),

    /// Group not found
    #[error("Group not found: {0}")]
    GroupNotFoundError(String),

    /// User not found
    #[error("User not found: {0}")]
    UserNotFoundError(String),

    /// Network error (timeout, connection lost, etc.)
    #[error("Network error: {0}")]
    NetworkError(String),

    /// JSON serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Generic HTTP error
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// Invalid URL
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Invalid or missing token
    #[error("Invalid or missing token")]
    InvalidToken,

    /// Other uncategorized errors
    #[error("Error: {0}")]
    Other(String),
}

impl From<reqwest::Error> for KeyrunesError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() || err.is_connect() {
            KeyrunesError::NetworkError(err.to_string())
        } else {
            KeyrunesError::HttpError(err.to_string())
        }
    }
}

impl From<serde_json::Error> for KeyrunesError {
    fn from(err: serde_json::Error) -> Self {
        KeyrunesError::SerializationError(err.to_string())
    }
}

impl From<url::ParseError> for KeyrunesError {
    fn from(err: url::ParseError) -> Self {
        KeyrunesError::InvalidUrl(err.to_string())
    }
}
