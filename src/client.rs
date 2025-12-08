//! Main client for interacting with the Keyrunes API
//!
//! This module contains the [`KeyrunesClient`], the main structure for
//! interacting with the Keyrunes API.
//!
//! ## Quick Start
//!
//! ```
//! use keyrunes_rust_sdk::KeyrunesClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = KeyrunesClient::new("https://keyrunes.example.com")?;
//! let user = client.register("john", "john@example.com", "password123").await?;
//! let token = client.login("john@example.com", "password123").await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{KeyrunesError, Result};
use crate::models::*;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Client for interacting with the Keyrunes API
///
/// The `KeyrunesClient` is the main structure for performing authentication
/// and authorization operations with the Keyrunes service.
///
/// ## Examples
///
/// ### Creating a client
///
/// ```
/// use keyrunes_rust_sdk::KeyrunesClient;
///
/// let client = KeyrunesClient::new("https://keyrunes.example.com")
///     .expect("Invalid URL");
/// ```
///
/// ### Registration and login
///
/// ```
/// # use keyrunes_rust_sdk::KeyrunesClient;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
/// let user = client.register("john", "john@example.com", "password123").await?;
/// let token = client.login("john@example.com", "password123").await?;
/// println!("Token: {}", token.token);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct KeyrunesClient {
    pub(crate) base_url: String,
    client: Client,
    pub(crate) token: Arc<RwLock<Option<String>>>,
}

impl KeyrunesClient {
    /// Creates a new instance of the Keyrunes client.
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL of the Keyrunes API (e.g., <https://keyrunes.example.com>)
    ///
    /// # Returns
    ///
    /// Returns `Result<KeyrunesClient, KeyrunesError>`:
    /// - `Ok(client)` if the URL is valid and the client was created successfully
    /// - `Err(KeyrunesError::InvalidUrl)` if the URL is invalid
    /// - `Err(KeyrunesError::HttpError)` if there was an error creating the HTTP client
    ///
    /// # Examples
    ///
    /// ```
    /// use keyrunes_rust_sdk::KeyrunesClient;
    ///
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")
    ///     .expect("Invalid URL");
    /// ```
    ///
    /// URLs with trailing slashes are normalized:
    ///
    /// ```
    /// use keyrunes_rust_sdk::KeyrunesClient;
    ///
    /// let client = KeyrunesClient::new("https://keyrunes.example.com/")
    ///     .expect("Invalid URL");
    /// ```
    pub fn new<S: Into<String>>(base_url: S) -> Result<Self> {
        let base_url = base_url.into();
        url::Url::parse(&base_url)?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .user_agent("keyrunes-rust-sdk/0.1.0")
                .build()?,
            token: Arc::new(RwLock::new(None)),
        })
    }

    /// Performs login and returns the authentication token.
    ///
    /// # Arguments
    ///
    /// * `username` - Username or email
    /// * `password` - User password
    ///
    /// # Returns
    ///
    /// Returns `Result<Token, KeyrunesError>`:
    /// - `Ok(token)` if login was successful
    /// - `Err(KeyrunesError::AuthenticationError)` if credentials are invalid
    /// - `Err(KeyrunesError::NetworkError)` if there was a network error
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let token = client.login("user@example.com", "password").await?;
    /// println!("Token: {}", token.token);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login<S: Into<String>>(&self, username: S, password: S) -> Result<Token> {
        let url = format!("{}/api/login", self.base_url);
        let credentials = LoginCredentials {
            identity: username.into(),
            password: password.into(),
        };

        let response = self.client.post(&url).json(&credentials).send().await?;

        let token = self.handle_response::<Token>(response).await?;
        let token_value = token.token.clone();
        *self.token.write().await = Some(token_value);
        Ok(token)
    }

    /// Registers a new user.
    ///
    /// # Arguments
    ///
    /// * `username` - Username
    /// * `email` - User email
    /// * `password` - User password (minimum 8 characters)
    ///
    /// # Returns
    ///
    /// Returns `Result<User, KeyrunesError>`:
    /// - `Ok(user)` if registration was successful
    /// - `Err(KeyrunesError::AuthenticationError)` if email is already in use
    /// - `Err(KeyrunesError::HttpError)` if there was an error in the request
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let user = client.register("john_doe", "john@example.com", "password123").await?;
    /// println!("User registered: {} ({})", user.username, user.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register<S: Into<String>>(
        &self,
        username: S,
        email: S,
        password: S,
    ) -> Result<User> {
        let url = format!("{}/api/register", self.base_url);
        let registration = UserRegistration {
            username: username.into(),
            email: email.into(),
            password: password.into(),
        };

        let response = self.client.post(&url).json(&registration).send().await?;

        let register_response: crate::models::RegisterResponse =
            self.handle_response(response).await?;
        Ok(crate::models::User::from(register_response.user))
    }

    async fn handle_response<T: for<'de> serde::Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();
        let url = response.url().clone();
        let body = response.text().await?;

        if status.is_success() {
            serde_json::from_str(&body).map_err(Into::into)
        } else {
            Err(self.handle_error(status, &body, &url))
        }
    }

    fn handle_error(
        &self,
        status: reqwest::StatusCode,
        body: &str,
        url: &reqwest::Url,
    ) -> KeyrunesError {
        let error_message = if body.trim_start().starts_with('<') {
            format!("HTTP {} - Received HTML response (endpoint may not exist or path is incorrect). Tried: {}", status.as_u16(), url)
        } else {
            let api_message = serde_json::from_str::<serde_json::Value>(body)
                .map(|v| {
                    v.get("message")
                        .or_else(|| v.get("error"))
                        .and_then(|m| m.as_str())
                        .unwrap_or(body)
                        .to_string()
                })
                .unwrap_or_else(|_| {
                    if body.len() > 200 {
                        format!("{}...", &body[..200])
                    } else {
                        body.to_string()
                    }
                });
            format!("{} (URL: {})", api_message, url)
        };

        match status {
            reqwest::StatusCode::UNAUTHORIZED => KeyrunesError::AuthenticationError(error_message),
            reqwest::StatusCode::FORBIDDEN => KeyrunesError::AuthorizationError(error_message),
            reqwest::StatusCode::NOT_FOUND => {
                if error_message.contains("user") || error_message.contains("User") {
                    KeyrunesError::UserNotFoundError(error_message)
                } else if error_message.contains("group") || error_message.contains("Group") {
                    KeyrunesError::GroupNotFoundError(error_message)
                } else {
                    KeyrunesError::Other(format!("Resource not found: {}", error_message))
                }
            }
            _ => KeyrunesError::HttpError(format!("HTTP {}: {}", status.as_u16(), error_message)),
        }
    }
}
