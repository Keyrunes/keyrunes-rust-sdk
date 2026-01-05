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
//! let user = client.register("john", "john@example.com", "password123", None).await?;
//! let token = client.login("john@example.com", "password123", None).await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{KeyrunesError, Result};
use crate::models::*;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

// Constants
const USER_AGENT: &str = "keyrunes-rust-sdk/0.1.0";
const HEADER_ORG_KEY: &str = "X-Organization-Key";
const ENV_ORG_KEY: &str = "KEYRUNES_ORG_KEY";

const ENDPOINT_LOGIN: &str = "/api/login";
const ENDPOINT_REGISTER: &str = "/api/register";
const ENDPOINT_ME: &str = "/api/me";

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
/// let user = client.register("john", "john@example.com", "password123", None).await?;
/// let token = client.login("john@example.com", "password123", None).await?;
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

        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(org_key) = std::env::var(ENV_ORG_KEY) {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&org_key) {
                headers.insert(HEADER_ORG_KEY, value);
            }
        }

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .user_agent(USER_AGENT)
                .default_headers(headers)
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
    /// * `namespace` - Optional namespace (defaults to "public")
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
    /// let token = client.login("user@example.com", "password", None).await?;
    /// println!("Token: {}", token.token);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login<S: Into<String>>(
        &self,
        username: S,
        password: S,
        namespace: Option<S>,
    ) -> Result<Token> {
        let url = format!("{}{}", self.base_url, ENDPOINT_LOGIN);
        let credentials = LoginCredentials {
            identity: username.into(),
            password: password.into(),
            namespace: namespace
                .map(|n| n.into())
                .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
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
    /// * `namespace` - Optional namespace (defaults to "public")
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
    /// let user = client.register("john_doe", "john@example.com", "password123", None).await?;
    /// println!("User registered: {} ({})", user.username, user.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register<S: Into<String>>(
        &self,
        username: S,
        email: S,
        password: S,
        namespace: Option<S>,
    ) -> Result<User> {
        let url = format!("{}{}", self.base_url, ENDPOINT_REGISTER);
        let registration = UserRegistration {
            username: username.into(),
            email: email.into(),
            password: password.into(),
            namespace: namespace
                .map(|n| n.into())
                .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
        };

        let response = self.client.post(&url).json(&registration).send().await?;

        let register_response: crate::models::RegisterResponse =
            self.handle_response(response).await?;
        Ok(crate::models::User::from(register_response.user))
    }

    /// Sets the authentication token manually.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT authentication token
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// client.set_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...").await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_token<S: Into<String>>(&self, token: S) {
        *self.token.write().await = Some(token.into());
    }

    /// Gets the current authenticated user.
    ///
    /// # Returns
    ///
    /// Returns `Result<User, KeyrunesError>`:
    /// - `Ok(user)` if the user was successfully retrieved
    /// - `Err(KeyrunesError::AuthenticationError)` if not authenticated or token is invalid
    /// - `Err(KeyrunesError::NetworkError)` if there was a network error
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let token = client.login("user@example.com", "password123", None).await?;
    /// let user = client.get_current_user().await?;
    /// println!("Current user: {} ({})", user.username, user.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_current_user(&self) -> Result<User> {
        let token = self.token.read().await;
        let token_value = token.as_ref().ok_or(KeyrunesError::InvalidToken)?;

        let url = format!("{}{}", self.base_url, ENDPOINT_ME);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token_value))
            .send()
            .await?;

        let user_response = self
            .handle_response::<crate::models::UserResponse>(response)
            .await?;
        Ok(crate::models::User::from(user_response))
    }

    /// Registers a new administrator user.
    ///
    /// # Arguments
    ///
    /// * `username` - Username
    /// * `email` - Administrator email
    /// * `password` - Administrator password (minimum 8 characters)
    /// * `admin_key` - Administrator registration key
    /// * `namespace` - Optional namespace (defaults to "public")
    ///
    /// # Returns
    ///
    /// Returns `Result<User, KeyrunesError>`:
    /// - `Ok(user)` if registration was successful
    /// - `Err(KeyrunesError::AuthenticationError)` if admin key is invalid
    /// - `Err(KeyrunesError::HttpError)` if there was an error in the request
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let admin = client.register_admin("admin_user", "admin@example.com", "password123", "admin-key-123", None).await?;
    /// println!("Admin registered: {} ({})", admin.username, admin.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register_admin<S: Into<String>>(
        &self,
        username: S,
        email: S,
        password: S,
        admin_key: S,
        namespace: Option<S>,
    ) -> Result<User> {
        let url = format!("{}{}", self.base_url, ENDPOINT_REGISTER);
        let registration = AdminRegistration {
            username: username.into(),
            email: email.into(),
            password: password.into(),
            admin_key: admin_key.into(),
            namespace: namespace
                .map(|n| n.into())
                .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
        };

        let response = self.client.post(&url).json(&registration).send().await?;

        let register_response: crate::models::RegisterResponse =
            self.handle_response(response).await?;
        Ok(crate::models::User::from(register_response.user))
    }

    /// Gets user information by ID.
    ///
    /// # Arguments
    ///
    /// * `user_id` - User ID
    ///
    /// # Returns
    ///
    /// Returns `Result<User, KeyrunesError>`:
    /// - `Ok(user)` if the user was successfully retrieved
    /// - `Err(KeyrunesError::UserNotFoundError)` if user doesn't exist
    /// - `Err(KeyrunesError::AuthenticationError)` if not authenticated or token is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let token = client.login("user@example.com", "password123", None).await?;
    /// let user = client.get_user("123").await?;
    /// println!("User: {} ({})", user.username, user.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_user<S: Into<String>>(&self, user_id: S) -> Result<User> {
        let token = self.token.read().await;
        let token_value = token.as_ref().ok_or(KeyrunesError::InvalidToken)?;

        let user_id = user_id.into();
        let url = format!("{}/api/users/{}", self.base_url, user_id);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token_value))
            .send()
            .await?;

        let user_response = self
            .handle_response::<crate::models::UserResponse>(response)
            .await?;
        Ok(crate::models::User::from(user_response))
    }

    /// Verifies if a user belongs to a specific group.
    ///
    /// # Arguments
    ///
    /// * `user_id` - User ID
    /// * `group_id` - Group ID
    ///
    /// # Returns
    ///
    /// Returns `Result<bool, KeyrunesError>`:
    /// - `Ok(true)` if user belongs to the group
    /// - `Ok(false)` if user doesn't belong to the group
    /// - `Err(KeyrunesError::GroupNotFoundError)` if group doesn't exist
    /// - `Err(KeyrunesError::AuthenticationError)` if not authenticated
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let token = client.login("user@example.com", "password123", None).await?;
    /// let has_access = client.has_group("123", "admins").await?;
    /// if has_access {
    ///     println!("User has admin access");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn has_group<U: Into<String>, G: Into<String>>(
        &self,
        user_id: U,
        group_id: G,
    ) -> Result<bool> {
        let token = self.token.read().await;
        let token_value = token.as_ref().ok_or(KeyrunesError::InvalidToken)?;

        let user_id = user_id.into();
        let group_id = group_id.into();
        let url = format!(
            "{}/api/users/{}/groups/{}",
            self.base_url, user_id, group_id
        );
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token_value))
            .send()
            .await?;

        let group_check = self.handle_response::<GroupCheck>(response).await?;
        Ok(group_check.has_group)
    }

    /// Gets the list of groups for a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - User ID (optional, if None uses current user)
    ///
    /// # Returns
    ///
    /// Returns `Result<Vec<String>, KeyrunesError>`:
    /// - `Ok(groups)` if the groups were successfully retrieved
    /// - `Err(KeyrunesError::UserNotFoundError)` if user doesn't exist
    /// - `Err(KeyrunesError::AuthenticationError)` if not authenticated
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let token = client.login("user@example.com", "password123", None).await?;
    /// let groups = client.get_user_groups(None::<&str>).await?;
    /// println!("User groups: {:?}", groups);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_user_groups<S: Into<String>>(
        &self,
        user_id: Option<S>,
    ) -> Result<Vec<String>> {
        let user = if let Some(user_id) = user_id {
            self.get_user(user_id).await?
        } else {
            self.get_current_user().await?
        };
        Ok(user.groups)
    }

    /// Clears the authentication token.
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let token = client.login("user@example.com", "password123", None).await?;
    /// client.clear_token().await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn clear_token(&self) {
        *self.token.write().await = None;
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
