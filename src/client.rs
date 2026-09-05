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
const USER_AGENT: &str = "keyrunes-rust-sdk/0.2.0";
const HEADER_ORG_KEY: &str = "X-Organization-Key";
const ENV_ORG_KEY: &str = "KEYRUNES_ORG_KEY";

const ENDPOINT_LOGIN: &str = "/api/login";
const ENDPOINT_REGISTER: &str = "/api/register";
const ENDPOINT_ME: &str = "/api/me";

// New constants start here
const ENDPOINT_FORGOT_PASSWORD: &str = "/api/forgot-password";
const ENDPOINT_RESET_PASSWORD: &str = "/api/reset-password";
const ENDPOINT_CHANGE_PASSWORD: &str = "/api/user/change-password";

/// How many bytes of an unparseable error body are echoed back to the caller.
const ERROR_BODY_PREVIEW_BYTES: usize = 200;

/// Truncates `input` to at most `max_bytes`, moving left to the nearest UTF-8
/// character boundary.
///
/// Slicing a `str` at an arbitrary byte index panics when the index lands
/// inside a multi-byte character, which a plain-text error body from an
/// upstream proxy can easily trigger.
fn truncate_on_char_boundary(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    // Byte 0 is always a boundary, so the search always lands somewhere; the
    // fallback is there to satisfy the type, not to handle a real case.
    let end = (0..=max_bytes)
        .rev()
        .find(|&index| input.is_char_boundary(index))
        .unwrap_or(0);
    &input[..end]
}
// New constants end here

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
///
/// URLs with trailing slashes are normalized:
///
/// ```
/// use keyrunes_rust_sdk::KeyrunesClient;
///
/// let client = KeyrunesClient::new("https://keyrunes.example.com/")
///     .expect("Invalid URL");
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

    /// Returns the normalized base URL this client targets.
    ///
    /// The value has every trailing slash stripped, so it can be concatenated
    /// with an endpoint path that starts with `/` without producing a double
    /// slash.
    ///
    /// # Examples
    ///
    /// ```
    /// use keyrunes_rust_sdk::KeyrunesClient;
    ///
    /// let client = KeyrunesClient::new("https://keyrunes.example.com///")?;
    /// assert_eq!(client.base_url(), "https://keyrunes.example.com");
    /// # Ok::<(), keyrunes_rust_sdk::KeyrunesError>(())
    /// ```
    pub fn base_url(&self) -> &str {
        &self.base_url
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
    /// The server responds `201 Created` with the new user's flat
    /// `UserResponse` JSON (no wrapper object).
    ///
    /// # Arguments
    ///
    /// * `username` - Username
    /// * `email` - User email
    /// * `password` - User password (minimum 8 characters)
    /// * `namespace` - Optional namespace (defaults to [`DEFAULT_NAMESPACE`], "public")
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

        let user_response = self
            .handle_response::<crate::models::UserResponse>(response)
            .await?;
        Ok(crate::models::User::from(user_response))
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

        let user_response = self
            .handle_response::<crate::models::UserResponse>(response)
            .await?;
        Ok(crate::models::User::from(user_response))
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
    /// # Deprecated
    ///
    /// The server no longer exposes `GET /api/users/{uid}/groups/{gid}`;
    /// every call fails with 404. Use [`KeyrunesClient::current_user_has_group`]
    /// instead, which checks group membership BY NAME via `GET /api/me`.
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
    #[deprecated(note = "rota removida no servidor")]
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

    /// Verifies if the CURRENT authenticated user belongs to a group, by name.
    ///
    /// Fetches `GET /api/me` and checks whether the returned `groups`
    /// (a list of group NAMES) contains `group_name`.
    ///
    /// # Arguments
    ///
    /// * `group_name` - Group name (e.g. "admins", "monitor")
    ///
    /// # Returns
    ///
    /// Returns `Result<bool, KeyrunesError>`:
    /// - `Ok(true)` if the current user belongs to the named group
    /// - `Ok(false)` if the current user does not belong to it
    /// - `Err(KeyrunesError::InvalidToken)` if no token is set
    /// - `Err(KeyrunesError::AuthenticationError)` if not authenticated
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let token = client.login("user@example.com", "password123", None).await?;
    /// let has_access = client.current_user_has_group("admins").await?;
    /// if has_access {
    /// #     println!("User has admin access");
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn current_user_has_group(&self, group_name: &str) -> Result<bool> {
        let user = self.get_current_user().await?;
        Ok(user.groups.iter().any(|g| g == group_name))
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

    // New methods start here

    /// Requests a password reset email.
    ///
    /// # Arguments
    ///
    /// * `email` - User email address
    /// * `namespace` - Optional namespace (defaults to "public")
    ///
    /// # Returns
    ///
    /// Returns `Result<ForgotPasswordResponse, KeyrunesError>`:
    /// - `Ok(response)` if the request was successful
    /// - `Err(KeyrunesError::HttpError)` if the server returned an error
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let response = client.forgot_password("user@example.com", None).await?;
    /// println!("Reset URL: {}", response.reset_url);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn forgot_password<S: Into<String>>(
        &self,
        email: S,
        namespace: Option<S>,
    ) -> Result<ForgotPasswordResponse> {
        let url = format!("{}{}", self.base_url, ENDPOINT_FORGOT_PASSWORD);
        let request = ForgotPasswordRequest {
            email: email.into(),
            namespace: namespace
                .map(|n| n.into())
                .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
        };
        let response = self.client.post(&url).json(&request).send().await?;
        self.handle_response::<ForgotPasswordResponse>(response)
            .await
    }

    /// Resets a password using a token received via email.
    ///
    /// # Arguments
    ///
    /// * `token` - Password reset token from email
    /// * `new_password` - New password to set
    /// * `namespace` - Optional namespace (defaults to "public")
    ///
    /// # Returns
    ///
    /// Returns `Result<MessageResponse, KeyrunesError>`:
    /// - `Ok(response)` if password was reset successfully
    /// - `Err(KeyrunesError::HttpError)` if the token is invalid or expired
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// let response = client.reset_password("reset-token-123", "newPassword456", None).await?;
    /// println!("Message: {}", response.message);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn reset_password<S: Into<String>>(
        &self,
        token: S,
        new_password: S,
        namespace: Option<S>,
    ) -> Result<MessageResponse> {
        let url = format!("{}{}", self.base_url, ENDPOINT_RESET_PASSWORD);
        let request = ResetPasswordRequest {
            token: token.into(),
            new_password: new_password.into(),
            namespace: namespace
                .map(|n| n.into())
                .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
        };
        let response = self.client.post(&url).json(&request).send().await?;
        self.handle_response::<MessageResponse>(response).await
    }

    /// Changes the password of the currently authenticated user.
    ///
    /// # Arguments
    ///
    /// * `current_password` - User's current password
    /// * `new_password` - New password to set
    ///
    /// # Returns
    ///
    /// Returns `Result<MessageResponse, KeyrunesError>`:
    /// - `Ok(response)` if password was changed successfully
    /// - `Err(KeyrunesError::InvalidToken)` if no token is set
    /// - `Err(KeyrunesError::AuthenticationError)` if current password is wrong
    /// - `Err(KeyrunesError::HttpError)` for other errors
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// client.set_token("user-token").await;
    /// let response = client.change_password("oldPass123", "newPass456").await?;
    /// println!("Message: {}", response.message);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn change_password<S: Into<String>>(
        &self,
        current_password: S,
        new_password: S,
    ) -> Result<MessageResponse> {
        let token = self.token.read().await;
        let token_value = token.as_ref().ok_or(KeyrunesError::InvalidToken)?;

        let url = format!("{}{}", self.base_url, ENDPOINT_CHANGE_PASSWORD);
        let request = ChangePasswordRequest {
            current_password: current_password.into(),
            new_password: new_password.into(),
        };
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token_value))
            .json(&request)
            .send()
            .await?;
        self.handle_response::<MessageResponse>(response).await
    }

    /// Admin-only: Resets a user's password and returns a temporary password.
    ///
    /// # Arguments
    ///
    /// * `user_id` - ID of the user to reset password for
    ///
    /// # Returns
    ///
    /// Returns `Result<PasswordResetResponse, KeyrunesError>`:
    /// - `Ok(response)` if password was reset successfully
    /// - `Err(KeyrunesError::InvalidToken)` if no token is set
    /// - `Err(KeyrunesError::AuthorizationError)` if user is not an admin
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// client.set_token("admin-token").await;
    /// let response = client.admin_reset_user_password("123").await?;
    /// println!("Temporary password: {}", response.temporary_password);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn admin_reset_user_password<S: Into<String>>(
        &self,
        user_id: S,
    ) -> Result<PasswordResetResponse> {
        let token = self.token.read().await;
        let token_value = token.as_ref().ok_or(KeyrunesError::InvalidToken)?;

        let user_id = user_id.into();
        let url = format!(
            "{}/api/admin/users/{}/reset-password",
            self.base_url, user_id
        );
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token_value))
            .send()
            .await?;
        self.handle_response::<PasswordResetResponse>(response)
            .await
    }

    /// Admin-only: Sends a password reset email to a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - ID of the user to send reset email to
    ///
    /// # Returns
    ///
    /// Returns `Result<MessageResponse, KeyrunesError>`:
    /// - `Ok(response)` if reset email was sent successfully
    /// - `Err(KeyrunesError::InvalidToken)` if no token is set
    /// - `Err(KeyrunesError::AuthorizationError)` if user is not an admin
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyrunes_rust_sdk::KeyrunesClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = KeyrunesClient::new("https://keyrunes.example.com")?;
    /// client.set_token("admin-token").await;
    /// let response = client.admin_send_password_reset("123").await?;
    /// println!("Message: {}", response.message);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn admin_send_password_reset<S: Into<String>>(
        &self,
        user_id: S,
    ) -> Result<MessageResponse> {
        let token = self.token.read().await;
        let token_value = token.as_ref().ok_or(KeyrunesError::InvalidToken)?;

        let user_id = user_id.into();
        let url = format!("{}/api/admin/users/{}/send-reset", self.base_url, user_id);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token_value))
            .send()
            .await?;
        self.handle_response::<MessageResponse>(response).await
    }
    // New methods end here

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
            Err(classify_error(status, &body, &url))
        }
    }
}

/// Extracts the human-readable detail an error body carries.
///
/// A JSON body is asked for `message`, then `error`; anything else — a plain
/// sentence from a proxy, an empty body — is passed through, cut to
/// [`ERROR_BODY_PREVIEW_BYTES`] so an upstream error page cannot end up whole
/// inside an error value.
fn error_detail(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .map(|v| {
            v.get("message")
                .or_else(|| v.get("error"))
                .and_then(|m| m.as_str())
                .unwrap_or(body)
                .to_string()
        })
        .unwrap_or_else(|_| {
            if body.len() > ERROR_BODY_PREVIEW_BYTES {
                format!(
                    "{}...",
                    truncate_on_char_boundary(body, ERROR_BODY_PREVIEW_BYTES)
                )
            } else {
                body.to_string()
            }
        })
}

/// Maps an unsuccessful response onto the error variant the caller sees.
///
/// A free function rather than a method: a `reqwest::Response` cannot be built
/// with an arbitrary status and body from a test, so calling this directly is
/// the only way to enumerate the classification.
pub(crate) fn classify_error(
    status: reqwest::StatusCode,
    body: &str,
    url: &url::Url,
) -> KeyrunesError {
    // An HTML body is a proxy or a router answering, not the API. Its content
    // describes a web page, not the resource that was asked for, so nothing in
    // it is allowed to reach the classification below.
    let (detail, error_message) = if body.trim_start().starts_with('<') {
        (
            String::new(),
            format!("HTTP {} - Received HTML response (endpoint may not exist or path is incorrect). Tried: {}", status.as_u16(), url),
        )
    } else {
        let detail = error_detail(body);
        let error_message = format!("{} (URL: {})", detail, url);
        (detail, error_message)
    };

    match status {
        reqwest::StatusCode::UNAUTHORIZED => KeyrunesError::AuthenticationError(error_message),
        reqwest::StatusCode::FORBIDDEN => KeyrunesError::AuthorizationError(error_message),
        reqwest::StatusCode::NOT_FOUND => {
            // Only the server's own words decide which resource was missing.
            // The URL is appended for the caller's benefit and must not steer
            // the classification: `/api/user/change-password` answering 404
            // means the route is absent, not that a user was not found.
            if detail.contains("user") || detail.contains("User") {
                KeyrunesError::UserNotFoundError(error_message)
            } else if detail.contains("group") || detail.contains("Group") {
                KeyrunesError::GroupNotFoundError(error_message)
            } else {
                KeyrunesError::Other(format!("Resource not found: {}", error_message))
            }
        }
        _ => KeyrunesError::HttpError(format!("HTTP {}: {}", status.as_u16(), error_message)),
    }
}

#[cfg(test)]
mod tests {
    use super::{truncate_on_char_boundary, ERROR_BODY_PREVIEW_BYTES};

    #[test]
    fn short_input_is_returned_untouched() {
        assert_eq!(truncate_on_char_boundary("abc", 10), "abc");
    }

    #[test]
    fn input_exactly_at_the_limit_is_returned_untouched() {
        let input = "a".repeat(10);
        assert_eq!(truncate_on_char_boundary(&input, 10), input);
    }

    #[test]
    fn ascii_input_is_cut_exactly_at_the_limit() {
        let input = "a".repeat(50);
        assert_eq!(truncate_on_char_boundary(&input, 10).len(), 10);
    }

    #[test]
    fn a_cut_inside_a_multibyte_character_moves_left() {
        // "€" is three bytes, so a limit of 4 lands inside the second one.
        let input = "€€€";
        let truncated = truncate_on_char_boundary(input, 4);
        assert_eq!(truncated, "€");
        assert_eq!(truncated.len(), 3);
    }

    #[test]
    fn a_cut_landing_on_a_boundary_keeps_the_whole_character() {
        let input = "€€€";
        assert_eq!(truncate_on_char_boundary(input, 6), "€€");
    }

    #[test]
    fn a_limit_shorter_than_the_first_character_yields_an_empty_string() {
        assert_eq!(truncate_on_char_boundary("€", 2), "");
    }

    #[test]
    fn a_zero_limit_yields_an_empty_string() {
        assert_eq!(truncate_on_char_boundary("abc", 0), "");
    }

    #[test]
    fn the_preview_limit_never_splits_a_character() {
        // The exact shape that used to panic: 198 ASCII bytes followed by a
        // three-byte character spanning bytes 198..201.
        let input = format!("{}{}", "a".repeat(198), "€".repeat(5));
        let truncated = truncate_on_char_boundary(&input, ERROR_BODY_PREVIEW_BYTES);
        assert_eq!(truncated.len(), 198);
        assert!(input.starts_with(truncated));
    }
}

/// Exhaustive enumeration of the error-classification space.
///
/// `classify_error` decides which `KeyrunesError` variant a caller matches on,
/// from three inputs that interact: the status, the shape of the body, and the
/// words inside it. Sampled tests pick a few plausible bodies; the cases that
/// actually break the classifier are the ones nobody thinks to write down — a
/// body that is valid JSON but not an object, an HTML page whose text happens
/// to say "user", a plain body sitting exactly on the preview limit. Every
/// combination is walked instead.
#[cfg(test)]
mod exhaustive_error_classification {
    use super::{classify_error, error_detail, ERROR_BODY_PREVIEW_BYTES};
    use crate::error::KeyrunesError;
    use exhaustive::{exhaustive_test, Exhaustive};
    use reqwest::StatusCode;

    /// A URL containing none of the words the 404 branch looks for, so the
    /// classification can only come from the body.
    const NEUTRAL_URL: &str = "https://keyrunes.example.com/api/thing";

    fn neutral_url() -> url::Url {
        url::Url::parse(NEUTRAL_URL).expect("the fixture URL must parse")
    }

    /// A status the API is capable of returning.
    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum Status {
        Unauthorized,
        Forbidden,
        NotFound,
        BadRequest,
        Conflict,
        Unprocessable,
        ServerError,
    }

    impl Status {
        fn code(self) -> StatusCode {
            match self {
                Status::Unauthorized => StatusCode::UNAUTHORIZED,
                Status::Forbidden => StatusCode::FORBIDDEN,
                Status::NotFound => StatusCode::NOT_FOUND,
                Status::BadRequest => StatusCode::BAD_REQUEST,
                Status::Conflict => StatusCode::CONFLICT,
                Status::Unprocessable => StatusCode::UNPROCESSABLE_ENTITY,
                Status::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    /// What the error body says the missing resource was.
    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum Subject {
        /// Names neither a user nor a group.
        Silent,
        LowercaseUser,
        CapitalisedUser,
        LowercaseGroup,
        CapitalisedGroup,
        /// Names both; the user branch is tried first.
        UserAndGroup,
    }

    impl Subject {
        fn phrase(self) -> &'static str {
            match self {
                Subject::Silent => "nothing matched the request",
                Subject::LowercaseUser => "user not found",
                Subject::CapitalisedUser => "User not found",
                Subject::LowercaseGroup => "group not found",
                Subject::CapitalisedGroup => "Group not found",
                Subject::UserAndGroup => "user is not in group",
            }
        }

        fn names_a_user(self) -> bool {
            matches!(
                self,
                Subject::LowercaseUser | Subject::CapitalisedUser | Subject::UserAndGroup
            )
        }

        fn names_a_group(self) -> bool {
            matches!(
                self,
                Subject::LowercaseGroup | Subject::CapitalisedGroup | Subject::UserAndGroup
            )
        }
    }

    /// The form an error body arrives in.
    #[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
    enum BodyShape {
        Empty,
        Html,
        /// An HTML page behind leading whitespace, which `trim_start` removes.
        HtmlAfterWhitespace,
        JsonMessage,
        JsonError,
        /// Both keys present; `message` is the one that counts.
        JsonMessageAndError,
        /// A JSON object carrying neither key.
        JsonWithoutEitherKey,
        /// Valid JSON that is not an object, so `get` never finds anything.
        JsonNotAnObject,
        Plain,
        /// Plain text of exactly [`ERROR_BODY_PREVIEW_BYTES`], the boundary
        /// the preview rule turns on.
        PlainExactlyAtLimit,
        PlainOverLimit,
        /// Over the limit, with a multi-byte character straddling the cut.
        PlainOverLimitMultibyte,
    }

    impl BodyShape {
        /// The subject phrase always leads, so truncation can never remove it
        /// and the expected classification stays a property of the input.
        fn body(self, subject: Subject) -> String {
            let phrase = subject.phrase();
            match self {
                BodyShape::Empty => String::new(),
                BodyShape::Html => format!("<html><body>{phrase}</body></html>"),
                BodyShape::HtmlAfterWhitespace => format!("\n\t  <html>{phrase}</html>"),
                BodyShape::JsonMessage => format!(r#"{{"message":"{phrase}"}}"#),
                BodyShape::JsonError => format!(r#"{{"error":"{phrase}"}}"#),
                BodyShape::JsonMessageAndError => {
                    format!(r#"{{"message":"{phrase}","error":"secondary detail"}}"#)
                }
                BodyShape::JsonWithoutEitherKey => format!(r#"{{"detail":"{phrase}"}}"#),
                BodyShape::JsonNotAnObject => format!(r#""{phrase}""#),
                BodyShape::Plain => phrase.to_string(),
                BodyShape::PlainExactlyAtLimit => {
                    let mut body = phrase.to_string();
                    while body.len() < ERROR_BODY_PREVIEW_BYTES {
                        body.push('x');
                    }
                    body.truncate(ERROR_BODY_PREVIEW_BYTES);
                    body
                }
                BodyShape::PlainOverLimit => {
                    format!("{phrase} {}", "x".repeat(ERROR_BODY_PREVIEW_BYTES))
                }
                BodyShape::PlainOverLimitMultibyte => {
                    format!("{phrase} {}", "€".repeat(ERROR_BODY_PREVIEW_BYTES))
                }
            }
        }

        /// Whether the subject phrase survives into the detail the 404 branch
        /// reads. An empty body has nothing to say, and an HTML body is
        /// discarded wholesale.
        fn carries_the_subject(self) -> bool {
            !matches!(
                self,
                BodyShape::Empty | BodyShape::Html | BodyShape::HtmlAfterWhitespace
            )
        }
    }

    /// The variant a caller would match on, as a name, so a failure says which
    /// one was produced instead of `false`.
    fn variant_name(error: &KeyrunesError) -> &'static str {
        match error {
            KeyrunesError::AuthenticationError(_) => "AuthenticationError",
            KeyrunesError::AuthorizationError(_) => "AuthorizationError",
            KeyrunesError::GroupNotFoundError(_) => "GroupNotFoundError",
            KeyrunesError::UserNotFoundError(_) => "UserNotFoundError",
            KeyrunesError::NetworkError(_) => "NetworkError",
            KeyrunesError::SerializationError(_) => "SerializationError",
            KeyrunesError::HttpError(_) => "HttpError",
            KeyrunesError::InvalidUrl(_) => "InvalidUrl",
            KeyrunesError::InvalidToken => "InvalidToken",
            KeyrunesError::Other(_) => "Other",
        }
    }

    /// 7 x 12 x 6 = 504 combinations.
    ///
    /// Outside 404 the status alone decides the variant: no body, however
    /// shaped or worded, may redirect a 401 or a 500 somewhere else.
    #[exhaustive_test]
    fn the_status_alone_decides_every_variant_but_404(
        status: Status,
        shape: BodyShape,
        subject: Subject,
    ) {
        if status == Status::NotFound {
            return; // has a rule of its own, enumerated below
        }

        let body = shape.body(subject);
        let error = classify_error(status.code(), &body, &neutral_url());

        let expected = match status {
            Status::Unauthorized => "AuthenticationError",
            Status::Forbidden => "AuthorizationError",
            _ => "HttpError",
        };

        assert_eq!(
            variant_name(&error),
            expected,
            "{status:?} with {shape:?}/{subject:?}"
        );
    }

    /// 12 x 6 = 72 combinations.
    ///
    /// A 404 is the one status whose variant depends on the body, and the rule
    /// is: a user beats a group, and naming neither leaves the error generic.
    #[exhaustive_test]
    fn a_404_names_whichever_resource_the_body_named(shape: BodyShape, subject: Subject) {
        let body = shape.body(subject);
        let error = classify_error(StatusCode::NOT_FOUND, &body, &neutral_url());

        let names_a_user = shape.carries_the_subject() && subject.names_a_user();
        let names_a_group = shape.carries_the_subject() && subject.names_a_group();

        let expected = if names_a_user {
            "UserNotFoundError"
        } else if names_a_group {
            "GroupNotFoundError"
        } else {
            "Other"
        };

        assert_eq!(variant_name(&error), expected, "body {body:?}");
    }

    /// 7 x 12 x 6 = 504 combinations.
    ///
    /// Whatever went wrong, the caller is told which URL produced it — the one
    /// piece of context a log line cannot reconstruct.
    #[exhaustive_test]
    fn the_url_always_reaches_the_caller(status: Status, shape: BodyShape, subject: Subject) {
        let body = shape.body(subject);
        let error = classify_error(status.code(), &body, &neutral_url());

        assert!(
            error.to_string().contains(NEUTRAL_URL),
            "{status:?} with {shape:?}/{subject:?} hid the URL: {error}"
        );
    }

    /// 12 x 6 = 72 combinations.
    ///
    /// A body that is not JSON is echoed to the caller, so it must be cut: an
    /// upstream proxy can answer with a whole HTML page, and the preview is
    /// what stops it from being carried around inside an error value.
    #[exhaustive_test]
    fn a_non_json_body_is_previewed_rather_than_echoed(shape: BodyShape, subject: Subject) {
        let body = shape.body(subject);
        if serde_json::from_str::<serde_json::Value>(&body).is_ok() {
            return; // the JSON path has no length rule
        }

        let detail = error_detail(&body);

        if body.len() <= ERROR_BODY_PREVIEW_BYTES {
            assert_eq!(detail, body, "a body within the limit must pass through");
        } else {
            let preview = detail
                .strip_suffix("...")
                .unwrap_or_else(|| panic!("a cut body must be marked as cut, got {detail:?}"));
            assert!(
                preview.len() <= ERROR_BODY_PREVIEW_BYTES,
                "preview of {} bytes exceeds the limit",
                preview.len()
            );
            assert!(
                body.starts_with(preview),
                "the preview must be a prefix of the body"
            );
        }
    }

    /// 12 x 6 = 72 combinations.
    ///
    /// The classifier is handed bytes off the wire; no combination of them may
    /// panic, which is how the UTF-8 truncation bug reached a release.
    #[exhaustive_test]
    fn no_body_shape_can_panic(shape: BodyShape, subject: Subject) {
        let body = shape.body(subject);
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let _ = classify_error(status, &body, &neutral_url());
        }
    }

    /// `message` outranks `error` when a server sends both, even when they
    /// disagree about what was missing.
    #[test]
    fn the_message_key_outranks_the_error_key() {
        let body = r#"{"message":"group not found","error":"user not found"}"#;
        let error = classify_error(StatusCode::NOT_FOUND, body, &neutral_url());
        assert_eq!(variant_name(&error), "GroupNotFoundError");
    }

    /// The URL is shown to the caller but must not classify the failure: every
    /// password endpoint this SDK calls sits under `/api/user/...`, and a
    /// missing route there is not a missing user.
    #[test]
    fn the_url_does_not_decide_which_resource_was_missing() {
        let url = url::Url::parse("https://keyrunes.example.com/api/user/change-password").unwrap();
        let error = classify_error(StatusCode::NOT_FOUND, "", &url);
        assert_eq!(variant_name(&error), "Other");
    }

    /// An HTML page is a proxy talking, not the API: its wording is not
    /// evidence about the resource, however suggestive.
    #[test]
    fn html_wording_does_not_decide_which_resource_was_missing() {
        let body = "<html><body>user not found</body></html>";
        let error = classify_error(StatusCode::NOT_FOUND, body, &neutral_url());
        assert_eq!(variant_name(&error), "Other");
        assert!(error.to_string().contains("Received HTML response"));
    }

    /// The status code reaches the caller as a number, not only as a variant.
    #[test]
    fn an_unmapped_status_carries_its_code() {
        let error = classify_error(StatusCode::IM_A_TEAPOT, "brewing", &neutral_url());
        assert!(error.to_string().contains("418"), "{error}");
    }
}
