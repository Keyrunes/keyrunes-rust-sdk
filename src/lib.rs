//! # Keyrunes Rust SDK
//!
//! Rust library for integrating with the Keyrunes authentication and authorization service.
//!
//! ## Quick Start
//!
//! ```
//! use keyrunes_rust_sdk::KeyrunesClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = KeyrunesClient::new("https://keyrunes.example.com")?;
//! let user = client.register("john", "john@example.com", "password123").await?;
//! let token = client.login("john", "password123").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Modules
//!
//! - [`client`] - Main client for interacting with the Keyrunes API
//! - [`error`] - Error types for the library
//! - [`models`] - Data models for serialization/deserialization

pub mod client;
pub mod error;
pub mod models;

#[cfg(any(feature = "axum", feature = "actix", feature = "rocket"))]
pub mod middleware;

pub use client::KeyrunesClient;
pub use error::{KeyrunesError, Result};
pub use models::*;
