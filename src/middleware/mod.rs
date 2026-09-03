//! Middlewares for web framework integration

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix")]
pub mod actix;

#[cfg(feature = "rocket")]
pub mod rocket;

pub mod loco;
