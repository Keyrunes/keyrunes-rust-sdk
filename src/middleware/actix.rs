//! Middleware for Actix Web integration

use crate::{KeyrunesClient, User};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, FromRequest, HttpMessage,
};
use std::{
    future::{ready, Ready},
    pin::Pin,
    rc::Rc,
    sync::Arc,
};

/// Keyrunes client state for use in Actix
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

/// Authenticated user data stored in the request
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user: User,
}

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        if let Some(user) = req.extensions().get::<AuthenticatedUser>() {
            return ready(Ok(user.clone()));
        }

        ready(Err(actix_web::error::ErrorUnauthorized(
            "User not authenticated",
        )))
    }
}

/// Middleware for authentication in Actix
pub struct KeyrunesAuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for KeyrunesAuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = KeyrunesAuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(KeyrunesAuthMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

pub struct KeyrunesAuthMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for KeyrunesAuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            if let Some(auth_header) = req.headers().get("authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        if let Some(state) = req.app_data::<actix_web::web::Data<KeyrunesState>>() {
                            state.client.set_token(token.to_string()).await;
                            if let Ok(user) = state.client.get_current_user().await {
                                req.extensions_mut().insert(AuthenticatedUser { user });
                            }
                        }
                    }
                }
            }

            service.call(req).await
        })
    }
}

/// Helper function to verify if the user belongs to a group
pub async fn require_group(
    req: &actix_web::HttpRequest,
    group_id: &str,
) -> Result<AuthenticatedUser, actix_web::Error> {
    let user = AuthenticatedUser::from_request(req, &mut actix_web::dev::Payload::None).await?;

    if let Some(state) = req.app_data::<actix_web::web::Data<KeyrunesState>>() {
        let has_group = state
            .client
            .has_group(&user.user.id, group_id)
            .await
            .map_err(|e| actix_web::error::ErrorForbidden(e.to_string()))?;

        if !has_group {
            return Err(actix_web::error::ErrorForbidden(format!(
                "User does not belong to group: {}",
                group_id
            )));
        }
    }

    Ok(user)
}

/// Helper function to verify if the user is an administrator
pub async fn require_admin(
    req: &actix_web::HttpRequest,
) -> Result<AuthenticatedUser, actix_web::Error> {
    require_group(req, "admins").await
}
