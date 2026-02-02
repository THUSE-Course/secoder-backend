use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use std::time::SystemTimeError;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    #[allow(dead_code)]
    Conflict(String),
    Server(anyhow::Error),
}

fn format_error(err: &anyhow::Error) -> String {
    let mut message = String::new();
    for (idx, cause) in err.chain().enumerate() {
        if idx > 0 {
            message.push_str(": ");
        }
        message.push_str(&cause.to_string());
    }
    message.to_lowercase()
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized(message.into())
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Server(anyhow::anyhow!(message.into()))
    }
}

#[derive(Serialize)]
pub struct AppErrorResponse {
    msg: String,
    ver: &'static str,
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self::Server(value)
    }
}

impl From<sea_orm::DbErr> for AppError {
    fn from(value: sea_orm::DbErr) -> Self {
        Self::Server(anyhow::Error::new(value))
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        Self::Server(anyhow::Error::new(value))
    }
}

impl From<axum::http::header::ToStrError> for AppError {
    fn from(value: axum::http::header::ToStrError) -> Self {
        Self::Server(anyhow::Error::new(value))
    }
}

impl From<SystemTimeError> for AppError {
    fn from(value: SystemTimeError) -> Self {
        Self::Server(anyhow::Error::new(value))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            Self::Server(err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format_error(&err))
            }
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg),
        };
        (
            status,
            Json(AppErrorResponse {
                msg: message,
                ver: env!("CARGO_PKG_VERSION"),
            }),
        )
            .into_response()
    }
}
