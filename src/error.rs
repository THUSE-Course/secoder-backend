use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Debug)]
pub struct AppError {
    err: anyhow::Error,
    code: StatusCode,
}

impl AppError {
    pub fn adhoc(code: StatusCode, err: impl Into<anyhow::Error>) -> Self {
        Self {
            code,
            err: err.into(),
        }
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(value: E) -> Self {
        Self {
            err: value.into(),
            code: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Serialize)]
pub struct AppErrorResponse {
    msg: String,
    ver: &'static str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (
            self.code,
            Json(AppErrorResponse {
                msg: self.err.to_string(),
                ver: env!("CARGO_PKG_VERSION"),
            }),
        )
            .into_response()
    }
}
