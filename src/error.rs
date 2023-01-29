use axum::{
    response::{IntoResponse, Response},
    Json,
};
use reqwest::StatusCode;
use serde::Serialize;

pub enum AppError {
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InternalError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
        };

        #[derive(Serialize)]
        struct Failure {
            error: String,
        }
        let body = Json(Failure {
            error: error_message,
        });

        (status, body).into_response()
    }
}
