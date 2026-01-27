use actix_web::{error::ResponseError, HttpResponse};
use std::fmt;

#[derive(Debug)]
pub enum ServerError {
    DatabaseError(String),
    AuthenticationError(String),
    ValidationError(String),
    InternalError(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServerError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            ServerError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            ServerError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            ServerError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServerError::DatabaseError(_) => HttpResponse::InternalServerError()
                .json(serde_json::json!({"success": false, "message": self.to_string()})),
            ServerError::AuthenticationError(_) => HttpResponse::Unauthorized()
                .json(serde_json::json!({"success": false, "message": self.to_string()})),
            ServerError::ValidationError(_) => HttpResponse::BadRequest()
                .json(serde_json::json!({"success": false, "message": self.to_string()})),
            ServerError::InternalError(_) => HttpResponse::InternalServerError()
                .json(serde_json::json!({"success": false, "message": self.to_string()})),
        }
    }
}

pub type ServerResult<T> = Result<T, ServerError>;
