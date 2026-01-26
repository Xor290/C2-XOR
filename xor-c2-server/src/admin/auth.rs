use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Duration, Utc};
use actix_web::HttpRequest;
use crate::admin::models::Claims;
use crate::admin::error::{ServerError, ServerResult};
use crate::admin::Database;
use std::env;

pub struct JwtManager {
    secret: String,
    expiration_hours: i64,
}

impl JwtManager {
    pub fn from_env() -> Self {
        let secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "default-insecure-secret-change-me".to_string());

        let expiration_hours = env::var("JWT_EXP_HOURS")
            .unwrap_or_else(|_| "1".to_string())
            .parse()
            .unwrap_or(1);

        JwtManager {
            secret,
            expiration_hours,
        }
    }

    pub fn generate_token(&self, username: &str) -> ServerResult<String> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(self.expiration_hours))
            .ok_or(ServerError::InternalError("Failed to calculate expiration".to_string()))?
            .timestamp() as usize;
        
        let claims = Claims {
            sub: username.to_owned(),
            exp: expiration,
        };
        
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|e| ServerError::InternalError(format!("Token generation failed: {}", e)))
    }

    pub fn extract_token(&self, req: &HttpRequest) -> ServerResult<String> {
        let auth_header = req
            .headers()
            .get("Authorization")
            .ok_or(ServerError::AuthenticationError("No Authorization header".to_string()))?
            .to_str()
            .map_err(|_| ServerError::AuthenticationError("Invalid Authorization header".to_string()))?;
        
        auth_header
            .strip_prefix("Bearer ")
            .ok_or(ServerError::AuthenticationError("Invalid Authorization format".to_string()))
            .map(|s| s.to_string())
    }

    pub fn verify_token(&self, token: &str) -> ServerResult<Claims> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|_| ServerError::AuthenticationError("Invalid or expired token".to_string()))
    }

    pub fn authenticate(&self, req: &HttpRequest, database: &Database) -> ServerResult<Claims> {
        let token = self.extract_token(req)?;
        let claims = self.verify_token(&token)?;
        
        if !database.is_session_valid(&token) {
            return Err(ServerError::AuthenticationError("Session expired or invalid".to_string()));
        }
        
        Ok(claims)
    }

    pub fn get_expiration_datetime(&self) -> String {
        Utc::now()
            .checked_add_signed(Duration::hours(self.expiration_hours))
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }
}
