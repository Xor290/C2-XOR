use crate::models::{LoginRequest, LoginResponse};
use std::time::Duration;

pub async fn login(server_url: &str, username: &str, password: &str) -> Result<String, String> {
    let url = format!("{}/api/login", server_url);
    let payload = LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&payload)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Connection error: {}", e))?;

    let login_response: LoginResponse = response
        .json()
        .await
        .map_err(|e| format!("Parse error: {}", e))?;

    if login_response.success {
        login_response
            .token
            .ok_or_else(|| "No token received".to_string())
    } else {
        Err(login_response.message)
    }
}

pub async fn logout(server_url: &str, token: &str) -> Result<(), String> {
    let url = format!("{}/api/logout", server_url);
    let client = reqwest::Client::new();

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Logout error: {}", e))?;

    Ok(())
}
