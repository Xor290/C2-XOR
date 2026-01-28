use crate::models::{ApiResponse, TaskCommand};
use std::time::Duration;

pub async fn send_command(
    server_url: &str,
    token: &str,
    agent_id: &str,
    command: &str,
) -> Result<(), String> {
    let url = format!("{}/api/task", server_url);
    let payload = TaskCommand {
        agent_id: agent_id.to_string(),
        command: command.to_string(),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&payload)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("Send command error: {}", e))?;

    let api_response: ApiResponse = response
        .json()
        .await
        .map_err(|e| format!("Parse response error: {}", e))?;

    if api_response.success {
        Ok(())
    } else {
        Err(api_response.message)
    }
}
