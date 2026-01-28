use crate::models::{GenerateListenerDialog, ListenerConfig};

pub async fn add_listener(
    server_url: &str,
    token: &str,
    config: &GenerateListenerDialog,
) -> Result<String, String> {
    let url = format!("{}/api/add/listener", server_url);
    let client = reqwest::Client::new();

    let listener_config = ListenerConfig {
        listener_name: config.listener_name.clone(),
        listener_type: config.listener_type.clone(),
        listener_ip: config.listener_ip.clone(),
        listener_port: config.listener_port,
        xor_key: config.xor_key.clone(),
        user_agent: config.user_agent.clone(),
        uri_paths: config.uri_paths.clone(),
        headers: config.headers.clone(),
        tls_cert: String::new(),
        tls_key: String::new(),
        tls_cert_chain: String::new(),
    };

    let response = client
        .post(&url)
        .bearer_auth(token)
        .json(&listener_config)
        .send()
        .await
        .map_err(|e| format!("HTTP request error: {}", e))?;

    let status = response.status();

    let response_text = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let api_response: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse API response: {}", e))?;

    if status != 200 {
        return Err(format!(
            "API error (status {}): {}",
            status,
            api_response["message"].as_str().unwrap_or("Unknown error")
        ));
    }

    Ok(api_response["message"]
        .as_str()
        .unwrap_or("Listener added successfully")
        .to_string())
}
