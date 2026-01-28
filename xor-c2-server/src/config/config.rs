use serde::{Deserialize, Serialize};
use std::fs;
use std::io;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_port: u16,
    pub bind_address: String,
    pub agent_timeout: u64,
}

impl Config {
    pub fn load(path: &str) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    pub fn get_server_port(&self) -> u16 {
        self.server_port
    }

    pub fn get_bind_address(&self) -> &str {
        &self.bind_address
    }

    pub fn get_agent_timeout(&self) -> u64 {
        self.agent_timeout
    }
}
