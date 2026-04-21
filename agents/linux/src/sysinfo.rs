use std::fs;
use std::net::UdpSocket;

pub fn get_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn get_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn get_process_name() -> String {
    fs::read_to_string("/proc/self/comm")
        .unwrap_or_else(|_| "agent".to_string())
        .trim()
        .to_string()
}

/// Returns the local IP used to reach external network (no actual packet sent)
pub fn get_local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}
