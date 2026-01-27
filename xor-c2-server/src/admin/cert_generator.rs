use rcgen::generate_simple_self_signed;

pub struct GeneratedCertificate {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_self_signed_cert(
    subject_alt_names: Vec<String>,
) -> Result<GeneratedCertificate, String> {
    // Generate self-signed certificate with the given SANs
    let cert = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| format!("Failed to generate certificate: {}", e))?;

    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| format!("Failed to serialize certificate: {}", e))?;

    let key_pem = cert.serialize_private_key_pem();

    Ok(GeneratedCertificate { cert_pem, key_pem })
}

pub fn generate_cert_for_listener(
    listener_name: &str,
    listener_ip: &str,
) -> Result<GeneratedCertificate, String> {
    let common_name = format!("{}.xor-c2.local", listener_name);

    let mut subject_alt_names = vec![
        common_name,
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];

    // Add the listener IP if it's not already included
    if listener_ip != "127.0.0.1" && listener_ip != "0.0.0.0" && listener_ip != "localhost" {
        subject_alt_names.push(listener_ip.to_string());
    }

    generate_self_signed_cert(subject_alt_names)
}
