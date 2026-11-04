use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::ClientConnection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{SubjectAltName, name::GeneralName};

pub fn inspect(connection: &ClientConnection, verified: bool) -> Value
{
    let certificates: Vec<_> = connection
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|der| certificate_info(der.as_ref()))
        .collect();
    json!({
        "protocol_version": connection.protocol_version().map(|version| format!("{version:?}")),
        "cipher_suite": connection.negotiated_cipher_suite().map(|suite| format!("{:?}", suite.suite())),
        "verification": if verified { "verified" } else { "skipped" },
        "certificates": certificates,
    })
}

fn certificate_info(der: &[u8]) -> Value
{
    let fingerprint = Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let mut info = json!({"sha256_fingerprint": fingerprint, "parse_error": null});
    let certificate = match Certificate::from_der(der)
    {
        Ok(certificate) => certificate,
        Err(err) =>
        {
            info["parse_error"] = json!(err.to_string());
            return info;
        }
    };
    let tbs = certificate.tbs_certificate();
    info["subject"] = json!(tbs.subject().to_string());
    info["issuer"] = json!(tbs.issuer().to_string());
    info["serial_number"] = json!(tbs.serial_number().to_string());
    info["not_before"] = json!(tbs.validity().not_before.to_string());
    info["not_after"] = json!(tbs.validity().not_after.to_string());
    let before = tbs.validity().not_before.to_unix_duration().as_secs();
    let after = tbs.validity().not_after.to_unix_duration().as_secs();
    info["not_before_unix"] = json!(before);
    info["not_after_unix"] = json!(after);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    info["expired"] = json!(now > after);
    info["not_yet_valid"] = json!(now < before);
    let names = match tbs.get_extension::<SubjectAltName>()
    {
        Ok(Some((_, names))) => names.0.into_iter().map(name_info).collect::<Vec<_>>(),
        Ok(None) => Vec::new(),
        Err(err) =>
        {
            info["parse_error"] = json!(err.to_string());
            Vec::new()
        }
    };
    info["subject_alt_names"] = json!(names);
    info
}

fn name_info(name: GeneralName) -> Value
{
    match name
    {
        GeneralName::DnsName(value) => json!({"type": "DNS", "value": value.as_str()}),
        GeneralName::Rfc822Name(value) => json!({"type": "email", "value": value.as_str()}),
        GeneralName::UniformResourceIdentifier(value) =>
        {
            json!({"type": "URI", "value": value.as_str()})
        }
        GeneralName::DirectoryName(value) =>
        {
            json!({"type": "directory", "value": value.to_string()})
        }
        GeneralName::RegisteredId(value) =>
        {
            json!({"type": "registered_id", "value": value.to_string()})
        }
        GeneralName::IpAddress(value) =>
        {
            let address = if let Ok(v4) = <[u8; 4]>::try_from(value.as_bytes())
            {
                Some(Ipv4Addr::from(v4).to_string())
            }
            else if let Ok(v6) = <[u8; 16]>::try_from(value.as_bytes())
            {
                Some(Ipv6Addr::from(v6).to_string())
            }
            else
            {
                None
            };
            json!({"type": "IP", "value": address, "raw_base64": STANDARD.encode(value.as_bytes())})
        }
        other =>
        {
            json!({"type": "other", "der_base64": other.to_der().ok().map(|der| STANDARD.encode(der))})
        }
    }
}
