use std::error::Error;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub struct Report {
    pub phase: &'static str,
    pub reason: &'static str,
    pub exit_code: u8,
    pub error: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub matched: bool,
    pub peer_addr: Option<String>,
    pub server_name: Option<String>,
    pub tls: Option<Value>,
    pub output: Vec<u8>,
    started: Instant,
}

impl Report {
    pub fn new() -> Self {
        Self {
            phase: "usage",
            reason: "invalid_arguments",
            exit_code: 2,
            error: None,
            bytes_sent: 0,
            bytes_received: 0,
            matched: false,
            peer_addr: None,
            server_name: None,
            tls: None,
            output: Vec::new(),
            started: Instant::now(),
        }
    }

    pub fn finish(&mut self, exit_code: u8, reason: &'static str) -> u8 {
        self.exit_code = exit_code;
        self.reason = reason;
        exit_code
    }

    pub fn fail(&mut self, error: &(dyn Error + 'static)) {
        self.error = Some(error.to_string());
        let reason = self.classify(error);
        self.finish(1, reason);
    }

    pub fn output_budget(&self, limit: Duration) -> Duration {
        limit
            .saturating_sub(self.started.elapsed())
            .max(Duration::from_millis(100))
    }

    fn classify(&self, error: &(dyn Error + 'static)) -> &'static str {
        if let Some(rustls::Error::InvalidCertificate(cert)) = error.downcast_ref::<rustls::Error>()
        {
            use rustls::CertificateError::*;
            return match cert {
                UnknownIssuer => "unknown_issuer",
                Expired | ExpiredContext { .. } => "certificate_expired",
                NotValidYet | NotValidYetContext { .. } => "certificate_not_yet_valid",
                NotValidForName | NotValidForNameContext { .. } => "hostname_mismatch",
                _ => "invalid_certificate",
            };
        }
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref()
                && inner.is::<rustls::Error>()
            {
                return self.classify(inner);
            }
            match io.kind() {
                ErrorKind::ConnectionRefused => return "connection_refused",
                ErrorKind::ConnectionReset => return "connection_reset",
                ErrorKind::BrokenPipe => return "broken_pipe",
                ErrorKind::TimedOut => return "connect_timeout",
                _ => {}
            }
        }
        match self.phase {
            "dns" => "dns_error",
            "connect" => "connect_error",
            "tls" => "tls_error",
            "certificate" => "invalid_certificate_file",
            "output" => "output_error",
            "write" => "write_error",
            _ => "read_error",
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "schema_version": 1,
            "ok": self.exit_code == 0,
            "exit_code": self.exit_code,
            "phase": self.phase,
            "reason": self.reason,
            "error": self.error,
            "elapsed_ms": self.started.elapsed().as_millis(),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "matched": self.matched,
            "peer_addr": self.peer_addr,
            "server_name": self.server_name,
            "tls": self.tls,
            "output_base64": STANDARD.encode(&self.output),
            "output_utf8": std::str::from_utf8(&self.output).ok(),
        })
    }
}
