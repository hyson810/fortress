pub mod https;
pub mod dns;
pub mod websocket;
pub mod icmp;
pub mod smb;

use async_trait::async_trait;

/// Result from a transport check-in
pub struct TransportResult {
    /// Raw bytes received from teamserver (encrypted envelope)
    pub data: Vec<u8>,
    /// Whether this was a new connection or reused
    pub reused: bool,
}

/// Every transport protocol implements this trait
#[async_trait]
pub trait Transport: Send + Sync {
    /// Check in with the teamserver. Returns encrypted task data (or empty).
    async fn checkin(&self) -> Result<TransportResult, TransportError>;

    /// Send encrypted result back to teamserver.
    async fn send(&self, data: &[u8]) -> Result<(), TransportError>;

    /// Display name for logging (e.g., "https/cdn.example.com")
    fn name(&self) -> &str;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("timeout")]
    Timeout,
    #[error("server returned error: {0}")]
    ServerError(u16),
    #[error("invalid response")]
    InvalidResponse,
}

/// Build a transport from config string
pub fn create_transport(kind: &str, url: &str) -> Result<Box<dyn Transport>, TransportError> {
    match kind {
        "https" => Ok(Box::new(https::HttpsTransport::new(url)?)),
        "ws" => Ok(Box::new(websocket::WsTransport::new(url)?)),
        "dns" => Ok(Box::new(dns::DnsTransport::new(url)?)),
        "icmp" => Ok(Box::new(icmp::IcmpTransport::new(url)?)),
        "smb" => Ok(Box::new(smb::SmbTransport::new(url)?)),
        _ => Err(TransportError::Connection(format!("unknown transport: {kind}"))),
    }
}
