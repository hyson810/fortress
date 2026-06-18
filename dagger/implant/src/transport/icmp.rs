use async_trait::async_trait;
use super::{Transport, TransportError, TransportResult};

pub struct IcmpTransport {
    target: String,
}

impl IcmpTransport {
    pub fn new(target: &str) -> Result<Self, TransportError> {
        Ok(Self { target: target.to_string() })
    }
}

#[async_trait]
impl Transport for IcmpTransport {
    async fn checkin(&self) -> Result<TransportResult, TransportError> {
        Err(TransportError::Connection(
            "ICMP transport requires raw socket (root) — not yet implemented".into(),
        ))
    }

    async fn send(&self, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::Connection("ICMP not yet implemented".into()))
    }

    fn name(&self) -> &str { "icmp" }
}
