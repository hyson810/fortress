use async_trait::async_trait;
use super::{Transport, TransportError, TransportResult};

pub struct SmbTransport {
    pipe_name: String,
}

impl SmbTransport {
    pub fn new(pipe: &str) -> Result<Self, TransportError> {
        Ok(Self { pipe_name: pipe.to_string() })
    }
}

#[async_trait]
impl Transport for SmbTransport {
    async fn checkin(&self) -> Result<TransportResult, TransportError> {
        Err(TransportError::Connection(
            "SMB named pipe transport — not yet implemented".into(),
        ))
    }

    async fn send(&self, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::Connection("SMB not yet implemented".into()))
    }

    fn name(&self) -> &str { "smb" }
}
