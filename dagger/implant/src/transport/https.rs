use async_trait::async_trait;
use super::{Transport, TransportError, TransportResult};
use reqwest::Client;

pub struct HttpsTransport {
    url: String,
    client: Client,
}

impl HttpsTransport {
    pub fn new(url: &str) -> Result<Self, TransportError> {
        let client = Client::builder()
            .http1_only()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            client,
        })
    }
}

#[async_trait]
impl Transport for HttpsTransport {
    async fn checkin(&self) -> Result<TransportResult, TransportError> {
        let resp = self
            .client
            .get(&self.url)
            .header("Accept", "application/octet-stream")
            .send()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        if resp.status().is_success() {
            let data = resp.bytes().await.map_err(|e| TransportError::Connection(e.to_string()))?;
            Ok(TransportResult { data: data.to_vec(), reused: false })
        } else {
            Err(TransportError::ServerError(resp.status().as_u16()))
        }
    }

    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        self.client
            .post(&self.url)
            .body(data.to_vec())
            .header("Content-Type", "application/octet-stream")
            .send()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(())
    }

    fn name(&self) -> &str { "https" }
}
