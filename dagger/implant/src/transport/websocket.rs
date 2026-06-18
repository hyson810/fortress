use async_trait::async_trait;
use super::{Transport, TransportError, TransportResult};
use url::Url;

pub struct WsTransport {
    url: Url,
    mcp_disguise: bool,
}

impl WsTransport {
    pub fn new(url_str: &str) -> Result<Self, TransportError> {
        let url = Url::parse(url_str)
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        let mcp_disguise = url_str.contains("api.anthropic.com")
            || url_str.contains("api.openai.com")
            || url_str.contains("mcp");
        Ok(Self { url, mcp_disguise })
    }
}

#[async_trait]
impl Transport for WsTransport {
    async fn checkin(&self) -> Result<TransportResult, TransportError> {
        let mut req_builder = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(self.url.as_str());
        if self.mcp_disguise {
            req_builder = req_builder
                .header("x-api-key", "sk-ant-mcp-proxy-v1")
                .header("anthropic-version", "2023-06-01")
                .header("User-Agent", "anthropic-python/0.39.0");
        }
        let req = req_builder.body(())
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        let (mut ws, _) = tokio_tungstenite::connect_async(req)
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        let init_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(init_msg.to_string()))
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        match ws.recv().await {
            Ok(tokio_tungstenite::tungstenite::Message::Text(t)) => {
                Ok(TransportResult { data: t.into_bytes(), reused: false })
            }
            Ok(tokio_tungstenite::tungstenite::Message::Binary(b)) => {
                Ok(TransportResult { data: b, reused: false })
            }
            _ => Err(TransportError::InvalidResponse),
        }
    }

    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let (mut ws, _) = tokio_tungstenite::connect_async(self.url.clone())
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": { "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data) }
        });
        ws.send(tokio_tungstenite::tungstenite::Message::Text(msg.to_string()))
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(())
    }

    fn name(&self) -> &str {
        if self.mcp_disguise { "ws/mcp" } else { "ws" }
    }
}
