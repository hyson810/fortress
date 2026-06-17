use anyhow::Result;

/// CPU-pinned batch dispatcher for AF_XDP.
pub struct Dispatcher {
    pub core_id: u32,
    pub batch_size: u32,
}

impl Dispatcher {
    pub fn new(core_id: u32, batch_size: u32) -> Self {
        Dispatcher { core_id, batch_size }
    }

    pub fn start(&self) -> Result<()> {
        anyhow::bail!("Dispatcher requires AF_XDP socket + UMEM. Core {} configured for batch size {}.", self.core_id, self.batch_size);
    }
}
