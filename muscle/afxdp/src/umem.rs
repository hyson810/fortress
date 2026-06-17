use anyhow::Result;

/// UMEM (User Memory) configuration for zero-copy AF_XDP.
pub struct Umem {
    pub frame_count: u32,
    pub frame_size: u32,
}

impl Umem {
    pub fn new(frame_count: u32, frame_size: u32) -> Self {
        Umem { frame_count, frame_size }
    }

    pub fn allocate(&self) -> Result<()> {
        anyhow::bail!("UMEM allocation requires huge pages and AF_XDP kernel support. Configured for {} frames of {} bytes.", self.frame_count, self.frame_size);
    }
}
