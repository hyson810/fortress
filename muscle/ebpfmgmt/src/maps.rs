use anyhow::Result;
use aya::maps::{
    lpm_trie::Key, HashMap, LpmTrie, Map, MapData, PerCpuArray,
};
use std::convert::TryFrom;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// Blocked IPs (LRU_HASH: u32 key, u8 value)
// ---------------------------------------------------------------------------

/// Block an IP by adding it to the blocked_ips BPF map.
pub fn block_ip(bpf: &mut aya::Ebpf, ip: Ipv4Addr) -> Result<()> {
    let block_map = bpf
        .map_mut("blocked_ips")
        .ok_or_else(|| anyhow::anyhow!("blocked_ips map not found"))?;
    let block_map: &mut Map = block_map;
    let mut typed: HashMap<&mut MapData, u32, u8> =
        HashMap::try_from(block_map)?;
    let key: u32 = u32::from(ip);
    typed.insert(&key, &1u8, 0)?;
    Ok(())
}

/// Unblock an IP by removing it from the blocked_ips BPF map.
pub fn unblock_ip(bpf: &mut aya::Ebpf, ip: Ipv4Addr) -> Result<()> {
    let block_map = bpf
        .map_mut("blocked_ips")
        .ok_or_else(|| anyhow::anyhow!("blocked_ips map not found"))?;
    let block_map: &mut Map = block_map;
    let mut typed: HashMap<&mut MapData, u32, u8> =
        HashMap::try_from(block_map)?;
    let key: u32 = u32::from(ip);
    typed.remove(&key)?;
    Ok(())
}

/// Set rate limit tokens for an IP in the rate_limit LRU hash map.
pub fn set_rate_limit(bpf: &mut aya::Ebpf, ip: Ipv4Addr, tokens: u32) -> Result<()> {
    let rl_map = bpf
        .map_mut("rate_limit")
        .ok_or_else(|| anyhow::anyhow!("rate_limit map not found"))?;
    let rl_map: &mut Map = rl_map;
    let mut typed: HashMap<&mut MapData, u32, u32> =
        HashMap::try_from(rl_map)?;
    let key: u32 = u32::from(ip);
    typed.insert(&key, &tokens, 0)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Stats (PERCPU_ARRAY: u32 key, u64 value)
// ---------------------------------------------------------------------------

/// Get statistics from the per-CPU stats map.
///
/// Key 0 = packets passed, key 1 = packets dropped, key 2 = rate-limited.
pub fn get_stats(bpf: &aya::Ebpf) -> Result<(u64, u64, u64)> {
    let stats_map = bpf
        .map("stats")
        .ok_or_else(|| anyhow::anyhow!("stats map not found"))?;
    let stats_map_ref: &Map = stats_map;
    let typed: PerCpuArray<&MapData, u64> =
        PerCpuArray::try_from(stats_map_ref)?;

    let passed = sum_percpu_values(&typed, 0)?;
    let dropped = sum_percpu_values(&typed, 1)?;
    let rate_limited = sum_percpu_values(&typed, 2)?;
    Ok((passed, dropped, rate_limited))
}

fn sum_percpu_values(
    map: &PerCpuArray<&MapData, u64>,
    index: u32,
) -> Result<u64> {
    let values = map
        .get(&index, 0)
        .map_err(|e| anyhow::anyhow!("failed to get per-CPU stats at index {}: {}", index, e))?;
    Ok(values.iter().sum())
}

// ---------------------------------------------------------------------------
// Whitelist (LPM_TRIE: u32 key data, u32 value)
// ---------------------------------------------------------------------------

/// Add a CIDR prefix to the whitelist map.
pub fn whitelist_add(bpf: &mut aya::Ebpf, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
    let wl_map = bpf
        .map_mut("whitelist")
        .ok_or_else(|| anyhow::anyhow!("whitelist map not found"))?;
    let wl_map: &mut Map = wl_map;
    let mut typed: LpmTrie<&mut MapData, u32, u32> =
        LpmTrie::try_from(wl_map)?;

    let key = Key::new(prefix_len as u32, u32::from(ip).to_be());
    let value: u32 = 1;
    typed.insert(&key, &value, 0)?;
    Ok(())
}

/// Remove a CIDR prefix from the whitelist map.
pub fn whitelist_remove(bpf: &mut aya::Ebpf, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
    let wl_map = bpf
        .map_mut("whitelist")
        .ok_or_else(|| anyhow::anyhow!("whitelist map not found"))?;
    let wl_map: &mut Map = wl_map;
    let mut typed: LpmTrie<&mut MapData, u32, u32> =
        LpmTrie::try_from(wl_map)?;

    let key = Key::new(prefix_len as u32, u32::from(ip).to_be());
    typed.remove(&key)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_conversion() {
        let ip: u32 = u32::from(std::net::Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(ip, 0xc0a80164);
    }

    #[test]
    fn test_lpm_key_construction() {
        let ip = Ipv4Addr::new(192, 168, 1, 0);
        let key = Key::new(24, u32::from(ip).to_be());
        assert_eq!(key.prefix_len(), 24);
        assert_eq!(key.data(), 0xc0a80100u32.to_be());
    }
}
