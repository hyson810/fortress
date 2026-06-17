use anyhow::Result;
use std::path::Path;

/// Read compiled BPF bytecode from a file.
pub fn read_bpf_object(path: &str) -> Result<Vec<u8>> {
    let data = std::fs::read(Path::new(path))?;
    if data.is_empty() {
        anyhow::bail!("BPF object file is empty: {}", path);
    }
    Ok(data)
}

/// Embedded BPF bytecode for the XDP filter.
pub const XDP_FILTER_BYTECODE: &[u8] = include_bytes!("../../../kernel/bpf/xdp_filter.o");

/// Embedded BPF bytecode for the TC egress filter.
pub const TC_EGRESS_BYTECODE: &[u8] = include_bytes!("../../../kernel/bpf/tc_egress.o");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdp_bytecode_embedded() {
        assert!(!XDP_FILTER_BYTECODE.is_empty());
    }

    #[test]
    fn test_tc_bytecode_embedded() {
        assert!(!TC_EGRESS_BYTECODE.is_empty());
    }
}
