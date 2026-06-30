//! eBPF program loader — manages BPF bytecode and program lifecycle.
//!
//! On Linux, eBPF programs are loaded via the bpf(2) syscall and attached to
//! XDP/TC hooks using netlink. This module handles bytecode management and
//! provides the Rust-side loading API that the Go brain calls via FFI.
//!
//! The actual BPF syscall layer is handled by cilium/ebpf on the Go side.
//! This module focuses on bytecode validation, embedding, and the Rust-side
//! configuration and management API.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Embedded BPF bytecode
// ---------------------------------------------------------------------------

/// Embedded BPF bytecode for the XDP filter.
pub const XDP_FILTER_BYTECODE: &[u8] = include_bytes!("../../../kernel/bpf/xdp_filter.o");

/// Embedded BPF bytecode for the TC egress filter.
pub const TC_EGRESS_BYTECODE: &[u8] = include_bytes!("../../../kernel/bpf/tc_egress.o");

// ---------------------------------------------------------------------------
// BPF lifecycle types
// ---------------------------------------------------------------------------

/// Where a BPF program is attached in the network stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachPoint {
    /// XDP native: driver-level hook, ~50ns per packet.
    XdpNative,
    /// XDP generic: SKB-level hook (fallback when driver doesn't support native).
    XdpGeneric,
    /// XDP offloaded: runs on NIC hardware (requires SmartNIC).
    XdpOffloaded,
    /// TC ingress classifier.
    TcIngress,
    /// TC egress classifier.
    TcEgress,
}

impl AttachPoint {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttachPoint::XdpNative => "xdp/native",
            AttachPoint::XdpGeneric => "xdp/generic",
            AttachPoint::XdpOffloaded => "xdp/offloaded",
            AttachPoint::TcIngress => "tc/ingress",
            AttachPoint::TcEgress => "tc/egress",
        }
    }
}

/// Describes a BPF program to be loaded.
#[derive(Debug, Clone)]
pub struct BpfProgramSpec {
    /// Human-readable name.
    pub name: String,
    /// Path to the compiled .o file.
    pub object_path: PathBuf,
    /// ELF section name (e.g., "xdp_filter").
    pub section: String,
    /// Where to attach.
    pub attach: AttachPoint,
    /// Network interface name.
    pub iface: String,
}

/// State of a loaded BPF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramState {
    Registered,
    Loaded,
    Attached,
    Error,
}

/// Tracks one BPF program through its lifecycle.
#[derive(Debug, Clone)]
pub struct BpfProgram {
    pub spec: BpfProgramSpec,
    pub state: ProgramState,
    pub bytecode_size: usize,
}

// ---------------------------------------------------------------------------
// BPF Loader
// ---------------------------------------------------------------------------

/// Manages the lifecycle of multiple BPF programs.
///
/// Responsibilities:
///   - Register BPF program specifications
///   - Validate bytecode availability and integrity
///   - Coordinate with the Go side (cilium/ebpf) for actual loading
///   - Track program state for health monitoring
///   - Ensure clean detach on shutdown
pub struct BpfLoader {
    programs: HashMap<String, BpfProgram>,
}

impl BpfLoader {
    /// Create a new empty BPF loader.
    pub fn new() -> Self {
        BpfLoader {
            programs: HashMap::new(),
        }
    }

    /// Register a BPF program specification.
    pub fn register(&mut self, spec: BpfProgramSpec) -> Result<()> {
        if self.programs.contains_key(&spec.name) {
            anyhow::bail!("BPF program '{}' already registered", spec.name);
        }

        // Validate the object file exists and has content.
        let bytecode = Self::validate_object(&spec.object_path)?;

        log::info!(
            "registered BPF program '{}' ({} bytes, section={}, attach={}, iface={})",
            spec.name,
            bytecode.len(),
            spec.section,
            spec.attach.as_str(),
            spec.iface,
        );

        self.programs.insert(
            spec.name.clone(),
            BpfProgram {
                spec,
                state: ProgramState::Registered,
                bytecode_size: bytecode.len(),
            },
        );
        Ok(())
    }

    /// Register the built-in XDP filter program.
    pub fn register_xdp_filter(&mut self, iface: &str) -> Result<()> {
        self.register(BpfProgramSpec {
            name: "xdp_filter".to_string(),
            object_path: PathBuf::from("kernel/bpf/xdp_filter.o"),
            section: "xdp_filter".to_string(),
            attach: AttachPoint::XdpNative,
            iface: iface.to_string(),
        })
    }

    /// Register the built-in TC egress program.
    pub fn register_tc_egress(&mut self, iface: &str) -> Result<()> {
        self.register(BpfProgramSpec {
            name: "tc_egress".to_string(),
            object_path: PathBuf::from("kernel/bpf/tc_egress.o"),
            section: "tc_egress".to_string(),
            attach: AttachPoint::TcEgress,
            iface: iface.to_string(),
        })
    }

    /// Mark a program as loaded in the kernel.
    pub fn mark_loaded(&mut self, name: &str) -> Result<()> {
        let prog = self
            .programs
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not registered", name))?;
        prog.state = ProgramState::Loaded;
        log::info!("BPF program '{}' loaded", name);
        Ok(())
    }

    /// Mark a program as attached to its hook point.
    pub fn mark_attached(&mut self, name: &str) -> Result<()> {
        let prog = self
            .programs
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not registered", name))?;
        prog.state = ProgramState::Attached;
        log::info!("BPF program '{}' attached via {}", name, prog.spec.attach.as_str());
        Ok(())
    }

    /// Mark a program as having errored.
    pub fn mark_error(&mut self, name: &str) -> Result<()> {
        let prog = self
            .programs
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not registered", name))?;
        prog.state = ProgramState::Error;
        Ok(())
    }

    /// Get the state of a registered program.
    pub fn program_state(&self, name: &str) -> Option<ProgramState> {
        self.programs.get(name).map(|p| p.state)
    }

    /// Return all registered program names.
    pub fn program_names(&self) -> Vec<&str> {
        self.programs.keys().map(|s| s.as_str()).collect()
    }

    /// Number of registered programs.
    pub fn count(&self) -> usize {
        self.programs.len()
    }

    /// Number of programs in each state.
    pub fn count_by_state(&self) -> HashMap<ProgramState, usize> {
        let mut counts = HashMap::new();
        for prog in self.programs.values() {
            *counts.entry(prog.state).or_insert(0) += 1;
        }
        counts
    }

    /// Return the XDP filter bytecode.
    pub fn xdp_bytecode() -> &'static [u8] {
        XDP_FILTER_BYTECODE
    }

    /// Return the TC egress bytecode.
    pub fn tc_bytecode() -> &'static [u8] {
        TC_EGRESS_BYTECODE
    }

    /// Validate a BPF object file exists and has content.
    fn validate_object(path: &Path) -> Result<Vec<u8>> {
        let data = std::fs::read(path)
            .with_context(|| format!("reading BPF object: {}", path.display()))?;
        if data.is_empty() {
            anyhow::bail!("BPF object file is empty: {}", path.display());
        }
        // Basic ELF header validation: should start with \x7fELF.
        if data.len() >= 4 && &data[0..4] != b"\x7fELF" {
            anyhow::bail!(
                "BPF object file is not a valid ELF: {}",
                path.display()
            );
        }
        Ok(data)
    }
}

impl Default for BpfLoader {
    fn default() -> Self {
        BpfLoader::new()
    }
}

// ---------------------------------------------------------------------------
// Bytecode helpers
// ---------------------------------------------------------------------------

/// Read compiled BPF bytecode from a file path.
pub fn read_bpf_object(path: &str) -> Result<Vec<u8>> {
    let data = std::fs::read(Path::new(path))?;
    if data.is_empty() {
        anyhow::bail!("BPF object file is empty: {}", path);
    }
    Ok(data)
}

/// Returns the size of embedded XDP filter bytecode.
pub fn xdp_bytecode_size() -> usize {
    XDP_FILTER_BYTECODE.len()
}

/// Returns the size of embedded TC egress bytecode.
pub fn tc_bytecode_size() -> usize {
    TC_EGRESS_BYTECODE.len()
}

/// Describe the XDP filter: what it does, which maps it uses.
pub fn xdp_filter_description() -> &'static str {
    "XDP filter: whitelist (LPM_TRIE) → blacklist (LRU_HASH 10K) → rate_limit (token bucket) → \
     stats (PERCPU_ARRAY). Drops blacklisted IPs at ~50ns, rate-limits flooders, \
     passes whitelisted IPs directly to userspace AF_XDP."
}

/// Describe the TC egress filter: what it does.
pub fn tc_egress_description() -> &'static str {
    "TC egress filter: monitors outbound traffic for data exfiltration patterns. \
     Tracks bytes-per-flow, alerts on threshold exceed (10MB default), \
     and can drop packets from compromised IPs."
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    #[test]
    fn test_bpf_loader_register() {
        let mut loader = BpfLoader::new();
        // Register with a spec that points to the embedded bytecode path.
        let spec = BpfProgramSpec {
            name: "test_prog".to_string(),
            object_path: PathBuf::from("kernel/bpf/xdp_filter.o"),
            section: "test".to_string(),
            attach: AttachPoint::XdpNative,
            iface: "eth0".to_string(),
        };
        assert!(loader.register(spec).is_ok());
        assert_eq!(loader.count(), 1);
    }

    #[test]
    fn test_bpf_loader_duplicate_register() {
        let mut loader = BpfLoader::new();
        let spec = BpfProgramSpec {
            name: "dup".to_string(),
            object_path: PathBuf::from("kernel/bpf/xdp_filter.o"),
            section: "test".to_string(),
            attach: AttachPoint::XdpNative,
            iface: "eth0".to_string(),
        };
        assert!(loader.register(spec.clone()).is_ok());
        assert!(loader.register(spec).is_err()); // Duplicate name.
    }

    #[test]
    fn test_bpf_loader_missing_object() {
        let mut loader = BpfLoader::new();
        let spec = BpfProgramSpec {
            name: "missing".to_string(),
            object_path: PathBuf::from("kernel/bpf/nonexistent.o"),
            section: "test".to_string(),
            attach: AttachPoint::XdpNative,
            iface: "eth0".to_string(),
        };
        assert!(loader.register(spec).is_err());
    }

    #[test]
    fn test_mark_states() {
        let mut loader = BpfLoader::new();
        let spec = BpfProgramSpec {
            name: "state_test".to_string(),
            object_path: PathBuf::from("kernel/bpf/xdp_filter.o"),
            section: "test".to_string(),
            attach: AttachPoint::TcEgress,
            iface: "eth1".to_string(),
        };
        loader.register(spec).unwrap();

        assert_eq!(loader.program_state("state_test"), Some(ProgramState::Registered));

        loader.mark_loaded("state_test").unwrap();
        assert_eq!(loader.program_state("state_test"), Some(ProgramState::Loaded));

        loader.mark_attached("state_test").unwrap();
        assert_eq!(loader.program_state("state_test"), Some(ProgramState::Attached));

        loader.mark_error("state_test").unwrap();
        assert_eq!(loader.program_state("state_test"), Some(ProgramState::Error));
    }

    #[test]
    fn test_count_by_state() {
        let mut loader = BpfLoader::new();
        for i in 0..3 {
            let spec = BpfProgramSpec {
                name: format!("prog_{}", i),
                object_path: PathBuf::from("kernel/bpf/xdp_filter.o"),
                section: "test".to_string(),
                attach: AttachPoint::XdpNative,
                iface: "eth0".to_string(),
            };
            loader.register(spec).unwrap();
        }
        let counts = loader.count_by_state();
        assert_eq!(counts.get(&ProgramState::Registered), Some(&3));
    }

    #[test]
    fn test_read_bpf_object_nonexistent() {
        assert!(read_bpf_object("/nonexistent/bpf.o").is_err());
    }
}
