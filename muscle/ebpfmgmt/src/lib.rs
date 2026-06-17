pub mod loader;
pub mod maps;

use anyhow::Result;
use aya::maps::Map;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;

pub struct EbpfEngine {
    bpf: Ebpf,
    _bpf_tc: Ebpf,
    iface: String,
}

impl EbpfEngine {
    /// Load BPF bytecode from embedded bytes and attach to interface.
    pub fn new(xdp_bytes: &[u8], tc_bytes: &[u8], iface: &str) -> Result<Self> {
        let mut bpf = Ebpf::load(xdp_bytes)?;

        // Attach XDP program
        let xdp_prog: &mut Xdp = bpf
            .program_mut("xdp_filter")
            .ok_or_else(|| anyhow::anyhow!("xdp_filter program not found"))?
            .try_into()?;
        xdp_prog.load()?;
        xdp_prog.attach(iface, XdpFlags::default())?;

        // Load TC bytes separately for egress
        let mut bpf_tc = Ebpf::load(tc_bytes)?;
        let tc_prog: &mut SchedClassifier = bpf_tc
            .program_mut("tc_egress")
            .ok_or_else(|| anyhow::anyhow!("tc_egress program not found"))?
            .try_into()?;
        tc_prog.load()?;
        tc_prog.attach(iface, TcAttachType::Egress)?;

        Ok(EbpfEngine {
            bpf,
            _bpf_tc: bpf_tc,
            iface: iface.to_string(),
        })
    }

    /// Get a mutable reference to the BPF instance (for map operations).
    pub fn bpf_mut(&mut self) -> &mut Ebpf {
        &mut self.bpf
    }

    /// Get a shared reference to the BPF instance (for read-only map operations).
    pub fn bpf(&self) -> &Ebpf {
        &self.bpf
    }

    /// Get the interface name.
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// Get reference to the blocked_ips map.
    pub fn blocked_ips_map(&self) -> Result<&Map> {
        self.bpf
            .map("blocked_ips")
            .ok_or_else(|| anyhow::anyhow!("blocked_ips map not found"))
    }

    /// Get reference to the rate_limit map.
    pub fn rate_limit_map(&self) -> Result<&Map> {
        self.bpf
            .map("rate_limit")
            .ok_or_else(|| anyhow::anyhow!("rate_limit map not found"))
    }

    /// Get reference to the stats map.
    pub fn stats_map(&self) -> Result<&Map> {
        self.bpf
            .map("stats")
            .ok_or_else(|| anyhow::anyhow!("stats map not found"))
    }

    /// Get reference to the whitelist map.
    pub fn whitelist_map(&self) -> Result<&Map> {
        self.bpf
            .map("whitelist")
            .ok_or_else(|| anyhow::anyhow!("whitelist map not found"))
    }
}
