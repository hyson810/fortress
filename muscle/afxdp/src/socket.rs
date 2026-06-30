//! AF_XDP socket — binds an XDP program to a network interface queue.
//!
//! An XDP socket (XSK) is a raw socket in the AF_XDP address family that
//! provides direct access to the XDP data path. Each socket is bound to a
//! specific network device queue ID, enabling multi-queue parallelism.
//!
//! Socket lifecycle:
//!   socket(AF_XDP, SOCK_RAW, 0) → bind to iface+queue → configure rings
//!   → attach to UMEM → enter Rx/Tx loop
//!
//! Multiple XDP sockets can share a single UMEM (one per RX queue), which
//! is the recommended configuration for multi-core throughput.

use anyhow::{Context, Result};
use std::io;

use crate::umem::Umem;

// ---------------------------------------------------------------------------
// Socket configuration
// ---------------------------------------------------------------------------

/// XDP socket bind flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpBindFlags {
    /// Default: shared UMEM, no special behavior.
    None = 0,
    /// XDP_USE_NEED_WAKEUP: driver must be woken via sendto() syscall.
    /// Reduces syscalls in high-throughput scenarios.
    NeedWakeup = 1,
    /// XDP_COPY: force copy mode (bypasses zero-copy). Useful for
    /// debugging or when the driver doesn't support zero-copy.
    Copy = 2,
    /// XDP_ZEROCOPY: force zero-copy mode. Fails if driver doesn't support.
    ZeroCopy = 4,
}

/// Configuration for creating and binding an XDP socket.
#[derive(Debug, Clone)]
pub struct XdpSocketConfig {
    /// Network interface name (e.g., "eth0", "enp1s0").
    pub iface: String,

    /// Hardware RX queue ID to bind to. Typically 0..N where N = number of
    /// RSS queues on the NIC. Each queue gets its own XDP socket.
    pub queue_id: u32,

    /// Bind flags controlling socket behavior.
    pub bind_flags: XdpBindFlags,

    /// Number of entries in the RX ring (must be power of two).
    /// Larger rings reduce drops but consume more UMEM frames.
    /// Recommended: 2048 for 10G, 4096 for 40G+.
    pub rx_ring_size: u32,

    /// Number of entries in the TX ring (must be power of two).
    /// Usually smaller than RX since most packets are dropped/forwarded.
    pub tx_ring_size: u32,

    /// Number of entries in the fill ring. Must match rx_ring_size
    /// or the kernel will adjust.
    pub fill_ring_size: u32,

    /// Number of entries in the completion ring. Must match tx_ring_size.
    pub completion_ring_size: u32,
}

impl Default for XdpSocketConfig {
    fn default() -> Self {
        XdpSocketConfig {
            iface: String::new(),
            queue_id: 0,
            bind_flags: XdpBindFlags::None,
            rx_ring_size: 2048,
            tx_ring_size: 512,
            fill_ring_size: 2048,
            completion_ring_size: 512,
        }
    }
}

impl XdpSocketConfig {
    /// Create a new config for the given interface and queue.
    pub fn new(iface: &str, queue_id: u32) -> Self {
        XdpSocketConfig {
            iface: iface.to_string(),
            queue_id,
            ..Default::default()
        }
    }

    /// Set zero-copy mode (requires driver support).
    pub fn with_zero_copy(mut self) -> Self {
        self.bind_flags = XdpBindFlags::ZeroCopy;
        self
    }

    /// Set need-wakeup mode for reduced syscall overhead.
    pub fn with_need_wakeup(mut self) -> Self {
        self.bind_flags = XdpBindFlags::NeedWakeup;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.iface.is_empty() {
            anyhow::bail!("interface name must be specified");
        }
        if !self.rx_ring_size.is_power_of_two() {
            anyhow::bail!("rx_ring_size must be a power of two");
        }
        if !self.tx_ring_size.is_power_of_two() {
            anyhow::bail!("tx_ring_size must be a power of two");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// XDP socket
// ---------------------------------------------------------------------------

/// An AF_XDP socket bound to a specific NIC queue.
///
/// The socket is the primary interface for receiving and transmitting packets
/// through the XDP fast-path. It must be created with a UMEM for the
/// zero-copy data path.
pub struct XdpSocket {
    pub config: XdpSocketConfig,

    /// UMEM shared across all sockets on this interface.
    /// Stored as raw pointer to avoid lifetime coupling.
    #[cfg(target_os = "linux")]
    umem_ptr: *const Umem,

    /// AF_XDP socket file descriptor.
    #[cfg(target_os = "linux")]
    xsk_fd: std::os::unix::io::RawFd,

    /// Interface index (resolved from name at bind time).
    #[cfg(target_os = "linux")]
    ifindex: u32,
}

impl XdpSocket {
    /// Create a new XDP socket configuration without binding.
    /// Call `bind()` to attach to an interface and UMEM.
    pub fn new(config: XdpSocketConfig) -> Self {
        #[cfg(not(target_os = "linux"))]
        {
            XdpSocket { config }
        }

        #[cfg(target_os = "linux")]
        {
            XdpSocket {
                config,
                umem_ptr: std::ptr::null(),
                xsk_fd: -1,
                ifindex: 0,
            }
        }
    }

    /// Bind the socket to the configured interface and attach to the UMEM.
    ///
    /// This performs:
    ///   1. Creates an AF_XDP socket via socket(2)
    ///   2. Resolves the interface index from the interface name
    ///   3. Binds the socket to (ifindex, queue_id) via bind(2)
    ///   4. Sets up the RX, TX, fill, and completion rings
    ///   5. Associates the UMEM with this socket
    #[cfg(target_os = "linux")]
    pub fn bind(&mut self, umem: &Umem) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        self.config.validate()?;

        // 1. Create AF_XDP socket.
        const AF_XDP: libc::c_int = 44;
        const SOCK_RAW: libc::c_int = 3;

        let fd = unsafe { libc::socket(AF_XDP, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to create AF_XDP socket");
        }
        self.xsk_fd = fd;

        // 2. Resolve interface index.
        let c_iface = CString::new(self.config.iface.as_bytes())
            .context("invalid interface name")?;
        let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
        if ifindex == 0 {
            unsafe { libc::close(fd) };
            anyhow::bail!("interface '{}' not found", self.config.iface);
        }
        self.ifindex = ifindex;

        // 3. Bind to interface + queue.
        // struct sockaddr_xdp {
        //     __u16 sxdp_family;   // AF_XDP
        //     __u16 sxdp_flags;    // bind flags
        //     __u32 sxdp_ifindex;  // interface index
        //     __u32 sxdp_queue_id; // queue ID
        //     __u32 sxdp_shared_umem_fd; // fd of shared UMEM
        // };
        const AF_XDP_U16: u16 = 44;

        #[repr(C)]
        struct SockAddrXdp {
            family: u16,
            flags: u16,
            ifindex: u32,
            queue_id: u32,
            shared_umem_fd: u32,
        }

        let sa = SockAddrXdp {
            family: AF_XDP_U16,
            flags: self.config.bind_flags as u16,
            ifindex,
            queue_id: self.config.queue_id,
            shared_umem_fd: umem.raw_fd() as u32,
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockAddrXdp>() as u32,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err).context(format!(
                "failed to bind XDP socket to {} queue {}",
                self.config.iface, self.config.queue_id,
            ));
        }

        // 4. Configure ring sizes via setsockopt XDP_RX_RING / XDP_TX_RING etc.
        // These must be set BEFORE the socket enters the bound state.
        self.set_ring_sizes()?;

        // 5. Store UMEM reference.
        self.umem_ptr = umem as *const Umem;

        Ok(())
    }

    /// Configure the RX, TX, fill, and completion ring sizes.
    #[cfg(target_os = "linux")]
    fn set_ring_sizes(&self) -> Result<()> {
        const SOL_XDP: libc::c_int = 283;
        const XDP_RX_RING: libc::c_int = 2;
        const XDP_TX_RING: libc::c_int = 3;
        const XDP_UMEM_FILL_RING: libc::c_int = 4;
        const XDP_UMEM_COMPLETION_RING: libc::c_int = 5;

        let rings = [
            (XDP_RX_RING, self.config.rx_ring_size, "RX"),
            (XDP_TX_RING, self.config.tx_ring_size, "TX"),
            (XDP_UMEM_FILL_RING, self.config.fill_ring_size, "fill"),
            (XDP_UMEM_COMPLETION_RING, self.config.completion_ring_size, "completion"),
        ];

        for (opt, size, name) in &rings {
            let ret = unsafe {
                libc::setsockopt(
                    self.xsk_fd,
                    SOL_XDP,
                    *opt,
                    size as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as u32,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error())
                    .context(format!("failed to set {} ring size to {}", name, size));
            }
        }

        Ok(())
    }

    /// Non-Linux: provide a descriptive error about requirements.
    #[cfg(not(target_os = "linux"))]
    pub fn bind(&mut self, _umem: &Umem) -> Result<()> {
        self.config.validate()?;
        anyhow::bail!(
            "AF_XDP socket binding requires Linux kernel 5.4+ with XDP driver support. \
             Configured for interface '{}' queue {}. \
             Will be functional when deployed on bare-metal Linux.",
            self.config.iface,
            self.config.queue_id,
        );
    }

    /// Return the raw socket file descriptor.
    #[cfg(target_os = "linux")]
    pub fn raw_fd(&self) -> std::os::unix::io::RawFd {
        self.xsk_fd
    }

    /// Interface index this socket is bound to.
    #[cfg(target_os = "linux")]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Queue ID this socket is bound to.
    pub fn queue_id(&self) -> u32 {
        self.config.queue_id
    }

    /// Interface name.
    pub fn iface(&self) -> &str {
        &self.config.iface
    }

    /// Check if this socket is bound (has a valid fd).
    #[cfg(target_os = "linux")]
    pub fn is_bound(&self) -> bool {
        self.xsk_fd >= 0
    }

    #[cfg(not(target_os = "linux"))]
    pub fn is_bound(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Drop — clean up socket resources
// ---------------------------------------------------------------------------

impl Drop for XdpSocket {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if self.xsk_fd >= 0 {
                unsafe { libc::close(self.xsk_fd) };
            }
        }
    }
}

// Safety: The UMEM pointer is only accessed within the bind() call and
// must outlive this socket (guaranteed by the caller's ownership).
unsafe impl Send for XdpSocket {}
unsafe impl Sync for XdpSocket {}

// ---------------------------------------------------------------------------
// Socket statistics
// ---------------------------------------------------------------------------

/// Per-socket statistics for monitoring and debugging.
#[derive(Debug, Default, Clone)]
pub struct XdpSocketStats {
    /// Total packets received via this socket.
    pub rx_packets: u64,

    /// Total packets transmitted via this socket.
    pub tx_packets: u64,

    /// Packets dropped due to full RX ring.
    pub rx_dropped: u64,

    /// Packets dropped due to full TX ring.
    pub tx_dropped: u64,

    /// Times the kernel woke userspace for RX processing.
    pub rx_wakeups: u64,

    /// Times userspace explicitly polled for packets.
    pub polls: u64,
}
