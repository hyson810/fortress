//! UMEM (Userspace Memory) region for zero-copy AF_XDP packet processing.
//!
//! A UMEM is a contiguous memory region backed by huge pages, shared between
//! kernel XDP and userspace. Packets are placed directly in UMEM frames — the
//! kernel writes into fill-queue frames and userspace reads from them, then
//! returns them to the fill queue. This eliminates all copies.
//!
//! Frame lifecycle:
//!   UMEM alloc → Fill queue → Kernel RX → RX queue → Userspace process
//!   → Fill queue (return) → Kernel RX → ...
//!
//! On Linux this requires CONFIG_XDP_SOCKETS=y and enough locked memory.

use anyhow::{Context, Result};
use std::io;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default frame size (4K — one huge-page entry on x86-64).
pub const DEFAULT_FRAME_SIZE: u32 = 4096;

/// Default number of frames in the UMEM. Must be a power of two.
/// 4096 × 4K = 16 MB of UMEM, suitable for 10G line rate.
pub const DEFAULT_FRAME_COUNT: u32 = 4096;

/// Minimum number of frames (power of two requirement from kernel).
pub const MIN_FRAME_COUNT: u32 = 64;

/// Maximum number of frames we support (limit from kernel AF_XDP).
pub const MAX_FRAME_COUNT: u32 = 65536;

/// UMEM frame headroom: bytes reserved before packet data for metadata/custom headers.
pub const DEFAULT_HEADROOM: u32 = 0;

// ---------------------------------------------------------------------------
// UMEM configuration
// ---------------------------------------------------------------------------

/// Configures how the UMEM memory region is laid out.
#[derive(Debug, Clone)]
pub struct UmemConfig {
    /// Number of frames. Must be a power of two >= MIN_FRAME_COUNT.
    pub frame_count: u32,

    /// Size of each frame in bytes. Typically 2048 or 4096.
    pub frame_size: u32,

    /// Headroom (bytes) reserved before the packet data in each frame.
    /// Useful for adding custom headers without copying.
    pub headroom: u32,

    /// If true, use huge pages (2MB or 1GB) for the UMEM backing memory.
    /// Improves TLB efficiency at high packet rates but requires
    /// hugetlbfs mounted at /dev/hugepages.
    pub use_huge_pages: bool,

    /// Number of entries in each of the fill and completion rings.
    /// Default: half of frame_count.
    pub ring_size: u32,
}

impl Default for UmemConfig {
    fn default() -> Self {
        UmemConfig {
            frame_count: DEFAULT_FRAME_COUNT,
            frame_size: DEFAULT_FRAME_SIZE,
            headroom: DEFAULT_HEADROOM,
            use_huge_pages: false,
            ring_size: DEFAULT_FRAME_COUNT / 2,
        }
    }
}

impl UmemConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<()> {
        if self.frame_count < MIN_FRAME_COUNT {
            anyhow::bail!(
                "frame_count {} must be >= {}",
                self.frame_count,
                MIN_FRAME_COUNT
            );
        }
        if self.frame_count > MAX_FRAME_COUNT {
            anyhow::bail!(
                "frame_count {} must be <= {}",
                self.frame_count,
                MAX_FRAME_COUNT
            );
        }
        if !self.frame_count.is_power_of_two() {
            anyhow::bail!(
                "frame_count {} must be a power of two",
                self.frame_count
            );
        }
        if self.frame_size < 2048 {
            anyhow::bail!("frame_size must be >= 2048 bytes");
        }
        if self.ring_size > self.frame_count {
            anyhow::bail!(
                "ring_size {} must be <= frame_count {}",
                self.ring_size,
                self.frame_count
            );
        }
        Ok(())
    }

    /// Total UMEM size in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.frame_count as u64 * self.frame_size as u64
    }
}

// ---------------------------------------------------------------------------
// UMEM region
// ---------------------------------------------------------------------------

/// A pre-allocated UMEM region with its frame descriptors.
///
/// On Linux this is backed by an actual AF_XDP UMEM. On non-Linux platforms
/// this is a stub that documents the expected API surface.
pub struct Umem {
    pub config: UmemConfig,

    /// Base address of the UMEM memory region (Linux only).
    #[cfg(target_os = "linux")]
    base_addr: *mut std::ffi::c_void,

    /// Size of the mapped UMEM region in bytes.
    #[cfg(target_os = "linux")]
    region_size: usize,

    /// File descriptor of the AF_XDP UMEM (Linux only).
    #[cfg(target_os = "linux")]
    fd: std::os::unix::io::RawFd,
}

impl Umem {
    /// Create a new UMEM with the given configuration.
    ///
    /// On Linux this:
    ///   1. Validates the config
    ///   2. Allocates memory (huge pages if configured)
    ///   3. Creates the AF_XDP UMEM via XDP_UMEM_REG setsockopt
    ///   4. Returns the ready-to-use UMEM
    pub fn new(config: UmemConfig) -> Result<Self> {
        config.validate()?;

        #[cfg(target_os = "linux")]
        {
            let region_size = (config.frame_count as usize) * (config.frame_size as usize);

            // Allocate the backing memory.
            let base_addr = if config.use_huge_pages {
                Self::allocate_huge_pages(region_size)
                    .context("failed to allocate huge pages for UMEM")?
            } else {
                Self::allocate_locked_memory(region_size)
                    .context("failed to allocate locked memory for UMEM")?
            };

            // Create the AF_XDP UMEM via setsockopt XDP_UMEM_REG.
            // This registers the memory region with the kernel's XDP subsystem.
            let fd = Self::create_umem_fd(&config, base_addr, region_size)
                .context("failed to create AF_XDP UMEM")?;

            Ok(Umem {
                config,
                base_addr,
                region_size,
                fd,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!(
                "AF_XDP UMEM requires Linux kernel 5.4+. \
                 Configured for {} frames of {} bytes ({} MB total). \
                 Will be functional when deployed on bare-metal Linux with XDP driver support.",
                config.frame_count,
                config.frame_size,
                config.total_bytes() / (1024 * 1024),
            );
        }
    }

    /// Allocate huge pages for the UMEM backing store.
    /// On Linux this uses mmap with MAP_HUGETLB.
    #[cfg(target_os = "linux")]
    fn allocate_huge_pages(size: usize) -> io::Result<*mut std::ffi::c_void> {
        use std::ptr;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE
            | libc::MAP_ANONYMOUS
            | libc::MAP_HUGETLB
            | libc::MAP_POPULATE;

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                prot,
                flags,
                -1, // fd (anonymous)
                0,  // offset
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Lock the memory to prevent swapping (required for AF_XDP).
        unsafe {
            libc::mlock(ptr, size);
        }

        Ok(ptr)
    }

    /// Allocate regular memory and lock it (no swapping allowed for AF_XDP).
    #[cfg(target_os = "linux")]
    fn allocate_locked_memory(size: usize) -> io::Result<*mut std::ffi::c_void> {
        use std::ptr;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE;

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                prot,
                flags,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Lock pages: AF_XDP requires mlock'd memory.
        unsafe {
            libc::mlock(ptr, size);
        }

        Ok(ptr)
    }

    /// Register the memory region with the kernel XDP subsystem.
    /// Uses setsockopt XDP_UMEM_REG with the UMEM registration struct.
    #[cfg(target_os = "linux")]
    fn create_umem_fd(
        config: &UmemConfig,
        addr: *mut std::ffi::c_void,
        size: usize,
    ) -> io::Result<std::os::unix::io::RawFd> {
        // The actual XDP_UMEM_REG setsockopt requires a socket of AF_XDP family.
        // We create one, register the UMEM, and return the UMEM fd.
        // This fd is then passed to XDP socket creation.
        //
        // AF_XDP socket creation sequence:
        //   socket(AF_XDP, SOCK_RAW, 0) -> xsk_fd
        //   setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg))
        //
        // The xsk_fd becomes the UMEM handle and is shared across multiple
        // XDP sockets on the same UMEM.

        // AF_XDP = 44 on modern kernels
        const AF_XDP: libc::c_int = 44;
        const SOCK_RAW: libc::c_int = 3;

        let fd = unsafe { libc::socket(AF_XDP, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // XDP_UMEM_REG struct (from linux/if_xdp.h):
        // struct xdp_umem_reg {
        //     __u64 addr;       // start of packet data area
        //     __u64 len;        // length of packet data area
        //     __u32 chunk_size; // frame size
        //     __u32 headroom;   // headroom before packet data
        //     __u32 flags;      // XDP_UMEM_UNALIGNED_CHUNK_FLAG
        // };
        //
        // SOL_XDP = 283, XDP_UMEM_REG = 1

        const SOL_XDP: libc::c_int = 283;
        const XDP_UMEM_REG: libc::c_int = 1;

        #[repr(C)]
        struct XdpUmemReg {
            addr: u64,
            len: u64,
            chunk_size: u32,
            headroom: u32,
            flags: u32,
        }

        let reg = XdpUmemReg {
            addr: addr as u64,
            len: size as u64,
            chunk_size: config.frame_size,
            headroom: config.headroom,
            flags: 0,
        };

        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as u32,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        Ok(fd)
    }

    /// Returns the raw file descriptor for this UMEM (Linux only).
    #[cfg(target_os = "linux")]
    pub fn raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd
    }

    /// Frame address for the given frame index.
    /// Returns the pointer to the start of the frame data (after headroom).
    #[cfg(target_os = "linux")]
    pub fn frame_addr(&self, frame_idx: u32) -> *mut std::ffi::c_void {
        let offset = frame_idx as usize * self.config.frame_size as usize;
        let headroom = self.config.headroom as usize;
        unsafe { self.base_addr.add(offset + headroom) }
    }

    /// Total number of frames in this UMEM.
    pub fn frame_count(&self) -> u32 {
        self.config.frame_count
    }

    /// Frame size in bytes.
    pub fn frame_size(&self) -> u32 {
        self.config.frame_size
    }

    /// Total UMEM size in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.config.total_bytes()
    }
}

// ---------------------------------------------------------------------------
// Drop — clean up UMEM resources
// ---------------------------------------------------------------------------

impl Drop for Umem {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                libc::close(self.fd);
                libc::munmap(self.base_addr, self.region_size);
            }
        }
    }
}

// Safety: UMEM memory is owned and not shared across threads without
// synchronization. The pointers are only accessed through the AF_XDP
// socket which is itself not Send/Sync.
unsafe impl Send for Umem {}
unsafe impl Sync for Umem {}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns the next power-of-two frame count >= the given value.
/// Caps at MAX_FRAME_COUNT.
pub fn next_power_of_two_frames(n: u32) -> u32 {
    if n <= MIN_FRAME_COUNT {
        return MIN_FRAME_COUNT;
    }
    let mut v = n.next_power_of_two();
    if v > MAX_FRAME_COUNT {
        v = MAX_FRAME_COUNT;
    }
    v
}
