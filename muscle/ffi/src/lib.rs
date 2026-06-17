mod ringbuf;

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RINGBUF: Mutex<Option<ringbuf::RingBuf>> = Mutex::new(None);

/// PacketContext must match the Go struct EXACTLY.
/// Go definition in internal/engine/types.go:
///   type PacketContext struct {
///       Timestamp   int64   // unix nano
///       SrcIP       [16]byte // IP bytes, IPv4 in last 4
///       DstIP       [16]byte
///       SrcPort     uint16
///       DstPort     uint16
///       Protocol    [8]byte  // "TCP\0\0\0\0\0"
///       TCPFlags    [8]byte  // "S\0\0\0\0\0\0\0"
///       PayloadSize uint16
///       PayloadHash uint64
///       Direction   [8]byte  // "ingress\0" or "egress\0\0"
///   }
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketContext {
    pub timestamp: i64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: [u8; 8],
    pub tcp_flags: [u8; 8],
    pub payload_size: u16,
    pub payload_hash: u64,
    pub direction: [u8; 8],
    _pad: [u8; 6], // padding to 80 bytes
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FortressStats {
    pub packets_received: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub packets_rate_limited: u64,
    pub ringbuf_writes: u64,
    pub ringbuf_overflows: u64,
}

static STATS: Mutex<FortressStats> = Mutex::new(FortressStats {
    packets_received: 0, packets_passed: 0, packets_dropped: 0,
    packets_rate_limited: 0, ringbuf_writes: 0, ringbuf_overflows: 0,
});

fn ip_to_bytes(ip_str: &str) -> [u8; 16] {
    let mut buf = [0u8; 16];
    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
        buf[12..16].copy_from_slice(&ip.octets());
    } else if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
        buf.copy_from_slice(&ip.octets());
    }
    buf
}

fn str_to_8(s: &str) -> [u8; 8] {
    let mut buf = [0u8; 8];
    let bytes = s.as_bytes();
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Initialize the Fortress muscle engine.
/// iface_name: network interface to attach XDP (e.g. "eth0", "wlan0")
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn fortress_init(iface_name: *const c_char) -> i32 {
    if INITIALIZED.load(Ordering::Acquire) {
        return -1;
    }
    let _iface = unsafe { CStr::from_ptr(iface_name) }.to_string_lossy();

    let rb = ringbuf::RingBuf::new(1024);
    *RINGBUF.lock().unwrap() = Some(rb);

    INITIALIZED.store(true, Ordering::Release);
    eprintln!("[fortress-ffi] initialized on interface: {}", _iface);
    0
}

/// Poll for new packets. Returns the number of packets available for reading.
/// In production, this polls AF_XDP. Currently returns 0 (simulation).
#[no_mangle]
pub extern "C" fn fortress_poll() -> i32 {
    if !INITIALIZED.load(Ordering::Acquire) { return -1; }
    0
}

/// Read one PacketContext from the ring buffer.
/// Returns bytes written to buf (0..80), or -1 on error/empty.
#[no_mangle]
pub extern "C" fn fortress_read(buf: *mut u8, max: i32) -> i32 {
    if !INITIALIZED.load(Ordering::Acquire) { return -1; }
    if max < 80 { return -1; }

    let mut rb = RINGBUF.lock().unwrap();
    if let Some(ref mut rb) = *rb {
        if let Some(pkt) = rb.pop() {
            unsafe {
                std::ptr::copy_nonoverlapping(&pkt as *const PacketContext as *const u8, buf, 80);
            }
            return 80;
        }
    }
    0
}

/// Push a simulated packet into the ring buffer (for testing without AF_XDP).
#[no_mangle]
pub extern "C" fn fortress_inject_packet(
    src_ip_c: *const c_char, dst_ip_c: *const c_char,
    src_port: u16, dst_port: u16, protocol_c: *const c_char,
    tcp_flags_c: *const c_char, payload_size: u16,
) -> i32 {
    if !INITIALIZED.load(Ordering::Acquire) { return -1; }

    let src_ip = unsafe { CStr::from_ptr(src_ip_c) }.to_string_lossy();
    let dst_ip = unsafe { CStr::from_ptr(dst_ip_c) }.to_string_lossy();
    let protocol = unsafe { CStr::from_ptr(protocol_c) }.to_string_lossy();
    let tcp_flags = unsafe { CStr::from_ptr(tcp_flags_c) }.to_string_lossy();

    let pkt = PacketContext {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64,
        src_ip: ip_to_bytes(&src_ip),
        dst_ip: ip_to_bytes(&dst_ip),
        src_port, dst_port,
        protocol: str_to_8(&protocol),
        tcp_flags: str_to_8(if tcp_flags.is_empty() { "\0" } else { &tcp_flags }),
        payload_size,
        payload_hash: 0,
        direction: str_to_8("ingress"),
        _pad: [0u8; 6],
    };

    let mut rb = RINGBUF.lock().unwrap();
    if let Some(ref mut rb) = *rb {
        rb.push(pkt);
        let mut s = STATS.lock().unwrap();
        s.packets_received += 1;
        s.ringbuf_writes += 1;
    }
    0
}

/// Get engine statistics.
#[no_mangle]
pub extern "C" fn fortress_stats() -> FortressStats {
    *STATS.lock().unwrap()
}

/// Block an IPv4 address at the XDP level.
#[no_mangle]
pub extern "C" fn fortress_block_ip(ip: u32) -> i32 {
    if !INITIALIZED.load(Ordering::Acquire) { return -1; }
    // TODO: BPF map write (Plan B3)
    eprintln!("[fortress-ffi] block_ip: {:x}", ip);
    0
}

/// Shutdown the engine, detach BPF programs, free resources.
#[no_mangle]
pub extern "C" fn fortress_close() -> i32 {
    INITIALIZED.store(false, Ordering::Release);
    *RINGBUF.lock().unwrap() = None;
    eprintln!("[fortress-ffi] shutdown complete");
    0
}
