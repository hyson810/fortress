# Fortress V6 Plan B: Rust 肌肉 + C 匕首

> **For agentic workers:** Use superpowers:subagent-driven-development.

**Goal:** Build the Rust muscle layer — AF_XDP zero-copy packet capture, protocol parsing, eBPF management, and C ABI bridge to Go brain. Plus C eBPF kernel programs.

**Architecture:** Rust library `libmuscle.so` exposes C ABI via `extern "C"`. Go brain loads it at startup via cgo. Communication via lock-free SPSC ring buffer in shared memory. eBPF programs compiled with clang, loaded by Rust via aya-rs.

**Tech Stack:** Rust 1.83+, aya-rs, clang 19, libbpf, Go cgo

**Dependencies:** Plan A (Go brain) must be complete. The `PacketContext` type in `internal/engine/types.go` is the shared ABI between Rust and Go.

---

## File Structure

```
fortress-v6/
├── muscle/                          # Rust workspace
│   ├── Cargo.toml                   # Workspace root
│   ├── afxdp/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── socket.rs            # AF_XDP socket lifecycle
│   │       ├── umem.rs              # UMEM huge page management
│   │       └── dispatcher.rs        # CPU-pinned batch dispatch
│   ├── protocol/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── parser.rs            # L2/L3/L4 header parser
│   │       ├── tls.rs               # TLS ClientHello → JA3
│   │       └── dns.rs               # DNS message parser
│   ├── ebpfmgmt/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── loader.rs            # aya-rs BPF loader
│   │       └── maps.rs              # BPF map read/write
│   └── ffi/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs               # extern "C" entry points
│           └── ringbuf.rs           # SPSC lock-free ring buffer
├── kernel/bpf/
│   ├── xdp_filter.c                 # XDP ingress filter
│   ├── tc_egress.c                  # TC egress monitor
│   └── vmlinux.h                    # BPF CO-RE header
└── cmd/fortress/
    └── main.go                      # Updated: load libmuscle.so at startup
```

---

### Task B1: Rust Workspace + FFI Ring Buffer

**Files:**
- Create: `muscle/Cargo.toml`
- Create: `muscle/ffi/Cargo.toml`
- Create: `muscle/ffi/src/lib.rs`
- Create: `muscle/ffi/src/ringbuf.rs`

Build the Rust workspace skeleton and the FFI bridge layer. The ring buffer is a lock-free SPSC (single producer, single consumer) shared memory region. Rust writes parsed packets, Go reads them.

The `extern "C"` API:
- `fortress_init(iface_name: *const c_char) -> i32` — init AF_XDP on interface
- `fortress_poll() -> i32` — poll for new packets, returns count available
- `fortress_read(buf: *mut u8, max: i32) -> i32` — read next packet context
- `fortress_stats() -> FortressStats` — get counters
- `fortress_block_ip(ip: u32) -> i32` — add IP to XDP blocklist
- `fortress_close() -> i32` — shutdown

The `PacketContext` struct must match the Go definition exactly (field order, types, alignment).

### Task B2: C eBPF Kernel Programs

**Files:**
- Create: `kernel/bpf/xdp_filter.c`
- Create: `kernel/bpf/tc_egress.c`
- Create: `kernel/bpf/vmlinux.h` (generated via `bpftool btf dump`)

XDP filter: whitelist LPM trie → blacklist LRU hash → rate limit token bucket → redirect sample to AF_XDP.
TC egress: per-destination byte/packet counters → 1MiB/60s threshold → perf event alert.

Compile with clang: `clang -O2 -g -target bpf -c xdp_filter.c -o xdp_filter.o`

### Task B3: Rust eBPF Management

**Files:**
- Create: `muscle/ebpfmgmt/Cargo.toml`
- Create: `muscle/ebpfmgmt/src/lib.rs`
- Create: `muscle/ebpfmgmt/src/loader.rs`
- Create: `muscle/ebpfmgmt/src/maps.rs`

Use aya-rs to:
- Load compiled BPF bytecode
- Create and pin BPF maps
- Attach XDP program to interface
- Attach TC egress program
- Provide Rust API for map read/write (block/unblock IP, get stats)

### Task B4: Rust Protocol Parsers

**Files:**
- Create: `muscle/protocol/Cargo.toml`
- Create: `muscle/protocol/src/lib.rs`
- Create: `muscle/protocol/src/parser.rs`
- Create: `muscle/protocol/src/tls.rs`
- Create: `muscle/protocol/src/dns.rs`

Zero-copy protocol parsing (no heap allocation for headers):
- L2: Ethernet, VLAN
- L3: IPv4, IPv6
- L4: TCP, UDP, ICMP
- TLS: ClientHello field extraction (version, cipher suites, extensions) → JA3 MD5
- DNS: query name, type, entropy

### Task B5: AF_XDP Socket + UMEM

**Files:**
- Create: `muscle/afxdp/Cargo.toml`
- Create: `muscle/afxdp/src/lib.rs`
- Create: `muscle/afxdp/src/socket.rs`
- Create: `muscle/afxdp/src/umem.rs`
- Create: `muscle/afxdp/src/dispatcher.rs`

- Create AF_XDP socket bound to network interface queue
- Allocate UMEM region (huge pages, shared with kernel)
- Set up Fill/Completion/RX/TX rings
- CPU-pin dispatcher goroutine (via core_affinity)
- Batch read 64 packets per poll()
- Parse each packet via protocol module
- Write PacketContext to FFI ring buffer

### Task B6: cgo Integration + Main Update

**Files:**
- Modify: `cmd/fortress/main.go`
- Create: `muscle/ffi/bridge.h`

Go side:
- `// #cgo LDFLAGS: -L../target/release -lmuscle`
- `// #include "bridge.h"`
- At startup: `C.fortress_init(cIfname)`
- Background goroutine: poll `C.fortress_read()` in a loop
- Feed parsed packets into the Go detection pipeline (replace simulation loop)

### Task B7: Build System + Integration Test

Create Makefile:
```makefile
build:
	cargo build --release --manifest-path muscle/Cargo.toml
	clang -O2 -g -target bpf -I/usr/include -c kernel/bpf/xdp_filter.c -o kernel/bpf/xdp_filter.o
	clang -O2 -g -target bpf -I/usr/include -c kernel/bpf/tc_egress.c -o kernel/bpf/tc_egress.o
	go build -o fortress ./cmd/fortress/
```

Integration test: start Go brain with Rust FFI loaded, verify ring buffer communication.

---

## Execution Order

B1 (workspace + ringbuf) → B2 (C BPF) ‖ B3 (ebpf mgmt) → B4 (protocol) → B5 (AF_XDP) → B6 (cgo) → B7 (build)
