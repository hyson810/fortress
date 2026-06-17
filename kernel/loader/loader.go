//go:build linux
// +build linux

/*
Package loader compiles, loads, and manages eBPF programs for the Fortress
network defense system.  It attaches XDP for ingress filtering and TC for
egress monitoring.

Requires Linux kernel 5.4+ with CONFIG_DEBUG_INFO_BTF=y for CO-RE.
Uses cilium/ebpf v0.14+.
*/
package loader

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// EBpfEngine
// ---------------------------------------------------------------------------

// EBpfEngine manages the lifecycle of the XDP and TC eBPF programs attached
// to a network interface.
type EBpfEngine struct {
	iface string

	xdpProg *ebpf.Program
	tcProg  *ebpf.Program
	xdpLink link.Link
	tcLink  link.Link

	maps *ebpfMaps

	alertReader   *perf.Reader
	alertCh       chan EgressAlert
	alertOnce     sync.Once
	droppedAlerts atomic.Uint64
}

// ebpfMaps holds references to all BPF maps used by the engine.
type ebpfMaps struct {
	BlockedIPs   *ebpf.Map
	RateLimit    *ebpf.Map
	Stats        *ebpf.Map
	EgressStats  *ebpf.Map
	EgressAlerts *ebpf.Map
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

// NewEBpfEngine loads the XDP and TC eBPF programs from embedded bytecode
// and attaches them to the named network interface.
func NewEBpfEngine(iface string) (*EBpfEngine, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface name must not be empty")
	}

	// Load the pre‑compiled eBPF collection from embedded .o bytecode.
	spec, err := ebpfBytecodeReader()
	if err != nil {
		return nil, fmt.Errorf("ebpf: parse collection spec: %w", err)
	}

	objs := loadedObjs{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: load programs and maps: %w", err)
	}

	// Resolve interface index once.
	ifaceIdx := ifaceToIndex(iface)
	if ifaceIdx == 0 {
		objs.CloseAll()
		return nil, fmt.Errorf("ebpf: interface %q not found", iface)
	}

	// Attach XDP (generic mode as safe default; use XDPDriverMode in prod).
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilter,
		Interface: ifaceIdx,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		objs.CloseAll()
		return nil, fmt.Errorf("ebpf: attach XDP to %s: %w", iface, err)
	}

	// Attach TC egress via clsact qdisc + bpf filter.
	tcLink, err := attachTCEgress(ifaceIdx, objs.TcEgress)
	if err != nil {
		xdpLink.Close()
		objs.CloseAll()
		return nil, fmt.Errorf("ebpf: attach TC egress to %s: %w", iface, err)
	}

	eng := &EBpfEngine{
		iface:   iface,
		xdpProg: objs.XdpFilter,
		tcProg:  objs.TcEgress,
		xdpLink: xdpLink,
		tcLink:  tcLink,
		maps: &ebpfMaps{
			BlockedIPs:   objs.BlockedIPs,
			RateLimit:    objs.RateLimit,
			Stats:        objs.Stats,
			EgressStats:  objs.EgressStats,
			EgressAlerts: objs.EgressAlerts,
		},
		alertCh: make(chan EgressAlert, 256),
	}

	return eng, nil
}

// ---------------------------------------------------------------------------
// Blocking / unblocking
// ---------------------------------------------------------------------------

// BlockIP adds an IPv4 address to the blocked_ips map.  All ingress packets
// from this IP will be dropped at the XDP layer.
func (e *EBpfEngine) BlockIP(ip string) error {
	key, err := ipToUint32(ip)
	if err != nil {
		return fmt.Errorf("BlockIP: %w", err)
	}
	val := uint8(1)
	return e.maps.BlockedIPs.Put(&key, &val)
}

// UnblockIP removes an IPv4 address from the blocked_ips map.
func (e *EBpfEngine) UnblockIP(ip string) error {
	key, err := ipToUint32(ip)
	if err != nil {
		return fmt.Errorf("UnblockIP: %w", err)
	}
	return e.maps.BlockedIPs.Delete(&key)
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

// SetRateLimit sets the current token count for the given IP in the
// rate_limit map.  The typical call pattern is a userspace goroutine that
// periodically refills tokens (e.g. 10 tokens/sec, capped at 100).
func (e *EBpfEngine) SetRateLimit(ip string, tokens uint32) error {
	key, err := ipToUint32(ip)
	if err != nil {
		return fmt.Errorf("SetRateLimit: %w", err)
	}
	return e.maps.RateLimit.Put(&key, &tokens)
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

// GetStats reads the per‑CPU stats map and returns the aggregated XDP
// counters.  Each per-CPU slot is summed across all online CPUs.
func (e *EBpfEngine) GetStats() (*XDPStats, error) {
	var (
		keyLen  uint32 = 0  // passed
		keyDrop uint32 = 1  // dropped
		keyRL   uint32 = 2  // rate_limited
		stats   XDPStats
	)

	// Per-CPU values: cilium/ebpf Lookup with a value larger than the map
	// value returns all CPUs' values concatenated.  For a per-CPU array
	// with uint64 values, the result is []uint64 with one slot per CPU.
	if err := sumPerCPUVal(e.maps.Stats, &keyLen, &stats.Passed); err != nil {
		return nil, fmt.Errorf("GetStats: passed counter: %w", err)
	}
	if err := sumPerCPUVal(e.maps.Stats, &keyDrop, &stats.Dropped); err != nil {
		return nil, fmt.Errorf("GetStats: dropped counter: %w", err)
	}
	if err := sumPerCPUVal(e.maps.Stats, &keyRL, &stats.RateLimited); err != nil {
		return nil, fmt.Errorf("GetStats: rate_limited counter: %w", err)
	}

	return &stats, nil
}

// sumPerCPUVal reads a per-CPU uint64 value and sums across all CPUs.
func sumPerCPUVal(m *ebpf.Map, key *uint32, total *uint64) error {
	vals := make([]uint64, ebpf.MustPossibleCPU())
	if err := m.Lookup(key, &vals); err != nil {
		return err
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	*total = sum
	return nil
}

// ---------------------------------------------------------------------------
// Egress alerts (perf ring)
// ---------------------------------------------------------------------------

// EgressAlerts returns a read‑only channel of exfiltration alerts from the
// TC egress program.  Callers should start consuming this channel before
// significant traffic begins.
func (e *EBpfEngine) EgressAlerts() <-chan EgressAlert {
	e.alertOnce.Do(func() {
		var err error
		e.alertReader, err = perf.NewReader(e.maps.EgressAlerts, osPageSize*64)
		if err != nil {
			close(e.alertCh)
			return
		}
		go e.pollAlerts()
	})
	return e.alertCh
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

// Close detaches all eBPF programs, closes the perf reader, and releases
// all maps.  After Close the engine must not be reused.
func (e *EBpfEngine) Close() error {
	var errs []error

	// Perf reader must be closed first so pollAlerts exits cleanly.
	if e.alertReader != nil {
		if err := e.alertReader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("alert reader: %w", err))
		}
	}
	if e.tcLink != nil {
		if err := e.tcLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tc link: %w", err))
		}
	}
	if e.xdpLink != nil {
		if err := e.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("xdp link: %w", err))
		}
	}
	if e.xdpProg != nil {
		if err := e.xdpProg.Close(); err != nil {
			errs = append(errs, fmt.Errorf("xdp prog: %w", err))
		}
	}
	if e.tcProg != nil {
		if err := e.tcProg.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tc prog: %w", err))
		}
	}
	if e.maps != nil {
		for _, m := range []struct {
			name string
			ptr  *ebpf.Map
		}{
			{"blocked_ips", e.maps.BlockedIPs},
			{"rate_limit", e.maps.RateLimit},
			{"stats", e.maps.Stats},
			{"egress_stats", e.maps.EgressStats},
			{"egress_alerts", e.maps.EgressAlerts},
		} {
			if m.ptr != nil {
				if err := m.ptr.Close(); err != nil {
					errs = append(errs, fmt.Errorf("map %s: %w", m.name, err))
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Close: %v", errs)
	}
	return nil
}

// loadedObjs holds the result of LoadAndAssign for the combined eBPF
// collection.  Its CloseAll method is used for cleanup on error paths.
type loadedObjs struct {
	XdpFilter    *ebpf.Program `ebpf:"xdp_filter"`
	TcEgress     *ebpf.Program `ebpf:"tc_egress"`
	BlockedIPs   *ebpf.Map     `ebpf:"blocked_ips"`
	RateLimit    *ebpf.Map     `ebpf:"rate_limit"`
	Stats        *ebpf.Map     `ebpf:"stats"`
	EgressStats  *ebpf.Map     `ebpf:"egress_stats"`
	EgressAlerts *ebpf.Map     `ebpf:"egress_alerts"`
}

func (o *loadedObjs) CloseAll() {
	if o.XdpFilter != nil {
		o.XdpFilter.Close()
	}
	if o.TcEgress != nil {
		o.TcEgress.Close()
	}
	if o.BlockedIPs != nil {
		o.BlockedIPs.Close()
	}
	if o.RateLimit != nil {
		o.RateLimit.Close()
	}
	if o.Stats != nil {
		o.Stats.Close()
	}
	if o.EgressStats != nil {
		o.EgressStats.Close()
	}
	if o.EgressAlerts != nil {
		o.EgressAlerts.Close()
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// ipToUint32 converts an IPv4 string to a uint32 in network byte order,
// suitable for use as a BPF map key.
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %q", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %q", ipStr)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

// ifaceToIndex returns the kernel interface index for the named interface,
// or 0 if the interface does not exist.
func ifaceToIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return iface.Index
}

// attachTCEgress attaches the TC egress BPF program via TCX
// (cilium/ebpf v0.17+, kernel 6.6+).
func attachTCEgress(ifaceIdx int, prog *ebpf.Program) (link.Link, error) {
	return link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Interface: ifaceIdx,
		Attach:    ebpf.AttachTCXEgress,
	})
}

// pollAlerts reads from the perf ring buffer and forwards decoded alerts
// onto the alert channel.  It blocks until the reader is closed.
func (e *EBpfEngine) pollAlerts() {
	defer close(e.alertCh)

	var alert EgressAlert
	for {
		record, err := e.alertReader.Read()
		if err != nil {
			log.Printf("[ebpf] perf reader error on %s: %v — closing alert channel", e.iface, err)
			return
		}
		if len(record.RawSample) < 16 {
			continue
		}
		alert.DestIP = binary.LittleEndian.Uint32(record.RawSample[0:4])
		alert.ByteCount = binary.LittleEndian.Uint64(record.RawSample[4:12])
		alert.Timestamp = binary.LittleEndian.Uint64(record.RawSample[12:20])
		select {
		case e.alertCh <- alert:
		default:
			// Drop alert if channel is full to avoid backing up the ring buffer.
			n := e.droppedAlerts.Add(1)
			if n%1000 == 0 {
				log.Printf("[ebpf] dropped %d egress alerts — channel full", n)
			}
		}
	}
}

// DroppedAlerts returns the number of egress alerts dropped due to a full
// channel since the engine started.
func (e *EBpfEngine) DroppedAlerts() uint64 {
	return e.droppedAlerts.Load()
}

// osPageSize is the memory page size used for perf ring buffer sizing.
var osPageSize = unix.Getpagesize()
