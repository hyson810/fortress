//go:build linux
// +build linux

package loader

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
)

// Embedded compiled eBPF bytecode objects.
//
// Build steps (run from repository root):
//   clang -O2 -g -target bpf \
//       -I/usr/include/x86_64-linux-gnu \
//       -c kernel/bpf/xdp_filter.c -o kernel/loader/xdp_filter.o
//   clang -O2 -g -target bpf \
//       -I/usr/include/x86_64-linux-gnu \
//       -c kernel/bpf/tc_egress.c -o kernel/loader/tc_egress.o
//
//go:embed xdp_filter.o
var xdpBytes []byte

//go:embed tc_egress.o
var tcBytes []byte

// ebpfBytecodeReader returns a reader for the combined eBPF collection.
// Since programs and maps are in separate .o files, we merge the
// CollectionSpecs before loading.
func ebpfBytecodeReader() (*ebpf.CollectionSpec, error) {
	specXDP, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpBytes))
	if err != nil {
		return nil, fmt.Errorf("parse xdp_filter.o: %w", err)
	}
	specTC, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcBytes))
	if err != nil {
		return nil, fmt.Errorf("parse tc_egress.o: %w", err)
	}

	// Merge TC programs and maps into the XDP spec.
	for name, prog := range specTC.Programs {
		if _, exists := specXDP.Programs[name]; exists {
			return nil, fmt.Errorf("duplicate program %q in merged specs", name)
		}
		specXDP.Programs[name] = prog
	}
	for name, m := range specTC.Maps {
		if _, exists := specXDP.Maps[name]; exists {
			return nil, fmt.Errorf("duplicate map %q in merged specs", name)
		}
		specXDP.Maps[name] = m
	}

	return specXDP, nil
}
