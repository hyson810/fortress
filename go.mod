module github.com/fortress/v6

go 1.22

require (
	github.com/cilium/ebpf v0.17.3
	golang.org/x/crypto v0.24.0
	golang.org/x/sys v0.30.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/google/gopacket v1.1.19

replace github.com/fortress/hydra-pro/shield/bpf_lsm => ./shield/bpf_lsm

replace github.com/fortress/hydra-pro/shield/memory => ./shield/memory

replace github.com/fortress/hydra-pro/shield/ftrace => ./shield/ftrace

replace github.com/fortress/hydra-pro/shield/io_uring => ./shield/io_uring
