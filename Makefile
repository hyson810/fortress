.PHONY: all build build-rust build-bpf build-go test clean

CARGO = cargo
CLANG = clang
GO = go
BPF_DIR = kernel/bpf
MUSCLE_DIR = muscle
TARGET_DIR = target
BIN = fortress

all: build-bpf build-rust build-go

build-bpf:
	$(CLANG) -O2 -g -target bpf -I/usr/include \
		-c $(BPF_DIR)/xdp_filter.c -o $(BPF_DIR)/xdp_filter.o
	$(CLANG) -O2 -g -target bpf -I/usr/include \
		-c $(BPF_DIR)/tc_egress.c -o $(BPF_DIR)/tc_egress.o
	@echo "BPF bytecode compiled"

build-rust:
	cd $(MUSCLE_DIR) && $(CARGO) build --release
	@echo "Rust muscle built"

build-go:
	$(GO) build -o $(BIN) ./cmd/fortress/
	@echo "Go brain built"

build:
	$(MAKE) build-bpf
	$(MAKE) build-rust
	$(MAKE) build-go

test:
	cd $(MUSCLE_DIR) && $(CARGO) test
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

bench:
	$(GO) test -bench=. ./... -benchmem

clean:
	rm -f $(BIN)
	rm -f $(BPF_DIR)/*.o
	cd $(MUSCLE_DIR) && $(CARGO) clean
	@echo "Cleaned"

verify: build test vet
	@echo "=== Fortress V6 Build Complete ==="
	@echo "Binary: $(BIN)"
	@echo "Rust .so: $(MUSCLE_DIR)/target/release/libfortress_ffi.so"
	@echo "BPF: $(BPF_DIR)/xdp_filter.o $(BPF_DIR)/tc_egress.o"
	@ls -la $(BIN) 2>/dev/null || echo "(Go binary not on this platform)"
	@ls -la $(MUSCLE_DIR)/target/release/libfortress_ffi.so
	@ls -la $(BPF_DIR)/*.o
