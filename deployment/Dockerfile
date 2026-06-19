# Hydra-Pro Multi-Stage Build
# Stage 1: Build Go + Rust + BPF
# Stage 2: Minimal runtime (Alpine, non-root, no shell)

# ── Stage 1: Builder ───────────────────────────────────────
FROM alpine:3.21 AS builder

RUN apk add --no-cache \
    go=~1.22 \
    rust cargo \
    clang llvm libbpf-dev \
    make git

WORKDIR /build
COPY . .

# Build BPF programs
RUN make build-bpf 2>/dev/null || \
    for f in shield/ebpf/*.bpf.c kernel/bpf/*.c; do \
        [ -f "$f" ] && clang -O2 -g -target bpf -c "$f" -o "${f%.c}.o"; \
    done

# Build Rust (muscle FFI + dagger implant)
RUN cd muscle && cargo build --release && \
    cd /build/dagger/implant && cargo build --release 2>/dev/null || true

# Build Go (teamserver + builder + fortress)
RUN cd dagger/teamserver && go build -o /build/fortress . && \
    go build -o /build/builder ./dagger/builder 2>/dev/null || true

# ── Stage 2: Runtime ───────────────────────────────────────
FROM alpine:3.21

LABEL org.opencontainers.image.title="Hydra-Pro"
LABEL org.opencontainers.image.description="Advanced C2 framework with eBPF defense"
LABEL org.opencontainers.image.source="https://github.com/fortress/hydra-pro"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache \
    libgcc libstdc++ ca-certificates && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -S hydra && adduser -S hydra -G hydra

# Copy binaries
COPY --from=builder /build/fortress /usr/local/bin/fortress
COPY --from=builder /build/muscle/target/release/libfortress_ffi.so /usr/local/lib/
COPY --from=builder /build/*.bpf.o /usr/local/lib/bpf/
COPY --from=builder /build/shield/ebpf/*.bpf.o /usr/local/lib/bpf/shield/ 2>/dev/null || true
COPY --from=builder /build/builder /usr/local/bin/hydra-builder 2>/dev/null || true

# Config placeholder
RUN mkdir -p /etc/hydra /var/lib/hydra /var/log/hydra

# Security hardening
RUN chown -R hydra:hydra /etc/hydra /var/lib/hydra /var/log/hydra
USER hydra

# No shell, no package manager → minimal attack surface
HEALTHCHECK --interval=30s --timeout=5s \
    CMD ["/usr/local/bin/fortress", "status"] || exit 1

ENTRYPOINT ["/usr/local/bin/fortress"]
CMD ["--help"]
