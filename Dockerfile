# Fortress V6 — OCI Container Image
# Build: docker build -t fortress-v6 .
# Run:   docker run --privileged --network host -v /sys/fs/bpf:/sys/fs/bpf fortress-v6 defend

FROM alpine:3.21

LABEL org.fortress.version="6.0.0"
LABEL org.fortress.description="National-grade autonomous network defense system"

# Install runtime dependencies
RUN apk add --no-cache \
    libgcc libstdc++ \
    nmap nmap-scripts \
    hydra \
    whois \
    iptables nftables \
    ca-certificates

# Install nuclei (Go binary)
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip \
    -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Copy Fortress binaries
COPY fortress /usr/local/bin/fortress
COPY muscle/target/release/libfortress_ffi.so /usr/local/lib/
COPY kernel/bpf/xdp_filter.o /usr/local/lib/bpf/
COPY kernel/bpf/tc_egress.o /usr/local/lib/bpf/
COPY fortress.yaml /etc/fortress/fortress.yaml

# Create runtime directories
RUN mkdir -p /var/log/fortress /var/lib/fortress /etc/fortress/rules.d

# Update ld cache
RUN ldconfig /usr/local/lib

ENTRYPOINT ["/usr/local/bin/fortress"]
CMD ["--mode", "defend", "--config", "/etc/fortress/fortress.yaml"]
