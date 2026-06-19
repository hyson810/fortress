# Hydra-Pro Operations Runbook

## Quick Start

```bash
# Clone and build
git clone https://github.com/fortress/hydra-pro && cd hydra-pro
make all

# Generate keys
./fortress keygen --output server.key

# Start production stack
docker compose -f deployment/docker-compose.prod.yml up -d

# Verify
./fortress status
curl -k https://localhost/health
```

## Architecture

```
                    ┌──────────────┐
  Operator ─────────┤  Teamserver  │──────────┐
  (CLI/API)         │  :443/:8443  │          │
                    └──────────────┘          │
                                              │ MCP / JSON-RPC
                    ┌──────────────┐          │ (AI流量伪装)
  Implant ──────────┤   Transport  │──────────┘
  (Rust async)      │  HTTPS/DNS/WS│
                    └──────────────┘

                    ┌──────────────┐
  Kernel ───────────┤   Shield     │
  (eBPF XDP/TC)     │  rootkit检测  │
                    │  跨视图验证   │
                    │  BPF LSM     │
                    └──────────────┘
                           │
                    ┌──────▼───────┐
                    │    Brain     │
                    │  评分/决策    │
                    │  蜂群免疫    │
                    └──────────────┘
```

## Health Checks

| Component | Check | Expected |
|-----------|-------|----------|
| Teamserver | `curl -k https://localhost/health` | HTTP 200 "ok" |
| Shield | `fortress status --shield` | eBPF programs loaded |
| Brain | `fortress status --brain` | scoring active |
| Swarm | `fortress status --swarm` | peers connected |

### Alert thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Threat score | >60 | >85 |
| PPS anomaly | Z > 3.0 | Z > 5.0 |
| RWX regions | >3 | >10 |
| Hidden pages | >5 | >20 |
| Unknown BPF programs | >0 | >2 |
| io_uring burst | >20/sec | >50/sec |

## Key Management

### Backup server keys

```bash
# Backup
cp server.key server.key.$(date +%Y%m%d).bak
chmod 600 server.key*

# Restore
cp server.key.YYYYMMDD.bak server.key
chmod 600 server.key
```

### Key rotation

```bash
# Generate new keypair
./fortress keygen --output server.key.new

# Distribute public key to all implants via existing sessions
./fortress key-rotate --key server.key.new

# Swap keys after all implants acknowledge
mv server.key.new server.key
```

## Incident Response

### Compromised implant takedown

```bash
# 1. Identify the compromised session
./fortress sessions list | grep <hostname>

# 2. Send self-destruct task
./fortress task --session <session_id> --type exit

# 3. Rotate server keys (all remaining implants must re-register)
./fortress key-rotate --force

# 4. Update whitelist
shield-bpf-whitelist reload --config whitelist.signed

# 5. Audit for lateral movement
cat /var/log/hydra/audit.log | grep <compromised_ip>
```

### BPF tampering detected

```bash
# If Shield reports rootkit detection:
# 1. Check which BPF programs are loaded
bpftool prog list

# 2. Unload suspicious programs
bpftool prog detach pinned /sys/fs/bpf/suspicious_prog

# 3. Enable strict BPF LSM
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled

# 4. Audit all pinned programs
cat /sys/fs/bpf/* | sha256sum | diff whitelist.hashes -
```

## Log Locations

| Component | Path | Format |
|-----------|------|--------|
| Teamserver | /var/log/hydra/teamserver.log | JSON lines |
| Shield | /var/log/hydra/shield.log | JSON lines |
| Brain | /var/log/hydra/brain.log | JSON lines |
| Audit | /var/log/hydra/audit.log | JSON lines |
| Docker | docker logs fortress | stdout/stderr |

### Sample log entry

```json
{
  "ts": "2026-06-18T16:30:47Z",
  "level": "info",
  "component": "shield",
  "event": "rootkit_detection",
  "finding": {
    "type": "syscall_table_hook",
    "address": "0xffffffffa0000000",
    "expected": "0xffffffff81234567",
    "actual": "0xffffffffc0001234",
    "severity": "critical"
  }
}
```

## Tuning

### Reduce false positives

```yaml
# fortress.yaml
brain:
  scorer:
    scan_threshold: 15        # raise from 10
    anomaly_z_threshold: 4.0  # raise from 3.0
  whitelist:
    auto_trust_days: 7        # extend from 3
    decay_rate: 0.05          # slower decay (was 0.1)
```

### Increase detection sensitivity

```yaml
brain:
  scorer:
    scan_threshold: 5
    anomaly_z_threshold: 2.0
  weights:
    honeypot_trip: 7.0        # aggressive
    intel_match: 3.0
```

## Upgrade Procedure

```bash
# 1. Pull new image
docker pull ghcr.io/fortress/hydra-pro:latest

# 2. Graceful restart (30s drain)
docker service update --image ghcr.io/fortress/hydra-pro:latest \
  --update-parallelism 1 --update-delay 30s fortress_stack

# 3. Verify all components
docker compose -f deployment/docker-compose.prod.yml exec fortress fortress status
```

## Emergency Contacts

- Hydra-Pro Maintainers: hydra@fortress.internal
- Escalation: /api/v1/escalate (requires operator API key)
