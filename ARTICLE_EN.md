# Building a Swarm-Based Network Defense System in Go + Rust + eBPF

> A deep dive into the architecture of an open-source 7-layer detection pipeline with a 64-core lock-free scorer capable of 32M evaluations/second.

## Why Another Defense System?

Traditional IDS/IPS systems share three fundamental problems:

1. **Single-layer detection** — Most systems have 1-2 detection layers, making evasion straightforward
2. **Performance bottlenecks** — Software packet processing can't keep up with modern network speeds
3. **Threat intelligence silos** — Every node fights alone, no collaboration

Over the past year, I've been building **Fortress V6 (Cyclops)** — a swarm-based network defense system in Go + Rust + eBPF. It's now fully open-source:

**GitHub: [github.com/hyson810/fortress](https://github.com/hyson810/fortress)**

This isn't a product pitch — it's an **architecture post-mortem**: why I made the decisions I did, what went wrong, and what I learned.

---

## 1. Why a 7-Layer Pipeline?

Most IDS systems have one detection layer: capture → rule match → alert.

The problem: a single detection layer can't cover the full attack surface.

Consider a DNS tunnel:
- At the **packet level**, it looks like legitimate DNS queries
- At the **behavioral level**, thousands of TXT queries per minute to the same domain is clearly anomalous
- At the **flow level**, every response is oversized — not normal DNS

So I split detection into 7 distinct layers:

```
L1: Packet Inspector — eBPF/XDP, pattern matching
L2: Flow Analyzer — 5-tuple + statistical features
L3: Behavior Analyzer — baseline profiling & deviation
L4: DNS Tunnel Detector — entropy + volumetric analysis
L5: HTTP Inspector + Brute Force — request analysis + rate detection
L6: Hybrid Anomaly Detector — ML model + heuristics
L7: Fingerprint Engine — JA3/SHA256/HASSH fingerprinting
```

Each layer passes results downstream, converging at the scorer.

**Benefits:**
- Bypassing one layer doesn't defeat the system
- Each layer can specialize (L1 is fast-and-loose, L6 is slow-and-accurate)
- Composite features are much harder to evade than single signals

**Cost:** latency stacking. End-to-end, median ~120μs (vs. ~5μs for bare XDP). Acceptable for most use cases.

---

## 2. The 64-Core Lock-Free Scorer

This was the most aggressively optimized component.

### Why Lock-Free?

Threat scoring is a **hot path** — every packet, millions of times per second. With mutex-based protection, contention destroys throughput as core count scales.

Go's typical goroutine + channel model also breaks down at 32M ops/second.

### How It Works

**Per-CPU sharding:**

```
Scoring state → partitioned across 64 shards
Each shard operates only on its own CPU
Reads aggregate across all shards (atomic ops)
```

Inside each shard, **atomic operations** replace locks entirely:

```go
type Shard struct {
    counters [1024]atomic.Uint64
    threshold atomic.Int64
}

func (s *Shard) Incr(idx int) {
    s.counters[idx].Add(1)
}

func (s *Shard) Load() uint64 {
    total := uint64(0)
    for i := range s.counters {
        total += s.counters[i].Load()
    }
    return total
}
```

Both `Store` and `Load` are lock-free. Only global state reads (e.g. "current threat score") trigger an O(n) shard scan.

**Single-node benchmark:** ~32M scores/second, zero heap allocations.

### An Interesting Optimization

The scorer has a **decay mechanism** — if an IP has no new events over time, its score decays exponentially. Naively scanning the full table with a timer causes cache line bouncing across 64 cores.

Solution: **lazy evaluation**. Each score stores a timestamp. On read: `score * math.Exp(-elapsed * decayRate)`. Slightly imprecise, but zero cache line contention.

---

## 3. SWIM Gossip Protocol — Decentralized Threat Mesh

What I disliked most about existing defense systems: they're all centralized.

Problems:
1. **Single point of failure** — SIEM goes down, all nodes go blind
2. **Bandwidth bottleneck** — Thousands of nodes shipping logs to one collector
3. **Latency** — Detection-to-sync measured in minutes

### Why SWIM?

SWIM (Scalable Weakly-consistent Infection-style Membership Protocol) provides decentralized node discovery and state propagation.

- **No central coordinator** — every node is a peer
- **Eventually consistent** — state propagates via gossip, converging in seconds
- **Scalable** — thousands of nodes theoretically supported

### What We Added

Stock SWIM only handles membership. We added three layers:

1. **Threat intelligence broadcast** — detected threats gossip to all peers immediately
2. **Raft consensus for irreversible actions** — bans and countermeasures require consensus
3. **Immunity propagation** — confirmed immunity (e.g. updated rules) spreads like a vaccine

### Real-World Benchmark

5-node swarm: a scan detection on one node → all 4 peers updated their blocklists in **~1.2 seconds**. For comparison, a typical SIEM model takes 30+ seconds from detection to policy push.

---

## 4. Adaptive Honeypot

Honeypots are an old idea, but traditional ones have hard problems:

1. **Easy to detect** — standard SSH banners, nmap fingerprints them instantly
2. **Static fingerprints** — attackers learn patterns over time
3. **DDoS magnet** — rate-limiting? What rate-limiting?

### Dynamic Fingerprinting

Our honeypots (SSH/HTTP/MySQL) **randomize their fingerprints on every startup**:

- SSH: random banner version + key exchange algorithm combination
- HTTP: random Server header + response ordering
- MySQL: random version string + auth plugin list

Every scan produces different results. Attackers can't build a "this is a honeypot" signature.

### Slowdown

When suspicious interaction is detected, response latency increases progressively:

```
1st connection: normal (~5ms)
5th connection: 500ms
10th connection: 5s
15th connection: 30s
```

Goal: **waste the attacker's time**, not block them. Automated tools stuck at 30s per connection is an excellent time sink.

---

## 5. The C2/Dagger Framework

The most controversial part of the project. Fortress includes a full C2 framework (codename Dagger):

- **Rust implants** — process injection, persistence, lateral movement
- **Multi-protocol listeners** — DNS / HTTPS / WebSocket / ICMP / SMB
- **Payload builder** — dynamic payload generation with obfuscation

**Why does a defense system need attack tools?**

Simple: **you can't defend against what you don't understand.**

Dagger serves as:
1. **Self-testing** — attack yourself before deployment to verify defenses
2. **Red team automation** — authorized penetration testing
3. **Threat hunting** — reverse-engineer implant TTPs for detection signatures

This is dual-use code. **Intended exclusively for authorized security testing and education.**

---

## 6. Performance Numbers

Single-node benchmark (AMD EPYC 64-core, 64GB RAM):

| Metric | Value |
|--------|-------|
| Packet throughput | ~1M PPS (XDP generic mode) |
| Scorer throughput | ~32M evaluations/sec |
| Pipeline latency (p50) | ~120μs |
| Swarm sync (5 nodes) | < 2 seconds |
| Go source | ~1.36M lines |
| Rust source | ~220K lines |

---

## 7. Lessons Learned (A.K.A. Things That Hurt)

### Go's GC vs. XDP

Allocating Go objects in XDP hot path creates massive GC pressure. Solution: **pre-allocated ring buffers + zero-copy handoff.**

### Rust Implant Compile Times

Full Rust implant build: 4-7 minutes. Development experience: painful. Solution: `cargo-chef` for Docker layer caching. CI compile: 45 seconds instead of 7 minutes.

### SWIM Split-Brain

After network partition recovery, SWIM clusters would sometimes remain split — two groups that wouldn't acknowledge each other. Solution: Raft for critical operations (decisions), SWIM only for discovery and state propagation.

### Honeypot Gets Honeypotted

First week online: discovered by Shodan, then targeted by botnets. Solution: strict network namespace isolation + aggressive rate limiting.

---

## Conclusion

Fortress isn't revolutionary. It just integrates existing technologies (XDP, SWIM, ML, honeypots) in a solid engineering way.

**GitHub: [github.com/hyson810/fortress](https://github.com/hyson810/fortress)**

If you're interested in:
- High-performance Go networking
- eBPF/XDP packet processing
- Distributed P2P systems
- Security tool development

Star, fork, PR — all welcome.

---

*Cross-posted on Dev.to, Medium, and Hacker News.*
