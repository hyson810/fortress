<div align="center">

# 🏰 Fortress V6 · Cyclops
### *Multi-Engine Network Defense & Threat Scoring System*
### *多引擎融合的网络防御与威胁评分系统*

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)]()
[![Rust](https://img.shields.io/badge/Rust-1.78+-DEA584?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-green)]()
[![CI](https://img.shields.io/github/actions/workflow/status/hyson810/fortress/.github/workflows/ci.yml?label=CI&logo=github)]()
[![Stars](https://img.shields.io/github/stars/hyson810/fortress?style=social)]()
[![eBPF](https://img.shields.io/badge/eBPF-XDP-blueviolet)]()
[![SWIM](https://img.shields.io/badge/SWIM-P2P-orange)]()

<br>

```
╔══════════════════════════════════════════════════════╗
║              7-Layer Detection Pipeline              ║
║  L1 Packet  L2 Flow  L3 Behavior  L4 DNS Tunnel     ║
║  L5 HTTP+BF  L6 ML  L7 Fingerprint                  ║
║           → 64-Core Lock-Free Scorer                ║
║           → SWIM Gossip Mesh (P2P)                  ║
║           → Adaptive Honeypot (SSH/HTTP/MySQL)       ║
║           → Countermeasure Chain (Raft Consensus)    ║
╚══════════════════════════════════════════════════════╝
```

<br>

[Features](#-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Demo](#-demo) • [Structure](#-project-structure) • [Security](#-security-notice) • [Contributing](#-contributing)

</div>

---

## ✨ Features

| Category | English | 中文 |
|----------|---------|------|
| 🔍 **Detection** | 7-Layer Pipeline: Packet → Flow → Behavior → DNS → HTTP+Brute Force → ML → Fingerprint | 7层串行检测管线：包检测→流量分析→行为基线→DNS隧道→HTTP+暴力破解→ML→指纹识别 |
| ⚡ **Scoring** | 64-Core Lock-Free Scorer, 32M+ scores/sec, zero allocation | 64核锁自由评分器，3200万次/秒，零内存分配 |
| 🍯 **Honeypot** | SSH/HTTP/MySQL adaptive honeypot with dynamic fingerprints | SSH/HTTP/MySQL自适应蜜罐，动态指纹 |
| 🕸️ **Swarm** | SWIM gossip protocol mesh, decentralized P2P threat intelligence | SWIM流行协议去中心化网格，P2P威胁情报共享 |
| 🛡️ **Response** | Raft consensus → Ban → Broadcast → Immunity propagation | Raft共识→封禁→广播→免疫传播反制链 |
| 🐝 **eBPF** | Kernel-level XDP packet processing | 内核级XDP/eBPF包处理 |
| 🤖 **AI** | REST API + MCP Server for AI/Copilot integration | REST API + MCP服务器，AI/Copilot集成 |
| ⚔️ **C2** | Dagger framework: Rust implants, multi-protocol listeners, lateral movement | Dagger框架：Rust植入体，多协议监听器，横向移动 |
| 🕵️ **Detection** | ARP spoofing detection via MAC tracking + latency analysis | ARP欺骗检测，MAC追踪+延迟分析 |

---

## 🚀 Quick Start

```bash
# Clone & build
git clone https://github.com/hyson810/fortress.git
cd fortress
go build -o fortress-linux ./cmd/fortress

# Scan mode
./fortress-linux -mode scan -target example.com

# Defense mode — full pipeline + honeypot + countermeasures
./fortress-linux -mode defend

# API — health & threats
curl http://localhost:9090/health
curl http://localhost:9090/threats
```

### Docker

```bash
docker build -t fortress:latest .
docker run --rm -it --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
  -v $(pwd)/fortress.yaml:/etc/fortress/fortress.yaml fortress:latest
```

---

## 🏗 Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              7-Layer Detection Pipeline      │
                    │                                              │
                    │  L1  Packet Inspector (eBPF/XDP)             │
                    │       ↓                                     │
                    │  L2  Flow Analyzer (5-tuple + stats)        │
                    │       ↓                                     │
                    │  L3  Behavior Analyzer (baseline profiling) │
                    │       ↓                                     │
                    │  L4  DNS Tunnel Detector (entropy + volume) │
                    │       ↓                                     │
                    │  L5  HTTP Inspector + Brute Force           │
                    │       ↓                                     │
                    │  L6  Hybrid Anomaly Detector (ML)           │
                    │       ↓                                     │
                    │  L7  Fingerprint Engine (JA3/SHA256/HASSH)  │
                    │       ↓                                     │
                    │  ┌──────────────────────────────────┐       │
                    │  │   64-Core Lock-Free Scorer       │       │
                    │  │   32M scores/sec · 0 alloc       │       │
                    │  └──────────────────────────────────┘       │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────┴───────────────────────────┐
                    │            Response Decision Engine          │
                    ├──────────────┬──────────────┬───────────────┤
                    │  Firewall    │  Honeypot    │ Counter-      │
                    │  Rules       │  (SSH/HTTP/  │ measure Chain │
                    │              │   MySQL)     │  (Raft)       │
                    ├──────────────┴──────────────┴───────────────┤
                    │        SWIM Gossip Mesh (P2P)               │
                    └─────────────────────────────────────────────┘
```

### Project Structure

```
├── cmd/fortress/       # Main entrypoint
├── internal/           # Core engine
│   ├── brain/          # ML models, prediction, countermeasures
│   ├── config/         # Configuration management
│   ├── deception/      # Honeypot services (SSH/HTTP/MySQL)
│   ├── defense/        # Firewall, ARP detection
│   ├── engine/         # Detection pipeline (7 layers)
│   ├── engines/        # eBPF/XDP packet processing
│   ├── fusion/         # Kali tool integration (nmap, nuclei, hydra, msf, etc.)
│   ├── host/           # System inventory
│   ├── mcp/            # MCP protocol server (AI/Copilot integration)
│   └── swarm/          # P2P gossip, consensus, cryptography, immunity
├── dagger/             # C2 framework (Rust implants, teamserver, builder)
├── shield/             # Additional defense layers
├── kernel/             # Kernel modules
├── configs/            # Example configurations
├── fuzz/               # Fuzzing harnesses
└── ci/                 # CI/CD pipelines
```

---

## 📸 Demo

> *Coming soon — watch this space for a live demo GIF showing Fortress detecting and neutralizing threats in real-time.*

In the meantime, try it yourself:

```bash
# Terminal 1: Start Fortress in defense mode
sudo ./fortress-linux -mode defend

# Terminal 2: Run a port scan (simulate attacker)
nmap -sS -p 1-1000 localhost

# Terminal 2: Check what Fortress detected
curl http://localhost:9090/threats | jq
```

---

## ⚙️ Configuration

See [fortress.yaml](fortress.yaml) for the complete reference.

```yaml
engine:
  xdp_mode: "generic"       # native|generic|offload
  max_pps: 1000000
  cpu_pin: [2, 3]

brain:
  ml_model: ""
  auto_counterstrike: false
  counterstrike_threshold: 85.0

whitelist:
  - "127.0.0.1"
  - "10.0.0.0/8"
```

---

## 🔒 Security Notice

> **Fortress V6 is a dual-use security tool designed for authorized security testing, network defense education, and legitimate cybersecurity operations.**  
>
> The `dagger/` subdirectory contains C2 framework components including implants, persistence, and lateral movement tools. These are provided for **red team operations** in authorized engagements, **security research and education**, and **defensive testing** of your own infrastructure.
>
> **You must NOT use this software for unauthorized access, attacks against systems you do not own or have explicit permission to test, or any illegal activity.**
>
> The `auto_counterstrike` feature should be enabled only in controlled, authorized environments.

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'feat: add amazing feature'`)
4. Push (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📄 License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

---

<div align="center">

**Built with Go, Rust, eBPF, and ☕**  

[![GitHub](https://img.shields.io/badge/GitHub-hyson810%2Ffortress-181717?logo=github)](https://github.com/hyson810/fortress)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-2375E0)](https://github.com/hyson810/fortress/discussions)
[![Issues](https://img.shields.io/badge/GitHub-Issues-262626)](https://github.com/hyson810/fortress/issues)
[![Release](https://img.shields.io/badge/Release-v6.0.0-blue)](https://github.com/hyson810/fortress/releases/tag/v6.0.0)

⭐ **Star this repo if you find it useful!** ⭐

</div>
