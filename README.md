<div align="center">
  <h1>🏰 Fortress V6 · Cyclops</h1>
  <p><strong>多引擎融合的网络防御与威胁评分系统</strong><br>
  <em>Multi-Engine Network Defense & Threat Scoring System</em></p>

  <p>
    <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go" alt="Go"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.78+-DEA584?logo=rust" alt="Rust"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-green" alt="License"></a>
    <a href="https://github.com/hyson810/fortress/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/CI-Passing-green?logo=githubactions" alt="CI"></a>
    <img src="https://img.shields.io/badge/eBPF-XDP-blueviolet" alt="eBPF">
    <img src="https://img.shields.io/badge/SWIM-P2P-orange" alt="SWIM">
  </p>

  <p>
    <a href="#features">Features</a> ·
    <a href="#quick-start">Quick Start</a> ·
    <a href="#architecture">Architecture</a> ·
    <a href="#project-structure">Structure</a> ·
    <a href="#security-notice">Security</a> ·
    <a href="#license">License</a>
  </p>

  <br>
  <pre>
┌──────────────────────────────────────────────────┐
│              7-Layer Detection Pipeline          │
│  Packet → Flow → Behavior → DNS → HTTP → ML → FP │
│                → 64-Core Lock-Free Scorer        │
│                → SWIM Gossip Mesh                │
│                → Adaptive Honeypot               │
│                → Countermeasure Chain            │
└──────────────────────────────────────────────────┘</pre>
</div>

---

## 📋 Features

| English | 中文 |
|---------|------|
| **7-Layer Serial Detection Pipeline** — Packet → Flow → Behavior → DNS → HTTP + Brute Force → Anomaly (ML) → Fingerprint | **7 层串行检测管线** — 包检测 → 流量分析 → 行为基线 → DNS隧道 → HTTP检测+暴力破解 → 混合异常检测 → 指纹识别 |
| **64-Core Lock-Free Scorer** — Zero allocation, 32M+ scores/sec single-node | **64 核锁自由评分器** — 无锁并发，0 内存分配，单机 3200 万次/秒评分 |
| **Adaptive Honeypot** — SSH/HTTP/MySQL emulation with dynamic fingerprint and slowdown | **自适应蜜罐** — SSH/HTTP/MySQL 协议模拟，动态指纹和减速带 |
| **ARP Spoofing Detection** — MAC tracking + response latency analysis | **ARP 欺骗检测** — 基于 MAC 地址变更和响应延迟 |
| **Countermeasure Chain** — Raft consensus → Ban → Broadcast → Immunity | **反制链** — Raft 共识 → 封禁 → 情报广播 → 免疫传播 |
| **SWIM Gossip Protocol Mesh** — Decentralized P2P threat intelligence | **SWIM 流行协议去中心化网格** — 无中心节点的威胁情报共享 |
| **eBPF/XDP Packet Processing** — Kernel-level high-speed inspection | **eBPF/XDP 包处理** — 内核级高速包检测 |
| **REST API + MCP Server** — Health, threats, AI/Copilot integration | **REST API + MCP 服务器** — 健康检查、威胁查询、AI/Copilot 集成 |
| **C2/Dagger Framework** — Rust implants, multi-protocol listeners, lateral movement | **C2/Dagger 框架** — Rust 植入体，多协议监听器，横向移动 |

---

## 🚀 Quick Start

```bash
# Clone & build
git clone https://github.com/hyson810/fortress.git
cd fortress
go build -o fortress-linux ./cmd/fortress

# Scan mode — target reconnaissance & threat assessment
./fortress-linux -mode scan -target example.com

# Defense mode — detection pipeline + honeypot + countermeasures
./fortress-linux -mode defend

# API — health check & threat query
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
                    ┌──────────────────────────────────────────────────┐
                    │              7-Layer Detection Pipeline          │
                    │                                                  │
                    │  L1  Packet Inspector (eBPF/XDP)                 │
                    │       ↓                                         │
                    │  L2  Flow Analyzer (5-tuple + stats)            │
                    │       ↓                                         │
                    │  L3  Behavior Analyzer (baseline profiling)     │
                    │       ↓                                         │
                    │  L4  DNS Tunnel Detector (entropy + volume)     │
                    │       ↓                                         │
                    │  L5  HTTP Inspector + Brute Force Detector      │
                    │       ↓                                         │
                    │  L6  Hybrid Anomaly Detector (ML + heuristics) │
                    │       ↓                                         │
                    │  L7  Fingerprint Engine (JA3/SHA256/HASSH)      │
                    │       ↓                                         │
                    │  64-Core Lock-Free Threat Scorer                │
                    └──────────────────────┬──────────────────────────┘
                                           │
                    ┌──────────────────────┴──────────────────────────┐
                    │              Response Decision Engine           │
                    ├─────────────┬──────────────┬───────────────────┤
                    │  Firewall   │  Honeypot     │  Countermeasure  │
                    │  Rules      │  (SSH/HTTP/   │  Chain (Raft)    │
                    │             │   MySQL)      │                   │
                    ├─────────────┴──────────────┴───────────────────┤
                    │           SWIM Gossip Mesh (P2P)               │
                    └────────────────────────────────────────────────┘
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
│   ├── fusion/         # Kali tool integration (nmap, nuclei, metasploit, hydra, etc.)
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

## ⚙️ Configuration

See [fortress.yaml](fortress.yaml) for the full configuration reference.

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
> The `dagger/` subdirectory contains C2 (Command & Control) framework components including implants, persistence, and lateral movement tools. These are provided for:
> - **Red team operations** in authorized engagements
> - **Security research and education**
> - **Defensive testing** of your own infrastructure
>
> **You must NOT use this software for unauthorized access, attacks against systems you do not own or have explicit permission to test, or any illegal activity.**
>
> The `auto_counterstrike` feature should be enabled only in controlled, authorized environments. Consult applicable laws before deploying active countermeasures.

---

## 🤝 Contributing

Contributions welcome!  
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
  <p>
    <sub>Built with Go, Rust, eBPF, and ☕</sub>
    <br>
    <a href="https://github.com/hyson810/fortress">GitHub</a> ·
    <a href="https://github.com/hyson810/fortress/discussions">Discussions</a> ·
    <a href="https://github.com/hyson810/fortress/issues">Issues</a>
  </p>

  <p>
    <a href="https://github.com/hyson810/fortress">
      <img src="https://img.shields.io/github/stars/hyson810/fortress?style=social" alt="Stars">
    </a>
    <a href="https://github.com/hyson810/fortress/fork">
      <img src="https://img.shields.io/github/forks/hyson810/fortress?style=social" alt="Forks">
    </a>
  </p>
</div>
