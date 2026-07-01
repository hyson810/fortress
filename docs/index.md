---
title: Fortress V6 · Cyclops
description: Multi-engine network defense & threat scoring system — Go + Rust + eBPF
---

<div align="center">

# 🏰 Fortress V6 · Cyclops

### *Multi-Engine Network Defense & Threat Scoring System*
### *多引擎融合网络防御与威胁评分系统*

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)]()
[![Rust](https://img.shields.io/badge/Rust-1.78+-DEA584?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-green)]()
[![CI](https://img.shields.io/github/actions/workflow/status/hyson810/fortress/.github/workflows/ci.yml?label=CI&logo=github)]()
[![Stars](https://img.shields.io/github/stars/hyson810/fortress?style=social)]()

*A 7-layer network defense system with eBPF/XDP kernel inspection, 64-core lock-free scoring engine (32M/s), SWIM P2P gossip mesh, and adaptive honeypots.*

---

</div>

## 🚀 Features

| Category | Capability |
|----------|-----------|
| 🔍 **Detection** | 7-layer pipeline: eBPF/XDP → Flow → Behavior → DNS → HTTP+BF → ML → Fingerprint |
| ⚡ **Scoring** | 64-core lock-free scorer — **32 million scores/sec**, zero allocation |
| 🍯 **Honeypot** | SSH/HTTP/MySQL adaptive with dynamic fingerprints |
| 🕸️ **Swarm** | SWIM gossip protocol mesh — decentralized P2P threat intelligence |
| 🛡️ **Response** | Raft consensus → Ban → Broadcast → Immunity propagation chain |
| 🐝 **eBPF** | Kernel-level XDP packet processing |
| 🤖 **AI Ready** | REST API + MCP Server for AI/Copilot integration |
| ⚔️ **C2 Framework** | Dagger: Rust implants, multi-protocol listeners, lateral movement |

## 🚀 Quick Start

```bash
git clone https://github.com/hyson810/fortress.git
cd fortress
go build -o fortress-linux ./cmd/fortress

# Scan mode
./fortress-linux -mode scan -target example.com

# Defense mode — full pipeline + honeypot + countermeasures
./fortress-linux -mode defend

# API
curl http://localhost:9090/health
curl http://localhost:9090/threats
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              7-Layer Detection Pipeline                  │
│  L1: Pkt  L2: Flow  L3: Behav  L4: DNS  L5: HTTP+BF   │
│               L6: ML  L7: Fingerprint                   │
├─────────────────────────────────────────────────────────┤
│              64-Core Lock-Free Scorer                    │
├─────────────────────────────────────────────────────────┤
│  SWIM P2P Mesh  ⇄  Adaptive Honeypot  ⇄  Raft Response │
└─────────────────────────────────────────────────────────┘
```

## Documentation

- 📖 [Full README](https://github.com/hyson810/fortress) — Comprehensive docs
- 📝 [Technical Article (EN)](https://github.com/hyson810/fortress/blob/main/ARTICLE_EN.md)
- 📝 [Technical Article (ZH)](https://github.com/hyson810/fortress/blob/main/ARTICLE_ZH.md)
- 🚀 [Deployment Guide](DEPLOYMENT.md)
- 📖 [Runbook](RUNBOOK.md)

## Tech Stack

| Component | Language | Technology |
|-----------|----------|------------|
| Core Engine | Go | Pipeline orchestration, scoring |
| Kernel Modules | Rust | eBPF/XDP packet processing |
| C2 Implants | Rust | Dagger framework |
| P2P Mesh | Go | SWIM gossip protocol |
| Consensus | Go | Raft for countermeasure chain |

## Support

⭐ **Star the repo** on [GitHub](https://github.com/hyson810/fortress) to help others discover Fortress!

---

<div align="center">

[GitHub](https://github.com/hyson810/fortress) • [Issues](https://github.com/hyson810/fortress/issues) • [Discussions](https://github.com/hyson810/fortress/discussions) • [License Apache 2.0](https://github.com/hyson810/fortress/blob/main/LICENSE)

</div>
