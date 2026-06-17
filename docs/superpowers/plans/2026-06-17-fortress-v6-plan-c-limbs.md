# Fortress V6 Plan C: 手脚 — Kali融合 + 主动防御 + 蜂群 + 欺骗

> **For agentic workers:** Use superpowers:subagent-driven-development.

**Goal:** Add Kali weapon orchestration, active defense (tarpit/honeypot/intel/firewall), swarm networking (gossip/immunity), and deception system.

**Architecture:** New Go packages under `internal/`: fusion/ (Kali orchestration), defense/ (tarpit/honeypot/firewall/intel), swarm/ (gossip/immunity), deception/ (abyss/mirror/poison). All integrate with existing brain scorer and response ladder.

**Dependencies:** Plan A (Go brain) + Plan B (Rust/C muscle).

---

## Tasks

### C1: Kali Fusion — Weapon Orchestration
**Files:** internal/fusion/kali.go, internal/fusion/chain.go
Orchestrate Kali's 600+ tools instead of self-writing weapons. Wrappers for nmap XML, nuclei JSONL, hydra stdout, sqlmap API pipe, msfconsole XMLRPC. Multi-weapon chain: nmap→nuclei→hydra→sqlmap→msf.

### C2: Active Defense — Tarpit + Honeypot + Firewall + Intel
**Files:** internal/defense/tarpit.go, honeypot.go, firewall.go, intel.go
TCP zero-window tarpit (raw socket), SSH/HTTP/MySQL honeypots, nftables rule management, WHOIS/ASN/Shodan threat intelligence with abuse report generation.

### C3: Swarm — Gossip + Immunity
**Files:** internal/swarm/gossip.go, immunity.go
SWIM epidemic protocol with Ed25519-signed immunity broadcasts. NaCl secretbox wire encryption. Multi-callback threat intel fanout.

### C4: Deception — LLM Abyss + Mirror + Poison
**Files:** internal/deception/abyss.go, mirror.go, poison.go
LLM-driven recursive depth honeypot, XDP digital twin redirection, data poisoning engine for fake vulnerability injection.

### C5: Main Integration + Tests
**Files:** Modify main.go, add integration tests
Wire fusion, defense, swarm, and deception into the response ladder. B阶 triggers intel, C阶 triggers tarpit+honeypot+Kali scan, D阶 triggers LLM abyss+full chain+immunity broadcast.
