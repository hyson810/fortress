# Hydra Pro — Wazuh 融合实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development

**Goal:** 吸收 Wazuh 主机安全能力：FIM 文件监控 + 漏洞扫描 + CIS 合规 + 系统清点

**Architecture:** 新增 `internal/host/` 包，4 个独立子模块 + HostMonitor 主入口，告警注入评分器

**Tech Stack:** Go 1.22, inotify (Linux), SHA256, net/http (CVE API)

---

### Task 1: HostMonitor 主入口 + Config

**Files:**
- Create: `internal/host/host.go`
- Create: `internal/host/host_test.go`

### Task 2: System Inventory 资产清点

**Files:**
- Create: `internal/host/inventory.go`
- Create: `internal/host/inventory_test.go`

### Task 3: FIM 文件完整性监控

**Files:**
- Create: `internal/host/fim.go`
- Create: `internal/host/fim_test.go`

### Task 4: Vuln Scanner 漏洞扫描器

**Files:**
- Create: `internal/host/vuln.go`
- Create: `internal/host/vuln_test.go`

### Task 5: CIS 合规检查器

**Files:**
- Create: `internal/host/cis.go`
- Create: `internal/host/cis_test.go`

### Task 6: 管线 + 配置集成

**Files:**
- Modify: `internal/engine/pipeline.go`
- Modify: `internal/config/config.go`
- Modify: `fortress.yaml`

### Task 7: 全量验证 + 推送

**Files:**
- Verify: `go build/vet/test ./...`
- Push + tag v6.3.0
