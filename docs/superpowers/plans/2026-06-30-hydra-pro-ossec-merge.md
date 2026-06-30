# Hydra Pro — OSSEC 融合实现计划

**Goal:** 吸收 OSSEC 日志分析 + Rootkit 签名扫描

**Architecture:** 新增 `internal/audit/` 包，LogWatcher + RootkitScanner 两个子模块

---

### Task 1: AuditMonitor 主入口 + Config
- Create: `internal/audit/audit.go`, `internal/audit/audit_test.go`

### Task 2: LogWatcher 日志监控
- Create: `internal/audit/logwatcher.go`, `internal/audit/logwatcher_test.go`

### Task 3: RootkitScanner 签名扫描
- Create: `internal/audit/rootkit.go`, `internal/audit/rootkit_test.go`

### Task 4: 管线 + 配置集成
- Modify: `internal/config/config.go`, `internal/engine/pipeline.go`, `fortress.yaml`

### Task 5: 全量验证 + v6.4.0
- build/vet/test, push, tag
