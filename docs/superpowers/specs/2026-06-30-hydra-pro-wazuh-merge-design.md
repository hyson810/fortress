# Hydra Pro — Wazuh 融合设计文档

> Fortress V6 + Suricata + CrowdSec → Phase 3：吸收 Wazuh 主机安全能力

## 核心理念

Fortress 当前是**网络层**防御（抓包 + 管线 + 评分器）。Wazuh 补的是**主机层**防御（文件监控 + 漏洞 + 合规 + 资产）。两个层面形成完整闭环。

## 架构

```
internal/host/ (新增包)

┌──────────────────────────────────────────┐
│            HostMonitor (主入口)            │
│  Start/Stop/Stats                         │
└────┬──────┬──────┬───────────────────────┘
     │      │      │
┌────▼──┐ ┌─▼───┐ ┌▼──────────┐ ┌──────────┐
│ FIM    │ │Vuln  │ │CIS Checker│ │Inventory │
│文件监控 │ │扫描器 │ │合规检查    │ │资产清点   │
│        │ │     │ │          │ │          │
│inotify │ │dpkg/│ │CIS基准    │ │OS/进程/   │
│+hash   │ │rpm→ │ │自动评估    │ │网络/端口  │
│基线    │ │CVE  │ │报告      │ │清点      │
└───┬────┘ └──┬──┘ └────┬─────┘ └────┬─────┘
    │         │         │            │
    └─────────┴─────────┴────────────┘
                    │ 异常告警
                    ▼
           Brain Scorer (评分器)
```

## 一、FIM — 文件完整性监控

`internal/host/fim.go`

职责：
- 监控受保护路径的文件变更（创建/修改/删除/权限变更）
- 使用 SHA256 哈希校验文件内容
- Linux: inotify 实时监控 + 定时全量扫描
- 基线管理：初始扫描存入数据库，变更时告警

```go
type FIMConfig struct {
    Enabled      bool     `yaml:"enabled"`
    WatchPaths   []string `yaml:"watch_paths"`   // 监控路径
    ExcludePaths []string `yaml:"exclude_paths"` // 排除路径
    HashAlgo     string   `yaml:"hash_algo"`     // sha256 / sha1 / md5
    ScanInterval string   `yaml:"scan_interval"` // 全量扫描间隔 (e.g. "24h")
    DBPath       string   `yaml:"db_path"`       // 基线数据库路径
}

type FileChangeEvent struct {
    Path     string
    Type     string    // created / modified / deleted / permission
    Hash     string    // new hash (if file exists)
    OldHash  string    // previous hash (if available)
    Mode     os.FileMode
    Size     int64
    Timestamp time.Time
    Score    float64
}
```

评分映射：
- `/etc/` 关键配置文件修改 → 80 分
- `/bin/`, `/usr/bin/` 可执行文件修改 → 90 分
- `/var/log/` 日志文件 → 20 分
- 其他路径 → 40 分

## 二、漏洞扫描器

`internal/host/vuln.go`

职责：
- 扫描系统已安装软件包（dpkg/rpm 数据库）
- 从本地或在线 CVE 数据库匹配已知漏洞
- 按严重度评分（CRITICAL=90, HIGH=70, MEDIUM=40, LOW=10）
- 增量扫描（缓存上次结果，只报告新增）

```go
type VulnConfig struct {
    Enabled      bool   `yaml:"enabled"`
    ScanInterval string `yaml:"scan_interval"` // 默认 24h
    CVEAPIURL    string `yaml:"cve_api_url"`   // CVE feed URL
    VulsDBPath   string `yaml:"vuls_db_path"`  // 本地 CVE 数据库
    Severity     string `yaml:"severity"`       // 最低报告级别
}

type VulnResult struct {
    Package     string
    Version     string
    CVE         string
    Severity    string    // CRITICAL / HIGH / MEDIUM / LOW
    Score       float64
    Description string
    FixedIn     string    // 修复版本
}
```

## 三、CIS 合规检查器

`internal/host/cis.go`

职责：
- 执行 CIS Benchmark 检查项（首批 30 项核心检查）
- 覆盖：文件权限、SSH 配置、内核参数、用户审计、网络设置
- 输出 pass/fail/NA + 修复建议
- 定期扫描 + 按需触发

```go
type CISConfig struct {
    Enabled     bool     `yaml:"enabled"`
    Interval    string   `yaml:"interval"`     // 默认 24h
    Profile     string   `yaml:"profile"`      // level_1 / level_2
    Benchmark   string   `yaml:"benchmark"`    // cis_ubuntu_22 / cis_debian_12
}

type CISCheck struct {
    ID          string   // e.g. "1.1.1.1"
    Title       string
    Description string
    Level       int      // 1 or 2
    Pass        bool
    Score       float64
    Remediation string
}
```

首批 10 项关键检查：
| ID | 检查项 | 失败分数 |
|----|--------|---------|
| 1.1.1 | /etc/passwd 权限 644 | 50 |
| 1.1.2 | /etc/shadow 权限 640 | 70 |
| 1.2.1 | SSH PermitRootLogin no | 60 |
| 1.3.1 | 密码策略 minlen >= 14 | 50 |
| 2.1.1 | 未使用的端口服务已禁用 | 30 |
| 2.2.1 | 审计日志存在 | 40 |
| 3.1.1 | 内核参数 net.ipv4.ip_forward=0 | 30 |
| 3.2.1 | iptables 策略默认 DROP | 60 |
| 4.1.1 | rkhunter 安装 | 40 |
| 5.1.1 | 非 root su 限制 | 40 |

## 四、系统资产清点

`internal/host/inventory.go`

职责：
- 采集系统基本信息（定时任务 + 按需查询）
- 输出标准化 Inventory 结构体

```go
type InventoryConfig struct {
    Enabled     bool   `yaml:"enabled"`
    Interval    string `yaml:"interval"` // 默认 1h
}

type SystemInventory struct {
    Timestamp   time.Time
    Hostname    string
    OS          OSInfo
    Kernel      string
    CPU         CPUInfo
    Memory      MemoryInfo
    Network     []NetworkInterface
    Processes   []ProcessInfo
    Packages    int
    Uptime      time.Duration
}

type OSInfo struct {
    Name       string  // Ubuntu / Debian / ...
    Version    string  // 22.04
    Arch       string  // amd64
}
```

## 五、管线接入

`internal/host/host.go` — 主入口

```go
type HostMonitor struct {
    fim       *FIMMonitor
    vuln      *VulnScanner
    cis       *CISChecker
    inventory *InventoryCollector
    alertCh   chan HostAlert
    scorer    *brain.ShardScorer
}

type HostAlert struct {
    Type      string   // fim / vuln / cis
    Severity  int      // 1-5
    Score     float64
    Message   string
    Timestamp time.Time
}
```

`HostMonitor.Start()` 启动所有子模块，告警统一进评分器。

## 六、配置

```yaml
host:
  enabled: false
  fim:
    watch_paths:
      - /etc/
      - /bin/
      - /usr/bin/
    exclude_paths:
      - /etc/mtab
      - /etc/hostname
    hash_algo: sha256
    scan_interval: 24h
  vuln:
    scan_interval: 24h
    cve_api_url: https://vulners.com/api/v3/
    severity: MEDIUM
  cis:
    interval: 24h
    profile: level_1
    benchmark: ubuntu_22
  inventory:
    interval: 1h
```

## 七、不做的事情

- ❌ 不搞 Wazuh 完整兼容（SQLite 数据库、REST API、agent/server 架构）
- ❌ 不搞多代理管理（Fortress 是单机守护进程）
- ❌ 不搞日志分析器（已有网络层检测）
- ❌ 不搞文件恢复（只检测，不修复）

## 八、实现顺序

1. `internal/host/host.go` — 模块入口 + Config + HostAlert
2. `internal/host/inventory.go` — 系统资产清点（最独立，快速出结果）
3. `internal/host/fim.go` — 文件完整性监控（核心价值最高）
4. `internal/host/vuln.go` — 漏洞扫描器（依赖 CVE 数据源）
5. `internal/host/cis.go` — 合规检查器（30 条检查规则）
6. `internal/engine/pipeline.go` — 管线接入
7. `internal/config/config.go` + `fortress.yaml` — 配置
8. 集成测试 + 全量验证
