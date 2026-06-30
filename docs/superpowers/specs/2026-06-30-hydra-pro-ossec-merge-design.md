# Hydra Pro — OSSEC 融合设计文档

> Phase 4：吸收 OSSEC 日志分析 + Rootkit 扫描

## 核心理念

Fortress 当前所有检测都是**网络层**（抓包 + 管线）。OSSEC 补的是**系统日志层**和**文件签名层**，两个维度形成完整覆盖。

## 架构

```
internal/audit/ (新增包)

┌─────────────────────────────────────┐
│          AuditMonitor (主入口)        │
│  Start/Stop/Alerts/Config            │
└────┬──────────────┬─────────────────┘
     │              │
┌────▼────────┐ ┌──▼────────────────┐
│ LogWatcher    │ │ RootkitScanner    │
│              │ │                   │
│ tail /var/log/│ │ 文件签名比对       │
│ auth.log     │ │ /proc 隐藏检测     │
│ syslog       │ │ 端口隐藏检测       │
│ apply rules  │ │ crontab 异常      │
│ → alert      │ │ → alert          │
└──────┬───────┘ └────┬─────────────┘
       │              │
       └──────┬───────┘
              │ HostAlert → 评分器
              ▼
       Brain Scorer
```

## 一、LogWatcher — 日志监控

`internal/audit/logwatcher.go`

职责：
- tail -f 系统日志文件（auth.log, syslog, kernel.log）
- 按行解析 + 正则匹配攻击模式
- 全内存，不写磁盘
- 可配置监控路径和规则

```go
type LogWatcherConfig struct {
    Enabled    bool     `yaml:"enabled"`
    LogPaths   []string `yaml:"log_paths"`   // /var/log/auth.log 等
    RulesPath  string   `yaml:"rules_path"`  // 规则文件路径
}

type LogRule struct {
    ID          string
    Pattern     string   // regex
    Severity    int      // 1-5
    Score       float64
    Description string
    Category    string   // auth_fail / sudo / cron / ssh
}
```

内置规则（首批 15 条）：
| ID | 匹配 | 描述 | 分数 |
|----|------|------|------|
| L001 | `Failed password for.*from.*` | SSH 密码失败 | 30 |
| L002 | `Failed password for root from.*` | SSH root 爆破 | 50 |
| L003 | `Accepted publickey for.*` | SSH 成功登录 | 10 |
| L004 | `sudo.*COMMAND=.* -u root` | sudo 提权 | 40 |
| L005 | `Invalid user.*from.*` | SSH 无效用户 | 30 |
| L006 | `PAM.*authentication failure` | PAM 认证失败 | 30 |
| L007 | `pam_unix.*authentication failure;.*` | Unix 认证失败 | 25 |
| L008 | `CRON.*\(root\)` CMD | cron 任务执行 | 20 |
| L009 | `User .* logged in` | 用户本地登录 | 10 |
| L010 | `New session .* of user .*` | 新会话 | 10 |
| L011 | `polkitd.*Authentication failure` | PolicyKit 失败 | 25 |
| L012 | `iptables.*DROP` | 防火墙拦截 | 15 |
| L013 | `FAILED su for .* by` | su 失败 | 50 |
| L014 | `rkhunter.*Warning` | Rootkit 警告 | 80 |
| L015 | `UFW BLOCK.*` | UFW 拦截 | 15 |

## 二、RootkitScanner — 签名扫描

`internal/audit/rootkit.go`

职责：
- 已知 rootkit 文件签名检查
- /proc 隐藏进程检测
- 端口隐藏检测
- crontab 异常条目检查
- SSH authorized_keys 后门检查

```go
type RootkitScannerConfig struct {
    Enabled bool   `yaml:"enabled"`
    DBPath  string `yaml:"db_path"`  // 签名数据库路径
}

type RootkitCheckResult struct {
    Type        string   // file / process / port / cron / ssh_key
    Severity    int      // 1-5
    Score       float64
    Description string
    Detail      string
}
```

检查项：
| 类型 | 检查方法 | 分数 |
|------|---------|------|
| 隐藏进程 | 对比 /proc 和 /proc/[pid]/status | 90 |
| 端口隐藏 | 对比 /proc/net/tcp 和 ss 输出 | 80 |
| 已知签名 | 检查常见 rootkit 文件路径 (14 种) | 90 |
| crontab 后门 | 检查异常 crontab 条目 | 70 |
| SSH 后门 | 检查 authorized_keys 异常 | 70 |
| 内核模块 | 检查 /proc/modules 可疑模块 | 80 |

## 三、管线接入

`internal/audit/audit.go` — AuditMonitor 主入口，统一告警流接入评分器。

## 四、配置

```yaml
audit:
  enabled: false
  logwatcher:
    log_paths:
      - /var/log/auth.log
      - /var/log/syslog
      - /var/log/kern.log
  rootkit:
    enabled: true
    scan_interval: 24h
```

## 五、实现顺序

1. `internal/audit/audit.go` — 模块入口 + Config
2. `internal/audit/logwatcher.go` — 日志监控 + 15 条规则
3. `internal/audit/rootkit.go` — Rootkit 签名扫描
4. `internal/audit/rootkit_test.go` — rootkit 检查测试
5. 管线 + 配置集成
6. 全量验证 + v6.4.0
