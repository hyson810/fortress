# Hydra Pro — CrowdSec 融合设计文档

> Fortress V6 + Suricata 融合 → Hydra Pro Phase 2：吸收 CrowdSec 协作威胁情报

## 核心理念

Fortress 不需要 CrowdSec 的日志解析器（已有 7 层管线），需要的是它的 **全球情报网络**：
1. **社区黑名单** — 15,000+ 已知恶意 IP，定时拉取进评分器
2. **IP 信誉** — 按需查询未知 IP 的历史信誉
3. **告警上报** — 把 Fortress 检测到的威胁投喂回 CrowdSec 社区

## 架构

```
           ┌─────────────────────────┐
           │   CrowdSec Module         │
           │  internal/crowdsec/        │
           │                            │
           │  ┌──────────────────┐     │
           │  │ BlocklistConsumer │ ←──│── HTTPS → CAPI (拉黑名单)
           │  │ (定时 2h 缓存)    │     │
           │  └────────┬─────────┘     │
           │  ┌────────▼─────────┐     │
           │  │ ReputationClient  │ ←──│── HTTPS → CAPI (查 IP)
           │  │ (LRU 缓存)       │     │
           │  └────────┬─────────┘     │
           │  ┌────────▼─────────┐     │
           │  │ AlertReporter     │ ──→│── HTTPS → LAPI (上报)
           │  │ (批量, 异步)      │     │
           │  └──────────────────┘     │
           └──────────┬───────────────┘
                      │ 威胁分数
             ┌────────▼────────┐
             │  Brain Scorer    │
             │  (64-shard)      │
             └─────────────────┘
```

## 一、BlocklistConsumer — 社区黑名单消费者

`internal/crowdsec/blocklist.go`

职责：
- 每 2 小时拉取 CrowdSec 社区黑名单
- 解析 IP 列表 + 标签（scan/bruteforce/spam 等分类）
- 写入本地缓存（内存 + 可选文件持久化）
- 按严重度映射为 Fortress 威胁分数

配置：
```go
type BlocklistConfig struct {
    Enabled       bool          // 启用
    Interval      time.Duration // 拉取间隔, 默认 2h
    CachePath     string        // 本地缓存路径
    APIKey        string        // CrowdSec API Key (可选)
    ScoreOnScan   float64       // 扫描 IP 默认分数, 30
    ScoreOnBrute  float64       // 爆破 IP 默认分数, 50
    ScoreOnMalicious float64    // 恶意 IP 默认分数, 70
}
```

## 二、ReputationClient — IP 信誉查询

`internal/crowdsec/reputation.go`

职责：
- 按需查询 CrowdSec 对某个 IP 的信誉评估
- 内部 LRU 缓存（1024 条目，TTL 10 分钟）
- 返回：是否存在、标签列表、最近攻击次数、最后活跃时间
- 非阻塞（不因查不到就丢包，超时即放过）

```go
type ReputationResult struct {
    IP            string
    Exists        bool
    Labels        []string  // scan, bruteforce, spam, malware
    AttackCount   int
    LastSeen      time.Time
    Score         int       // 0-100 综合信誉分
}
```

## 三、AlertReporter — 告警上报

`internal/crowdsec/reporter.go`

职责：
- 监听 Fortress 评分器的告警，翻译为 CrowdSec Alert 格式
- 批量异步上报到本地 CrowdSec LAPI (http://127.0.0.1:8080)
- 失败重试（最多 3 次），不阻塞管线

CrowdSec Alert 格式：
```json
{
  "scenario": "fortress/suricata-rule-match",
  "scenario_version": "",
  "message": "Suricata rule SID 1000001: SQL Injection Attempt",
  "source": {
    "ip": "192.168.1.1",
    "cn": "",
    "as": "",
    "range": ""
  },
  "start_at": "2026-06-30T12:00:00Z",
  "stop_at": "2026-06-30T12:00:00Z"
}
```

## 四、模块入口

`internal/crowdsec/crowdsec.go`

```go
type CrowdSec struct {
    blocklist  *BlocklistConsumer
    reputation *ReputationClient
    reporter   *AlertReporter
    scorer     *brain.ShardScorer  // 注入评分器引用
}

func New(cfg Config, scorer *brain.ShardScorer) *CrowdSec
func (c *CrowdSec) Start(ctx context.Context)
func (c *CrowdSec) Stop()
func (c *CrowdSec) QueryReputation(ip string) (*ReputationResult, bool) // 查信誉
func (c *CrowdSec) ReportAlert(alert *crowdsecAlert) // 上报告警
```

## 五、管线接入

`internal/engine/pipeline.go` 改动：

- NewDetectionPipeline 中增加 `EnableCrowdSec()` 调用
- 管线 `feedSuricataAlerts` 中顺带调用 `crowdSec.ReportAlert()`
- 评分器前可插入 `crowdSec.QueryReputation()` 对未知 IP 加权

## 六、配置

```yaml
crowdsec:
  enabled: false
  blocklist:
    interval: 2h
    score_scan: 30
    score_bruteforce: 50
    score_malicious: 70
  reputation:
    cache_size: 1024
    cache_ttl: 10m
    timeout: 3s
  reporter:
    batch_size: 10
    flush_interval: 5s
    lapi_url: http://127.0.0.1:8080
```

## 七、不做的事情

- ❌ 不搞 CrowdSec 场景引擎（已有 7 层管线 + Suricata 规则）
- ❌ 不搞 log parser（Fortress 抓包检测，不读日志）
- ❌ 不搞 bouncer（Fortress 自己就是反制层）
- ❌ 不依赖本地 CrowdSec 运行（API Key 可以直接对接 CAPI）

## 八、实现顺序

1. `internal/crowdsec/crowdsec.go` — 模块入口 + Config
2. `internal/crowdsec/blocklist.go` — BlocklistConsumer
3. `internal/crowdsec/reputation.go` — ReputationClient + LRU 缓存
4. `internal/crowdsec/reporter.go` — AlertReporter
5. `internal/engine/pipeline.go` — 管线接入
6. `fortress.yaml` — 配置
7. 集成测试 + 基准
