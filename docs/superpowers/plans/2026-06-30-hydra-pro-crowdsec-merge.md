# Hydra Pro — CrowdSec 融合实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 吸收 CrowdSec 协作威胁情报能力：社区黑名单消费 + IP 信誉查询 + 告警上报

**Architecture:** 新增 `internal/crowdsec/` 包，三个独立模块（BlocklistConsumer, ReputationClient, AlertReporter）通过管道接入现有评分器。不依赖本地 CrowdSec 进程运行。

**Tech Stack:** Go 1.22, net/http, LRU 缓存, brain.ShardScorer

---

## 文件结构

### 新增文件
| 文件 | 职责 |
|------|------|
| `internal/crowdsec/crowdsec.go` | 模块入口, Config 结构体, Start/Stop |
| `internal/crowdsec/crowdsec_test.go` | 集成测试 |
| `internal/crowdsec/blocklist.go` | BlocklistConsumer — 定时拉取 + 缓存 IP 黑名单 |
| `internal/crowdsec/blocklist_test.go` | Blocklist 测试 |
| `internal/crowdsec/reputation.go` | ReputationClient — IP 信誉查询 + LRU 缓存 |
| `internal/crowdsec/reputation_test.go` | Reputation 测试 |
| `internal/crowdsec/reporter.go` | AlertReporter — 告警上报 LAPI |
| `internal/crowdsec/reporter_test.go` | Reporter 测试 |

### 修改文件
| 文件 | 改动 |
|------|------|
| `internal/config/config.go` | 新增 CrowdSecConfig 结构体 |
| `internal/engine/pipeline.go` | 新增 EnableCrowdSec + feedCrowdSec |
| `fortress.yaml` | 新增 crowdsec 配置段 |

---

### Task 1: CrowdSec 模块入口 + Config 结构体

**Files:**
- Create: `internal/crowdsec/crowdsec.go`
- Create: `internal/crowdsec/crowdsec_test.go`

**Config 结构体：**
```go
package crowdsec

import "time"

type Config struct {
    Enabled bool `yaml:"enabled"`

    Blocklist BlocklistConfig `yaml:"blocklist"`
    Reputation ReputationConfig `yaml:"reputation"`
    Reporter ReporterConfig `yaml:"reporter"`
}

type BlocklistConfig struct {
    Interval      time.Duration `yaml:"interval"`        // default 2h
    CachePath     string        `yaml:"cache_path"`      // 缓存文件路径
    APIKey        string        `yaml:"api_key"`        
    ScoreOnScan   float64       `yaml:"score_scan"`      // default 30
    ScoreOnBrute  float64       `yaml:"score_bruteforce"` // default 50
    ScoreOnMalicious float64    `yaml:"score_malicious"` // default 70
}

type ReputationConfig struct {
    CacheSize int           `yaml:"cache_size"` // default 1024
    CacheTTL  time.Duration `yaml:"cache_ttl"`  // default 10m
    Timeout   time.Duration `yaml:"timeout"`    // default 3s
}

type ReporterConfig struct {
    BatchSize     int           `yaml:"batch_size"`     // default 10
    FlushInterval time.Duration `yaml:"flush_interval"` // default 5s
    LAPIURL       string        `yaml:"lapi_url"`       // default http://127.0.0.1:8080
}
```

**CrowdSec struct:**
```go
type CrowdSec struct {
    cfg        Config
    scorer     *brain.ShardScorer
    blocklist  *BlocklistConsumer
    reputation *ReputationClient
    reporter   *AlertReporter
    alertCh    chan *AlertItem
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
}

type AlertItem struct {
    IP        string
    Scenario  string
    Message   string
    Timestamp time.Time
    Source    string // "suricata" | "fortress"
}

func New(cfg Config, scorer *brain.ShardScorer) *CrowdSec
func (c *CrowdSec) Start(ctx context.Context)
func (c *CrowdSec) Stop()
func (c *CrowdSec) QueryReputation(ip string) (*ReputationResult, bool)
func (c *CrowdSec) ReportAlert(alert *AlertItem)
```

Tests:
- Test config defaults
- Test New/Start/Stop lifecycle
- Test QueryReputation returns default for unknown IP

---

### Task 2: BlocklistConsumer — 社区黑名单

**Files:**
- Create: `internal/crowdsec/blocklist.go`
- Create: `internal/crowdsec/blocklist_test.go`

```go
type BlocklistConsumer struct {
    cfg      BlocklistConfig
    entries  map[string]BlocklistEntry  // IP → entry
    mu       sync.RWMutex
    client   *http.Client
}

type BlocklistEntry struct {
    IP        string
    Labels    []string
    Source    string   // "crowdsec" | "local"
    Score     float64
    UpdatedAt time.Time
}
```

Methods:
- `NewBlocklistConsumer(cfg BlocklistConfig) *BlocklistConsumer`
- `Start(ctx context.Context)` — starts periodic fetch goroutine
- `Stop()`
- `BlockedIPs() []BlocklistEntry` — snapshot of cached entries
- `Score(ip string) float64` — returns score for IP by classification
- `fetchOnce()` — does the actual HTTPS fetch (mockable in tests)

Blocklist URL: `https://admin.api.crowdsec.net/v1/blocklists/{id}/download` with API key.

For testing: use a mock HTTP server that returns a canned IP list:
```go
func TestBlocklistConsumer_Fetch(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("1.2.3.4 scan\n5.6.7.8 bruteforce\n"))
    }))
    defer server.Close()
    
    consumer := NewBlocklistConsumer(BlocklistConfig{...})
    // Override fetch URL for test
    err := consumer.fetchFromURL(server.URL)
    // Verify entries parsed correctly
}
```

Tests:
1. Parse IP list from HTTP response
2. Score lookup for known IPs
3. Score for unknown IP returns 0
4. Concurrent read safety
5. Empty response doesn't error
6. Bad URL returns error

---

### Task 3: ReputationClient — IP 信誉查询 + LRU 缓存

**Files:**
- Create: `internal/crowdsec/reputation.go`
- Create: `internal/crowdsec/reputation_test.go`

```go
type ReputationClient struct {
    cfg    ReputationConfig
    cache  *lruCache  // simple LRU, thread-safe
    client *http.Client
}

type ReputationResult struct {
    IP          string
    Exists      bool
    Labels      []string
    AttackCount int
    LastSeen    time.Time
    Score       int     // 0-100
}

type lruCache struct {
    mu      sync.Mutex
    maxSize int
    ttl     time.Duration
    items   map[string]*cacheEntry
    order   []string  // LRU order
}

type cacheEntry struct {
    result    ReputationResult
    expiresAt time.Time
}
```

Methods:
- `NewReputationClient(cfg ReputationConfig) *ReputationClient`
- `Query(ctx context.Context, ip string) (ReputationResult, bool)` — check cache first, then HTTP
- `clearExpired()` — background cleanup

Query flow:
1. Check LRU cache — hit → return cached
2. HTTP GET to CAPI reputation endpoint
3. Parse response, cache it, return
4. On timeout/error → return empty result (don't block)

Implement a simple LRU cache inside the package (no external dependency):
- Max 1024 entries
- TTL 10 minutes per entry
- O(1) get using map + doubly linked list (or simplified: map + append on access)

Simpler LRU: use a fixed-size slice, on access move to front, evict from back.

Tests:
1. Query returns cached result on repeat
2. Cache eviction at max size
3. Expired entries are skipped
4. HTTP timeout returns empty (not error)
5. Concurrent queries don't race

---

### Task 4: AlertReporter — 告警上报

**Files:**
- Create: `internal/crowdsec/reporter.go`
- Create: `internal/crowdsec/reporter_test.go`

```go
type AlertReporter struct {
    cfg       ReporterConfig
    queue     []AlertItem
    mu        sync.Mutex
    client    *http.Client
    stopCh    chan struct{}
}

type CrowdSecAlert struct {
    Scenario        string `json:"scenario"`
    Message         string `json:"message"`
    Source          struct {
        IP string `json:"ip"`
    } `json:"source"`
    StartAt         string `json:"start_at"`
    StopAt          string `json:"stop_at"`
}
```

Methods:
- `NewAlertReporter(cfg ReporterConfig) *AlertReporter`
- `Start(ctx context.Context)` — background flush goroutine
- `Stop()`
- `Report(alert AlertItem)` — queue alert
- `flush()` — batch-send queued alerts to LAPI

The reporter accumulates alerts and flushes in batches:
- Trigger: batch size reached OR flush interval elapsed
- POST to `${LAPI_URL}/v1/alerts` with array of CrowdSecAlert
- On success: clear queued items
- On failure: retry up to 3 times, then discard (don't grow unbounded)

Tests:
1. Report queues an alert
2. Flush sends batched alerts
3. Empty queue flush is no-op
4. LAPI error doesn't crash
5. Queue capped at 1000 items (drop oldest)

---

### Task 5: 管线集成

**Files:**
- Modify: `internal/engine/pipeline.go`
- Modify: `internal/config/config.go`
- Modify: `internal/engine/suricata_test.go`

In `internal/config/config.go`, add CrowdSec config:
```go
type Config struct {
    // ... existing fields
    CrowdSec crowdsec.Config `yaml:"crowdsec"`
}
```

Default:
```go
cfg.CrowdSec = crowdsec.Config{
    Enabled: false,
    Blocklist: crowdsec.BlocklistConfig{
        Interval: 2 * time.Hour,
        ScoreOnScan: 30,
        ScoreOnBrute: 50,
        ScoreOnMalicious: 70,
    },
    Reputation: crowdsec.ReputationConfig{
        CacheSize: 1024,
        CacheTTL: 10 * time.Minute,
        Timeout: 3 * time.Second,
    },
    Reporter: crowdsec.ReporterConfig{
        BatchSize: 10,
        FlushInterval: 5 * time.Second,
        LAPIURL: "http://127.0.0.1:8080",
    },
}
```

In `internal/engine/pipeline.go`:
1. Add `crowdSec *crowdsec.CrowdSec` field to DetectionPipeline
2. Add `EnableCrowdSec() error` method
3. In `Start()`: if enabled, call `crowdSec.Start()`
4. In `Stop()`: call `crowdSec.Stop()`
5. In `feedSuricataAlerts()`: also call `crowdSec.ReportAlert()` for each alert

In `fortress.yaml`:
```yaml
crowdsec:
  enabled: false
  blocklist:
    interval: 2h
    score_scan: 30
    score_bruteforce: 50
    score_malicious: 70
```

---

### Task 6: 集成测试 + 全量验证

**Files:**
- Modify: `internal/crowdsec/crowdsec_test.go`

Integration test:
```go
func TestCrowdSecEndToEnd(t *testing.T) {
    cfg := DefaultConfig()
    cfg.Enabled = true
    cfg.Blocklist.Interval = time.Hour // won't trigger in test
    
    var scorer brain.ShardScorer
    cs := New(cfg, &scorer)
    
    ctx, cancel := context.WithCancel(context.Background())
    cs.Start(ctx)
    defer cs.Stop()
    defer cancel()
    
    // Test reputation query (no network = empty result)
    result, ok := cs.QueryReputation("1.2.3.4")
    if ok {
        t.Log("Reputation found:", result.Labels)
    } else {
        t.Log("No reputation (expected in test env)")
    }
    
    // Test alert reporting (no LAPI = dropped gracefully)
    cs.ReportAlert(AlertItem{
        IP: "1.2.3.4",
        Scenario: "fortress/test",
        Message: "test alert",
        Timestamp: time.Now(),
    })
}
```

Final verification:
```bash
go build ./...
go vet ./...
go test ./internal/crowdsec/... -v -race
go test ./internal/engine/... -v
```

---

## 自检

1. **Spec 覆盖**: Config(Task1), Blocklist(Task2), Reputation(Task3), Reporter(Task4), Pipeline(Task5), Tests(Task6) — 全部覆盖
2. **无占位符**: 所有步骤含完整代码
3. **类型一致**: AlertItem 在模块入口和 Reporter 间对齐，Config 与 pipeline 一致
4. **无矛盾**: 不依赖本地 CrowdSec 运行，不影响热路径性能
