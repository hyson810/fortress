# Hydra Pro — Suricata 融合设计文档

> Fortress V6 → Hydra Pro 第一阶段：吸收 Suricata 核心能力
> 日期: 2026-06-30

---

## 核心理念

保留 Fortress 的"脑子"（评分器 + 反制链 + 蜜罐），换 Suricata 的"眼睛和鼻子"（抓包 + 规则引擎 + 协议解析）。

```
                    ┌──────────────────┐
                    │   AF_PACKET 抓包   │  ← 新增
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │   包解码器         │  ← 新增
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
      ┌────────────┐  ┌────────────┐  ┌────────────┐
      │ 规则引擎     │  │ 流重组器     │  │ 协议解析器   │  ← 全部新增
      └──────┬─────┘  └──────┬─────┘  └──────┬─────┘
             └───────────────┼────────────────┘
                             ▼
                    ┌──────────────────┐
                    │   Fortress 管线    │  ← 现有，不变
                    │  (7层 + 评分器)   │
                    │  + 反制链 + 蜜罐   │
                    └──────────────────┘
```

---

## 一、AF_PACKET 抓包层

`internal/capture/`

```
internal/capture/
├── afpacket.go       # AF_PACKET 环形缓冲区 (TPACKET_V3)
├── afpacket_linux.go # Linux 特有: setsockopt, PACKET_FANOUT
├── handler.go        # CaptureHandler 接口 + 工厂
├── handler_inject.go # 注入模式兼容 (测试/无权限环境)
└── handler_test.go
```

```go
type CaptureHandler interface {
    Packets() <-chan []byte    // 原始以太帧
    Stats() CaptureStats
    Close() error
}
```

### 两种模式

| 模式 | 权限 | 性能 | 用途 |
|------|------|------|------|
| AF_PACKET | CAP_NET_RAW / root | ~10Gbps+ | 生产 |
| 注入/测试 | 无 | N/A | 开发 |

### 配置参数
- 环形缓冲区: 默认 64 帧 × 65536 字节
- Fanout: `PACKET_FANOUT_HASH`（流哈希保序）
- 模式: blocking poll + 超时

---

## 二、Suricata 兼容规则引擎

`internal/suricata/`

```
internal/suricata/
├── parser.go          # .rules 文件解析
├── parser_test.go
├── rule.go            # Rule 结构体 + 匹配逻辑
├── match.go           # 报文匹配 (content/offset/depth/dsize/flags)
├── ruleset.go         # Ruleset: 加载/重载/热更新
├── prefilter.go       # 预过滤器 (先行过滤，减少匹配量)
└── engine.go          # SuricataEngine 主入口
```

### 首批兼容语法

`alert/pass/drop`, `msg`, `content`(含 `|hex|`), `offset/depth`, `distance/within`, `nocase`, `dsize`, `flags`, `sid/rev`, `classtype`, `reference`, `metadata`, `flow`

### 解析示例

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"SQL Injection Attempt";
    content:"union|20|select"; nocase;
    classtype:web-application-attack; sid:2024210; rev:4;)
```

---

## 三、性能架构

### 三级过滤

```
包 → 预过滤器(1μs) → AC自动机匹配 → 工作池(8-16 goroutine) → 告警→评分器
```

1. **预过滤器** — 协议 + 端口 + flags + dsize，<1μs/包
2. **Aho-Corasick 自动机** — O(包长) 匹配全部规则，远快于逐条 regex
3. **工作池** — 匹配到的规则并行执行详细检测

### 零拷贝

AFPACKET mmap → 指针引用 → 只在评分时复制，减少 ~3 次拷贝/包

### 与 Fortress 7 层管线关系

- 规则引擎与现有管线**并行运行**
- 预过滤器不匹配规则 → 直接送现有管线
- 规则引擎告警 → 输入评分器，与管线告警合并打分

### 预期性能影响

| 场景 | 变化 |
|------|------|
| 无攻击背景流量 | 更快（预过滤器跳过规则层） |
| 500规则 + 攻击 | 更快（AC自动机替代逐条检测） |
| 10000规则满载 | 线速（工作池 + 预过滤器） |

---

## 四、包解码层

`internal/capture/decode.go`

- 以太帧头 → 源/目标 MAC
- IP 头 → 协议号、源/目标 IP、TOS、TTL
- TCP/UDP 头 → 端口、flags、序列号
- 负载 → 字节数组

使用 `gopacket` 层解码，限制只解码必要字段，不做完整协议树。

---

## 五、流重组器

`internal/suricata/stream.go`

TCP 流重组：
- 5-tuple 键
- 双向缓冲区（to_server / to_client）
- 超时淘汰（默认 60s）
- 每流最大 64KB
- 为 HTTP 事务探测和对 content 关键字跨越多个包场景服务

---

## 六、管线接入

`internal/engine/pipeline.go` 改动：

```
原入口: packetCh → L1 PacketInspector
新入口: capture.Packets() → gopacket decode → SuricataEngine → (告警→评分器) + (送现有管线)
```

- SuricataEngine.Start(ctx) 启动抓包 + 规则引擎 goroutine
- 管线的 Start() 内部调用 capture.Start()
- 新增 `SuricataMode` 标志位，可在 fortress.yaml 中开关
- 规则路径通过 fortress.yaml 配置

---

## 七、配置文件

```yaml
capture:
  mode: afpacket           # afpacket | inject
  interface: eth0
  buffer_frames: 64
  buffer_size: 65536

suricata:
  enabled: true
  rules_path: /etc/hydra/rules/
  default_ruleset: emerging-threats
  worker_pool: 8
  prefilter: true
```

---

## 八、依赖

```go
require (
    github.com/google/gopacket v1.1.19  // gopacket + afpacket
    golang.org/x/sys v0.30.0            // 已有
)
```

`gopacket` 是唯一新增 Go 依赖。AF_PACKET 通过 `golang.org/x/sys` 必要系统调用。

---

## 九、不做的事情（YAGNI）

- ❌ 不搞 Suricata 完整兼容（YAML 配置、Hyperscan、CUDA）
- ❌ 不搞 IPS inline（第一版只有检测）
- ❌ 不改现有评分器/反制链/蜜罐
- ❌ 不搞 Lua 脚本
- ❌ 不搞 app-layer 完整解析树（首批只做 HTTP + DNS）

---

## 十、实现顺序

1. `internal/capture/` — 包解码 + AF_PACKET + handler 接口
2. `internal/suricata/` — parser + rule + match + prefilter + engine
3. `internal/suricata/stream.go` — TCP 流重组
4. `internal/engine/pipeline.go` — 管线接入改动
5. `fortress.yaml` — 配置项
6. 集成测试 + 性能基准
