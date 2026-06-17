# Fortress V6 — 国家级网络防御系统设计规格

**版本:** V6 (Cyclops / 独眼巨人)  
**日期:** 2026-06-17  
**状态:** 设计完成，待实现规划  
**目标规模:** 30,000 行 · 70+ 文件 · 三语言

---

## 1. 项目定位

Fortress V6 是一个**自主防御反击系统**，运行在 Linux 容器中，通过 eBPF/XDP 内核拦截 +
Go 大脑智能决策 + Rust 高性能数据面 + Kali 工具编排，实现对网络攻击的全自动检测、评分、反击。

**定位:** 国家级护网行动红蓝对抗武器。一个容器拉起完整防御环境，攻击者面对的不是一台机器，是一个有大脑、有肌肉、有武器的掠食者。

**目标平台:** Linux x86_64 (WSL2 Alpine 开发，Kali Linux/Alpine Linux 生产部署)

**开发硬件:** AMD Ryzen 5 5600U (6C/12T, Zen 3, AVX2), 16GB DDR4, 1TB SSD

---

## 2. 架构总览

### 2.1 三层七域

```
═══ Dagger Layer · C · 内核匕首 (~500行) ═══
  kernel/bpf/
    xdp_filter.c       XDP 快速路径 — 白名单/黑名单/限速
    tc_egress.c        TC 出口监控 — 数据外泄检测

═══ Muscle Layer · Rust · 高性能数据面 (~8,000行) ═══
  muscle/afxdp/        AF_XDP 零拷贝收发包 + CPU绑定
  muscle/protocol/     协议深度解析 (L2-L7, SIMD加速)
  muscle/ebpf/         eBPF 程序加载 + map 管理 (aya-rs)
  muscle/ffi/          C ABI → Go cgo 桥接 + 共享内存 RingBuf

═══ Brain Layer · Go · 智能决策面 (~21,500行) ═══
  internal/engine/     7层检测引擎 (L1-L7)
  internal/brain/      评分融合 + 四阶响应阶梯 + CVE预测
  internal/fusion/     Kali 武器编排 (nmap/nuclei/hydra/sqlmap/msf)
  internal/defense/    主动防御 (tarpit/蜜罐/防火墙/威胁情报)
  internal/swarm/      蜂群网络 (SWIM/Raft/免疫广播/NaCl加密)
  internal/deception/  欺骗系统 (LLM递归深渊/数字替身/数据投毒)
  internal/stealth/    隐身术 (看门狗/Argon2id/反调试)
  internal/mcp/        MCP AI 控制面 (9工具)
  cmd/fortress/        入口 + CLI + 模式分发
```

### 2.2 行数预算

| 层 | 语言 | 文件数 | 行数 | 占比 |
|----|------|--------|------|------|
| 内核匕首 | C | 3 | 500 | 2% |
| 肌肉引擎 | Rust | 18 | 8,000 | 27% |
| 大脑 | Go | 50+ | 21,500 | 71% |
| **总计** | | **70+** | **30,000** | **100%** |

---

## 3. 数据流

```
NIC 中断
  → XDP 快速路径 (C, ~50ns): 白名单→PASS, 黑名单→DROP, 超速→DROP, 其他→REDIRECT
  → AF_XDP 零拷贝 (Rust, ~100ns/pkt): UMEM共享内存 → CPU绑定批处理64包 → PacketContext
  → 协议解析 (Rust, SIMD): L2 EtherType→VLAN→L3 IPv4/v6→L4 TCP/UDP/ICMP
  → 共享内存 RingBuf (Rust→Go, ~10ns): 原子写 → Go侧非阻塞轮询 → 零拷贝指针
  → L1-L7 检测引擎 (Go, goroutine): channel串联, 每层独立
  → 评分融合 (Go, 13检测器加权): TotalScore = Σ(weight_i × score_i)
  → 四阶响应决策:
    A阶 (0-25): 静默记录
    B阶 (25-50): WHOIS + 限速 + 滥用报告
    C阶 (50-75): Tarpit + 蜜罐 + eBPF封禁 + 攻击者扫描
    D阶 (75-100): LLM深渊 + 全武器链 + 蜂群免疫 (需Raft N/2+共识)
  → 反击执行 (Go + Kali): 按阶执行对应动作
```

### 3.1 性能目标

| 指标 | 目标 | 瓶颈 |
|------|------|------|
| XDP 决策延迟 | ~50ns | BPF map查找 |
| AF_XDP 用户态延迟 | ~100ns/pkt | poll() 批处理 |
| Rust→Go 传递延迟 | ~10ns | atomic write |
| L1-L7 全管线延迟 | <1µs/pkt | goroutine channel + 锁 |
| 评分→反击决策 | <10ms | 跨IP关联计算 |
| D阶全武器链 | ~5s | Kali外部进程 + 网络I/O |

---

## 4. 响应阶梯 (四阶 A/B/C/D)

### A阶 · 静默观察 (0-25分)
- 触发: 碎片化扫描、单次探测、低速率异常
- 动作: JSONL日志 + pcap环形缓冲dump + 终端提示
- **不暴露存在**

### B阶 · 主动侦查 (25-50分)
- 触发: SYN洪水持续、慢速扫描、DNS隧道、蜜罐触碰
- 动作: A阶全部 + WHOIS/RDAP查询 + ASN归属 + Shodan查IP + nftables限速(10req/min) + 生成滥用报告草稿
- **不主动攻击**

### C阶 · 掠食者模式 (50-75分)
- 触发: 3+检测器同时告警、JA3匹配恶意工具、蜜罐交互、跨IP协同
- 动作: B阶全部 + TCP Tarpit + 动态蜜罐 + nftables永久封禁 + 蜂群广播 + nmap/nuclei扫描攻击者 + 发送滥用报告
- **不主动利用漏洞**

### D阶 · 黑洞反击 (75-100分)
- 触发: 持续高分、APT特征、蜂群多数节点同意(Raft >N/2)、确认非误报
- 动作: C阶全部 + LLM递归深渊蜜罐 + 数据投毒 + Kali全武器链(nmap→nuclei→hydra→sqlmap→msf) + eBPF XDP_DROP内核丢包 + 蜂群免疫永久封锁 + 证据加密存档
- **需人工预授权首次启用**

### 安全控制
- D阶必须人工预授权才能首次启用
- 白名单IP永远不超过B阶
- 每次跃阶记录不可篡改审计日志
- 30分钟无活动自动降级到A阶

---

## 5. Go 大脑详细设计

### 5.1 检测引擎 (internal/engine/) ~6,000行

| 层 | 模块 | 行数 | 检测内容 | 算法 |
|----|------|------|----------|------|
| L1 | packet.go | 500 | SYN/UDP/ICMP洪水·端口扫描·ARP欺骗 | 滑动窗口+环形缓冲 |
| L2 | flow.go | 600 | 5元组流追踪·多窗口端口扫描 | 256分片哈希+三窗口计数器 |
| L3 | behavior.go | 400 | 流量熵偏离基线 | Welford在线+sigma偏离 |
| L4 | dns.go | 400 | DNS隧道(熵+长度+频率) | Shannon熵+阈值 |
| L5 | http.go | 800 | TCP流重组·SQLi/XSS/遍历 | 序列号重组+Regex |
| L5 | bruteforce.go | 300 | SSH/HTTP爆破 | 每秒连接计数 |
| L6 | anomaly.go | 800 | 6特征EMA Z-Score+CMS | EMA+Welford+CMS 4×65536 |
| L7 | fingerprint.go | 800 | JA3/JA4 TLS+被动OS | ClientHello解析+TTL/窗口匹配 |

### 5.2 大脑决策 (internal/brain/) ~3,500行

- **scorer.go (800行):** 13检测器加权融合、每IP ThreatRecord、256分片互斥锁、BoltDB持久化
- **ladder.go (600行):** 四阶响应阶梯、D阶Raft共识、自动降级、白名单封顶B阶
- **correlation.go (500行):** 子网邻居加成×1.3、同检测器关联×1.2、分布式攻击乘数×1.5
- **decay.go (300行):** 指数衰减 score×e^(-λt)、半衰期30min、惰性计算
- **predict.go (800行):** 代码知识图谱→CWE、服务版本→CVE映射、eBPF规则自动生成

### 5.3 Kali 武器融合 (internal/fusion/) ~2,000行

**核心原则: 不自己造武器。编排Kali现有最强工具。**

| 模块 | 编排工具 | 解析 | 触发阶 |
|------|----------|------|--------|
| nmap.go | nmap -sS -sV -sC -O --script vuln | XML→PortInfo | C |
| nuclei.go | nuclei -u target -jsonl | JSONL→Finding | C |
| hydra.go | hydra -L user -P pass ssh://target | stdout→Credential | D |
| sqlmap.go | sqlmap -u url --batch | API pipe→VulnReport | D |
| msf.go | msfconsole -x "use exploit; run" | XMLRPC→Session | D |
| chain.go | 多武器攻击链编排 | nmap→nuclei→hydra→sqlmap→msf | D |

### 5.4 其他子系统

- **internal/defense/ (~2,500行):** tarpit(600) + honeypot(800) + firewall(500) + intel(600)
- **internal/swarm/ (~2,100行):** gossip(700) + consensus(600) + immunity(500) + crypto(300)
- **internal/deception/ (~1,900行):** abyss(800) + mirror(600) + poison(500)
- **internal/stealth/ (~900行):** watchdog(400) + crypt(300) + anti-debug(200)
- **internal/mcp/ (~1,500行):** server.go + tools.go (9个AI代理工具)
- **cmd/fortress/ (~500行):** main.go CLI + 模式分发 + 信号处理

---

## 6. Rust 肌肉详细设计

### 6.1 AF_XDP 子模块 (~1,500行)
- **socket.rs (400行):** AF_XDP套接字创建、绑定网卡队列
- **umem.rs (500行):** UMEM巨型页内存分配、Fill/Completion环管理
- **dispatcher.rs (600行):** CPU核心绑定(core_affinity)、poll()批量读64包、推送RingBuf

### 6.2 协议解析子模块 (~2,300行)
- **parser.rs (800行):** L2/L3/L4协议解析、纯Rust零unsafe、SIMD加速
- **tls.rs (600行):** TLS ClientHello字段提取、JA3/JA4哈希
- **dns.rs (400行):** DNS消息解析
- **http.rs (500行):** HTTP请求/响应解析

### 6.3 eBPF 管理子模块 (~900行)
- **loader.rs (500行):** aya-rs加载BPF字节码、附加XDP/TC程序
- **maps.rs (400行):** 运行时BPF map读写

### 6.4 FFI 桥接子模块 (~1,100行)
- **bridge.rs (600行):** `extern "C" fn` 接口暴露给Go cgo
- **ringbuf.rs (500行):** lock-free SPSC环形缓冲区 (Rust写Go读)

---

## 7. C 内核匕首详细设计

### xdp_filter.c (200行)
- BPF Maps: whitelist(LPM_TRIE), blacklist(LRU_HASH 10K), rate(LRU_HASH 50K), stats(PERCPU_ARRAY)
- 逻辑: 白名单→PASS → 黑名单→DROP → 令牌桶超速→DROP → 采样→REDIRECT AF_XDP

### tc_egress.c (200行)
- BPF Maps: egress_stats(LRU_PERCPU_HASH), egress_alerts(PERF_EVENT_ARRAY)
- 逻辑: 每目标IP计数→60s窗口→1MiB阈值→perf_event告警→窗口重置

---

## 8. 容器交付

```
fortress-v6.oci
├── /usr/local/bin/fortress            # Go 大脑二进制 (静态链接)
├── /usr/local/lib/libmuscle.so        # Rust 肌肉动态库
├── /usr/local/lib/bpf/fortress_kern.o # eBPF 字节码
├── /usr/share/kali/                   # Kali 600+ 工具
├── /etc/fortress/fortress.yaml        # 默认配置
└── /var/lib/fortress/                 # 运行时数据 (威胁DB/证据/pcap)

启动:
  docker run --privileged --network host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    fortress-v6 defend
```

---

## 9. 测试策略

### 四层金字塔
- **L1 基准:** 50+ 场景 (吞吐/延迟/内存/CPU)，CI门禁
- **L2 单元:** 500+ 测试 (每个引擎/解析器/决策函数独立)
- **L3 集成:** 100+ 测试 (多引擎联动、Go↔Rust FFI、Swarm多节点)
- **L4 E2E:** 20 场景 (完整攻击链→检测→评分→反击)

### 20个E2E攻防场景
涵盖: SYN洪水、UDP洪水、慢速扫描、DNS隧道、SQL盲注、SSH爆破、JA3伪造、OS欺骗、蜜罐触碰/交互、蜂群免疫、Raft共识、数据外泄、Slowloris、友军火力、全引擎饱和、蜂群分区、Rust FFI压力、Kali全链、红蓝终极对决

### CI性能门槛
- XDP延迟 <100ns
- AF_XDP吞吐 >1M PPS
- Rust解析 >5M PPS/核
- Go检测 >500K PPS
- 评分决策 <10ms
- 10K IP内存 <500MB
- 容器启动 <5s

---

## 10. 技术栈

| 组件 | 选型 | 理由 |
|------|------|------|
| 大脑语言 | Go 1.23+ | goroutine并发、cilium/ebpf、静态二进制、开发效率 |
| 肌肉语言 | Rust 1.80+ | 零成本抽象、无GC抖动、SIMD、内存安全、aya-rs |
| 匕首语言 | C (clang) | BPF唯一选择 |
| eBPF库(Rust) | aya-rs | 纯Rust、无libbpf依赖 |
| eBPF库(Go) | cilium/ebpf | Go标准eBPF库 |
| 配置 | YAML (gopkg.in/yaml.v3) | 成熟稳定 |
| 持久化 | BoltDB | 嵌入式、零依赖、ACID |
| 加密 | NaCl secretbox + Argon2id + AES-256-GCM | 抗量子前安全 |
| 蜂群签名 | Ed25519 | 快速、小签名、抗侧信道 |
| 容器 | Docker/OCI 或 systemd-nspawn | 一条命令部署 |
| MCP协议 | stdio JSON-RPC | AI代理标准协议 |

---

## 11. 设计决策记录

1. **Go + Rust + C 三语言而非纯Go:** V5证明了纯Go的局限。Rust做热路径极致性能，Go做智能决策快速开发
2. **Kali工具编排而非自造武器:** 287行包装 vs 10,000行自造，质量和维护成本天壤之别
3. **共享内存RingBuf而非gRPC:** 1M PPS时序列化开销不可接受
4. **OCI容器而非静态二进制:** Kali 600+工具链必须一起打包
5. **独眼巨人单进程而非三哨兵:** 消除跨平台弱点，一个大脑统一决策
6. **D阶需Raft共识:** 战争级别的反击必须有分布式授权
