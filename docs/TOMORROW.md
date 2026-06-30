# Fortress V6 · 明天最终完工清单

**日期:** 2026-06-18  
**当前状态:** 27,264 行 · 107 文件 · 100+ 测试通过 · Windows 可编译可测试  
**明天目标:** 30,000+ 行 · Linux 实机验证 · V5 残留清零 · 护网行动就绪

---

## 一、eBPF 内核层补全 + Linux 实机部署 ⭐ 最高优先级

当前 Fortress V6 只有用户态检测。内核层（C 匕首）代码写了但没加载过。
明天把 eBPF XDP/TC 加载进内核，让 Fortress 变成真正的全栈防御：

```
数据包进网卡
  → XDP (内核, C, ~50ns): 白名单放行, 黑名单 DROP, 超速限流
  → AF_XDP (用户态, Rust): 零拷贝批量收包
  → 协议解析 (Rust, SIMD)
  → L1-L7 检测 (Go, goroutine pipeline)
  → 评分 → 决策 → 反击
```

```
▢ 1.1  在 WSL2 (Alpine 或 Kali) 里装 Go 1.23+、Rust 1.80+、clang
▢ 1.2  编译 BPF 字节码: clang -O2 -target bpf -c kernel/bpf/xdp_filter.c → xdp_filter.o
▢ 1.3  编译 BPF 字节码: clang -O2 -target bpf -c kernel/bpf/tc_egress.c → tc_egress.o
▢ 1.4  用 cilium/ebpf 加载 xdp_filter.o 到 lo 或 eth0
▢ 1.5  验证 BPF maps: whitelist(LPM_TRIE) + blacklist(LRU_HASH 10K) + rate_limit + stats
▢ 1.6  测 XDP 决策延迟: 目标 <100ns (BPF map 查找)
▢ 1.7  测 XDP DROP 吞吐: 目标线速丢包 (不受用户态 CPU 限制)
▢ 1.8  编译 Rust muscle: cargo build --release → libfortress_ffi.so
▢ 1.9  编译 Go brain: CGO_ENABLED=1 go build → fortress 二进制
▢ 1.10 跑 AF_XDP 零拷贝收包: Rust→Go ringbuf 传输验证
▢ 1.11 跑全管线: 真实网卡流量 → XDP → AF_XDP → Rust → Go → 检测 → 评分
▢ 1.12 测性能: 记录 Linux 实机 PPS、延迟、内存

目标:
  内核层 XDP DROP:    线速 (~14M PPS 小包, 不受 CPU 限制)
  用户态 AF_XDP:      >1M PPS
  全管线 (含检测):     >300K PPS (从 Windows 223K 提升)
```

## 二、V5 残留清理

```
▢ 2.1  main.go 重写: 停用 counterstrike/offense/weapons 导入
▢ 2.2  main.go 改接 V6 pipeline.go + defense/ + fusion/
▢ 2.3  删除或归档 internal/counterstrike/
▢ 2.4  删除或归档 internal/offense/
▢ 2.5  删除或归档 internal/weapons/
▢ 2.6  internal/engines/ → 确认所有引用来自 V6 pipeline.go
▢ 2.7  go vet ./... 零错误
▢ 2.8  go test ./... 全部 PASS
```

## 三、填到 30,000 行 + 修复 V3.1 增强检测 (已确认的退化)

```
缺口模块                    当前      目标      差距
────────────────────────────────────────────────────
Rust AF_XDP 实现             67     1,500    +1,433
Rust eBPF mgmt 扩展         254       900      +646
Go 引擎检测规则扩展        2,530     3,500      +970
V3.1 6特征 EMA 恢复         缺失     500       +500  ← 今天发现的退化
集成测试                      0       500      +500
────────────────────────────────────────────────────
合计                                             ~4,000
```

### V3.1 6 特征 EMA Z-Score 恢复 (engines/anomaly.go 扩展)

V3.1 Python 的 HybridAnomalyDetector 有 6 个特征维度在线学习，
V6 Go 版在迁移过程中丢失了 4 个。必须恢复：

```
▢ 3.1  pkt_size EMA        包大小分布异常检测 (分片攻击)
▢ 3.2  iat EMA             包间间隔异常 (低速率/慢速攻击)
▢ 3.3  payload_entropy EMA 载荷熵实时追踪 (加密伪装检测)
▢ 3.4  burst_count EMA     100ms 突发包数 (脉冲式攻击)
▢ 3.5  symmetry EMA        上下行流量对称性 (隧道/外泄检测)
▢ 3.6  flags_bitmask EMA   已在 V6 中 — 验证完整性

每个特征: Welford 在线方差 + EMA + 偏差 EMA, Z > 4.0 告警
目标: 低速率/加密/分段/非对称 — 四种红队绕过手段全部可检测
```

```
▢ 3.7  Rust AF_XDP: 实现 socket bind + UMEM 分配 + poll 批量收包
▢ 3.8  Rust AF_XDP: CPU core affinity 绑定
▢ 3.9  Rust eBPF mgmt: aya-rs 运行时 map 读写 (block_ip/unblock_ip/get_stats)
▢ 3.10 Go engines/: 每个 L1-L7 引擎加 5+ 新检测规则
▢ 3.11 Go engines/: 增加 ICMP 隧道检测、SMB 扫描检测、RDP 爆破检测
▢ 3.12 写 engine/pipeline_test.go 完整集成测试 (8→16 tests)
▢ 3.13 写 defense/sinkhole_test.go、deceptor_test.go 等
```

## 四、Kali 工具链实际集成

```
▢ 4.1  在 WSL2 Kali 装 nmap、nuclei、hydra、sqlmap、msfconsole
▢ 4.2  装 amass、gobuster、responder、john、ffuf (融合模块封装的)
▢ 4.3  逐个工具调用验证: 检查命令行参数是否正确、输出解析是否工作
▢ 4.4  跑一次 nmap→nuclei→hydra→sqlmap→msf 完整链
▢ 4.5  验证 D阶 触发 → Raft 共识 → 全武器链启动
```

## 五、护网行动准备

```
▢ 5.1  生成 aggressive.yaml 最终版 (IP 白名单填入实际 C2/队友/裁判)
▢ 5.2  写 runbook: 启动命令、监控命令、手动封禁命令、紧急停机命令
▢ 5.3  写 red-team-playbook: 护网红队常用 TTPs 及 Fortress 对应检测
▢ 5.4  Docker build + 导出 tar.gz 可携带部署包
▢ 5.5  README.md 更新 (中英文双语)
```

## 六、最终验证

```
▢ 6.1  27,000 → 30,000+ 行确认
▢ 6.2  go vet ./... 全绿
▢ 6.3  go test ./... 全绿 (100+ tests)
▢ 6.4  cargo build --release 成功
▢ 6.5  clang BPF 编译成功
▢ 6.6  Docker build 成功
▢ 6.7  护网行动部署方案验证 (按 DEPLOYMENT.md 从头走一遍)
▢ 6.8  打 tag: v6.0.0-rc1 "Cyclops · 独眼巨人"
```

---

## 明天执行顺序

```
上午:
  1. eBPF 内核加载 (XDP + TC 编译+验证)         ← 2小时
  2. V5 清理 (main.go 重写 + 删旧包)           ← 1小时
  3. 填检测规则 (engines L1-L7 加规则)          ← 1小时

下午:
  4. Rust AF_XDP 实现 + 性能测量               ← 2小时
  5. Kali 工具链验证                           ← 1小时
  6. 全量测试                                  ← 1小时

晚上:
  7. 护网行动准备 (runbook/README/Docker)      ← 1小时
  8. 最终验证 + 打 tag                         ← 30分钟
```

## 三层防御体系 (明天收工后)

```
内核层 ████████████████████  XDP DROP · 令牌桶限速 · 白名单放行
用户层 ████████████████████  AF_XDP 零拷贝 · L1-L7 检测 · 评分决策
反击层 ████████████████████  Kali 全武器链 · 蜂群免疫 · LLM 深渊
```

---

## 目标

明天结束时 Hydra-mini 应该：
- ✅ 30,000+ 行
- ✅ Linux 实机跑通 XDP + AF_XDP + Go 全管线
- ✅ V5 残留清零
- ✅ Kali 武器链实测
- ✅ Docker 一键部署
- ✅ 护网行动 ready
- ✅ 改名: Fortress V6 → Hydra-mini
- ✅ tag hydra-mini-v1.0.0
