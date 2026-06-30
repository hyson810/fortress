# Fortress V6 · 独眼巨人 Cyclops

**多引擎融合的网络防御与威胁评分系统**

Fortress V6 是一个用 Go 编写的全栈网络防御平台，集成了 7 层检测管线、64 核锁自由威胁评分器、自适应蜜罐、动态响应和去中心化 P2P 协作。

## 架构概览

```
                    ┌──────────────────────────────────────┐
                    │        7层串行检测管线 (L1→L7)        │
                    │  Packet → L1 PacketInspector          │
                    │          → L2 FlowAnalyzer            │
                    │          → L3 BehaviorAnalyzer        │
                    │          → L4 DNSTunnelDetector       │
                    │          → L5 HttpInspector+Brute     │
                    │          → L6 HybridAnomalyDetector   │
                    │          → L7 FingerprintEngine       │
                    │          → 64核锁自由评分器          │
                    └──────────────────────────────────────┘
```

## 快速开始

```bash
# 编译
go build -o fortress-linux ./cmd/fortress

# 扫描模式
./fortress-linux -mode scan -target example.com

# 防御模式（蜜罐 + 管线 + 反制）
./fortress-linux -mode defend

# API 监控
curl http://localhost:9090/health
curl http://localhost:9090/threats
```

## 功能特性

- **7 层串行检测管线**：包检测 → 流量分析 → 行为基线 → DNS隧道 → HTTP检测 → 异常检测 → 指纹识别
- **64 核锁自由评分器**：无锁并发，0 内存分配，单机 3200 万次/秒评分
- **自适应蜜罐**：SSH / HTTP / MySQL 协议模拟，动态指纹和减速带
- **ARP 欺骗检测**：基于 MAC 地址变更和响应延迟
- **反制链**：Raft 共识 → 封禁 → 情报广播 → 免疫传播
- **SWIM 流行协议去中心化网格**：无中心节点的威胁情报共享
- **结构化日志**：JSON 输出，支持文件和 stdout
- **REST API**：健康检查、威胁查询、攻击注入

## 配置

复制 `fortress.yaml` 到工作目录，按需修改。

## 开源协议

Apache 2.0
