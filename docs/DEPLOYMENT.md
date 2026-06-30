# Fortress V6 护网行动部署手册

**版本:** V6 (Cyclops / 独眼巨人)
**日期:** 2026-06-17
**环境:** WSL2 Alpine Linux · AMD Ryzen 5 5600U · 16GB DDR4 · 1TB SSD
**语言:** 简体中文

---

## 1. 硬件画像与性能预算

### 1.1 硬件规格

| 组件 | 规格 | 备注 |
|------|------|------|
| CPU | AMD Ryzen 5 5600U (6C/12T, Zen 3, AVX2) | 基础 2.3GHz, 加速 4.2GHz |
| 内存 | 16GB DDR4-3200 | WSL2 默认分配 8GB，建议调整至 12GB |
| 存储 | 1TB NVMe SSD | 证据留存充足 (~200GB 预算) |
| 网卡 | 集成 Realtek/WiFi 6 | XDP generic 模式（无硬件卸载） |
| 系统 | Windows 11 Pro + WSL2 Alpine 3.21 | 单机防御，非分布式 |

### 1.2 性能预算（基于此硬件实测估算）

| 指标 | 预算 | 说明 |
|------|------|------|
| XDP 包处理 | ~500K PPS | generic 模式，非 native |
| Go 引擎吞吐 | ~200K PPS | 6C/12T，goroutine 并发 |
| Rust 协议解析 | ~2M PPS/核 | SIMD 加速，Zen 3 AVX2 |
| 内存占用 | ~2GB 稳态，~4GB 峰值 | 含 Kali 工具缓存 |
| 磁盘 I/O | 500MB/s 顺序写 | NVMe，pcap/日志写入 |
| 并发追踪 IP 数 | ~10,000 | BoltDB 持久化 |
| 容器启动 | <10s | 含 Kali 工具链初始化 |

### 1.3 WSL2 配置优化

```powershell
# Windows 端: %USERPROFILE%\.wslconfig
[wsl2]
memory=12GB
processors=8
swap=4GB
networkingMode=mirrored
dnsTunneling=true
firewall=false
```

```bash
# 验证 WSL2 资源配置
cat /proc/meminfo | grep MemTotal
nproc
```

---

## 2. 战前检查清单

### 2.1 操作系统加固

```bash
# === 内核参数调优 ===
cat >> /etc/sysctl.d/99-fortress.conf <<'EOF'
# 网络缓冲区
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 4000

# BPF 资源限制
kernel.unprivileged_bpf_disabled = 0
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 0
net.core.bpf_jit_kallsyms = 1

# 连接追踪
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 300

# 文件描述符
fs.file-max = 2097152
fs.nr_open = 2097152

# SYN flood 防护 (护网A阶自带，此处为OS兜底)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# 禁用IP转发(防御节点非路由器)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 安全基线
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
EOF

sysctl --system

# === 资源限制 ===
cat >> /etc/security/limits.conf <<'EOF'
*    hard  nofile  2097152
*    soft  nofile  2097152
*    hard  memlock unlimited
*    soft  memlock unlimited
EOF
```

### 2.2 依赖安装

```bash
# === Alpine 包安装（在 WSL2 Alpine 容器内） ===
apk update && apk add --no-cache \
    # 编译工具链
    go rust cargo clang lld llvm-dev musl-dev make \
    # BPF 开发
    libbpf-dev bpftool linux-headers \
    # 网络工具
    nmap nmap-scripts nmap-nselibs \
    whois curl wget tcpdump ngrep \
    # 运行时依赖
    libgcc libstdc++ libpcap-dev \
    # 密码学
    libsodium-dev argon2-dev \
    # 容器工具
    docker docker-cli-buildx \
    # 日志
    logrotate jq \
    # Kali 核心工具（手动遴选）
    hydra

# === Nuclei（Go 二进制）===
wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip \
    -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# === 校验版本 ===
go version      # ≥ 1.23
rustc --version # ≥ 1.80
clang --version # ≥ 17
nuclei --version
nmap --version
```

### 2.3 构建步骤

```bash
# 进入仓库根目录
cd ~/fortress-v6

# 完整构建（三阶段：BPF → Rust → Go）
make build

# 分步构建（故障排查用）
make build-bpf     # clang -O2 -target bpf → xdp_filter.o, tc_egress.o
make build-rust    # cargo build --release → libfortress_ffi.so
make build-go      # go build -o fortress ./cmd/fortress/
```

### 2.4 战前验证清单

```bash
# === 编译产物检查 ===
ls -la fortress                                    # Go 二进制 (约 30-50MB)
ls -la muscle/target/release/libfortress_ffi.so     # Rust 动态库 (约 5-10MB)
ls -la kernel/bpf/xdp_filter.o kernel/bpf/tc_egress.o  # BPF 字节码
file fortress                                     # ELF 64-bit LSB, statically linked

# === 单元测试 ===
make test

# === 静态检查 ===
make vet

# === 冒烟测试（A 阶安全模式，无反击） ===
./fortress --mode defend --config fortress.yaml &
sleep 3
# 发送测试流量验证引擎工作
nmap -sS -p 22,80,443 localhost
kill %1

# === BPF 加载验证 ===
bpftool prog list | grep xdp
bpftool map list

# === 日志输出检查 ===
cat logs/fortress-*.jsonl | tail -5
```

**检查通过标准:**
- [ ] Go/Rust/BPF 三组件全部编译成功
- [ ] 单元测试 0 失败
- [ ] `go vet` 0 警告
- [ ] 冒烟测试中 nmap 扫描被检测（日志有 SYN scan 事件）
- [ ] BPF 程序成功加载到内核
- [ ] 配置白名单 IP 未被误拦

---

## 3. OCI 容器构建

### 3.1 Dockerfile 说明

```
# 多阶段构建（优化后）
Stage 1 (当前 Dockerfile): Alpine 3.21 基础镜像 + Kali 工具 + 二进制
  - 基础层: alpine:3.21 (~7MB)
  - 工具层: nmap, hydra, whois, nftables (~50MB)
  - 应用层: fortress Go 二进制 + Rust .so + BPF .o (~60MB)
  - 总镜像: ~120MB（不含 nuclei 模板）
```

### 3.2 镜像构建

```bash
# === 构建镜像 ===
docker build -t fortress-v6:latest .

# === 打标签（推送到内部仓库） ===
docker tag fortress-v6:latest fortress-registry.internal:5000/fortress-v6:$(date +%Y%m%d-%H%M)
docker tag fortress-v6:latest fortress-registry.internal:5000/fortress-v6:latest

# === 推送 ===
docker push fortress-registry.internal:5000/fortress-v6:latest

# === 导出离线包（无网络环境） ===
docker save fortress-v6:latest | gzip > fortress-v6-$(date +%Y%m%d).tar.gz
```

### 3.3 运行时挂载

| 宿主机路径 | 容器路径 | 用途 | 必需 |
|-----------|----------|------|------|
| `/sys/fs/bpf` | `/sys/fs/bpf` | BPF 文件系统（持久化 maps） | 是 |
| `/var/lib/fortress` | `/var/lib/fortress` | 威胁数据库、证据、pcap | 是 |
| `/var/log/fortress` | `/var/log/fortress` | 审计日志、运行日志 | 是 |
| `/etc/fortress` | `/etc/fortress` | 配置文件、规则目录 | 是 |

### 3.4 `--privileged` 与 `--network host` 必要性

| 参数 | 原因 | 替代方案 |
|------|------|---------|
| `--privileged` | 加载 BPF 程序 + 访问 `/sys/fs/bpf` + 创建 AF_XDP 套接字 | `--cap-add=CAP_BPF,CAP_NET_ADMIN,CAP_SYS_ADMIN`（不完整，生产不用） |
| `--network host` | XDP 附加到物理网卡 + AF_XDP 零拷贝 + 蜂群直接通信 | 无替代，桥接/NAT 会破坏 XDP 数据路径 |

**安全权衡:** `--privileged` 使容器拥有完整内核能力，这在护网环境中是可接受的（防御节点就是堡垒本身），但在日常非演习期间应降级运行。

---

## 4. 部署拓扑

### 4.1 单节点防御配置（本次护网）

```
                        护网网络边界
                             |
                    ┌────────┴────────┐
                    │   宿主机网卡      │
                    │  (eth0 / wlan0)  │
                    └────────┬────────┘
                             |
                    ┌────────┴────────┐
                    │  XDP 快速路径   │ ← 内核 eBPF (C)
                    │ 白名单→PASS     │
                    │ 黑名单→DROP     │
                    │ 限速→限速后PASS  │
                    └────────┬────────┘
                             | AF_XDP 重定向
                    ┌────────┴────────┐
                    │  AF_XDP 用户态  │ ← Rust 肌肉层
                    │  协议解析 + SIMD │
                    │  JA3/JA4 指纹   │
                    └────────┬────────┘
                             | 共享内存 RingBuf
                    ┌────────┴────────┐
                    │  Go 大脑引擎    │ ← 7 层检测 + 评分
                    │  L1-L7 Pipeline │
                    └────────┬────────┘
                             |
                    ┌────────┴────────┐
                    │  评分融合       │
                    │  13 检测器加权  │
                    └────────┬────────┘
                             |
              ┌──────────────┼──────────────┐
              │              │              │
         A阶 (0-25)    B阶 (25-50)   C阶 (50-75)  D阶 (75-100)
         静默记录      主动侦查      掠食者模式    黑洞反击
              │              │              │              │
         JSONL 日志    WHOIS+限速    Tarpit+封禁    LLM深渊+全链
```

### 4.2 多节点蜂群（可选扩展）

```bash
# 节点A（主防御，本机）
./fortress --mode defend --config fortress-a.yaml

# 节点B（辅助，需要另一台机器）
# fortress-b.yaml:
#   swarm.peers: ["192.168.1.100:9700"]
#   swarm.name: "hive-02"
./fortress --mode defend --config fortress-b.yaml
```

**蜂群拓扑:**
```
  Node-A (Leader)          Node-B (Follower)
    | 192.168.1.100           | 192.168.1.101
    |                         |
    +-------- SWIM ----------+
    |    Gossip 免疫广播      |
    +------- Raft ----------+
        共识投票 (D阶)
```

### 4.3 启动命令

```bash
# === 标准防御模式（护网主模式） ===
docker run --privileged --network host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /var/lib/fortress:/var/lib/fortress \
    -v /var/log/fortress:/var/log/fortress \
    -v /etc/fortress:/etc/fortress \
    -e FORTRESS_GOSSIP_KEY="$(cat /etc/fortress/gossip.key)" \
    --name fortress-defender \
    --restart=unless-stopped \
    fortress-v6:latest \
    --mode defend --config /etc/fortress/fortress.yaml

# === 混合模式（防御 + 主动融合扫描） ===
docker run ... fortress-v6:latest --mode fusion --config /etc/fortress/fortress.yaml
```

---

## 5. 配置调优（fortress.yaml）

### 5.1 护网专用配置

```yaml
# fortress-hardened.yaml — 护网行动激进配置
swarm:
  name: "hw2026-node01"
  bind: "0.0.0.0:9700"
  peers: []                         # 单机部署，无蜂群
  gossip_key: "env://FORTRESS_GOSSIP_KEY"

engine:
  xdp_mode: "generic"               # WSL2 无 native 模式
  af_xdp_queue: 0
  max_pps: 1000000                  # 入站速率上限
  cpu_pin: [2, 3, 4, 5]            # 护网期间多分配核心

brain:
  rules_dir: "/etc/fortress/rules.d"
  ml_model: ""                      # 启用后将加载 CVE 预测模型
  auto_counterstrike: false         # D阶仍需人工预授权
  counterstrike_threshold: 75.0     # D阶阈值（默认 85）
  ban_duration: 7200                # 封禁时长 2 小时（护网期间 2 小时）

  # === 护网激进阈值覆盖 ===
  aggressive_mode: true             # 启用激进模式
  aggressive:
    b_threshold: 20                 # 默认 25，提前进入主动侦查
    c_threshold: 45                 # 默认 50，提前进入掠食者模式
    d_threshold: 70                 # 默认 75，提前进入黑洞反击
    decay_half_life: 45             # 默认 30min，延长记忆
    correlation_multiplier: 1.5     # 关联加分加倍
    honeypot_touch_weight: 25       # 蜜罐触碰权重提升（默认 15）

weapons:
  nmap_bin: "/usr/bin/nmap"
  nuclei_bin: "/usr/local/bin/nuclei"
  hydra_bin: "/usr/bin/hydra"
  wordlists: "/usr/share/wordlists"
  max_concurrent: 80                # 护网期间提升并发

whitelist:
  # === 本机回环 ===
  - "127.0.0.1"
  - "::1"
  # === 可信内网段 ===
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  # === 队友/裁判 IP（关键！逐条确认） ===
  - "192.168.100.0/24"              # 蓝队内部网络
  - "10.10.0.0/16"                  # 裁判/监控系统
  # === 护网平台（根据实际情况填写） ===
  # - "x.x.x.x/32"                  # 裁判评分系统
  # - "y.y.y.y/32"                  # 协同蓝队 C2

log_dir: "/var/log/fortress"
evidence_dir: "/var/lib/fortress/evidence"
pcap_dir: "/var/lib/fortress/pcap"
```

### 5.2 白名单管理关键原则

```
核心规则: 白名单 IP 永远不会超过 B 阶。不会触发 C/D 阶反击。
```

- **必须在战前添加:** 队友 IP、协同蓝队 C2、裁判系统、护网平台 IP
- **严禁遗漏:** 遗漏白名单的队友将被系统自动反击
- **运行中动态添加:** 通过 MCP 工具 `tools/whitelist` 或在 `fortress.yaml` 中添加后发送 `SIGHUP`
- **验证方法:** `grep "whitelist" logs/fortress-*.jsonl | jq '.src_ip' | sort -u`

### 5.3 蜜罐端口选择

```yaml
# /etc/fortress/rules.d/honeypots.yaml
honeypots:
  - port: 22
    service: "OpenSSH 8.9"
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  - port: 3306
    service: "MySQL 5.7"
    banner: "5.7.42-0ubuntu0.18.04.1"
  - port: 6379
    service: "Redis 6.0"
    banner: "NOAUTH Authentication required."
  - port: 8080
    service: "Tomcat 9.0"
    banner: "Apache Tomcat/9.0.65"
  - port: 9200
    service: "Elasticsearch 7.10"
    banner: '{"name":"node-01","cluster_name":"prod-es","version":{"number":"7.10.2"}}'
```

### 5.4 日志轮转

```
# /etc/logrotate.d/fortress
/var/log/fortress/*.jsonl {
    hourly
    rotate 48
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        docker exec fortress-defender kill -HUP 1
    endscript
}
```

---

## 6. 交战规则 (Rules of Engagement)

### 6.1 ABCD 四阶响应对照表

| 阶段 | 分数 | 名称 | 护网场景触发条件 | 响应动作 |
|------|------|------|-----------------|---------|
| **A** | 0-25 | 静默观察 | 单次探测、慢速扫描、低速率 ping | JSONL 记录 + pcap 环形缓冲 + 不暴露存在 |
| **B** | 25-50 | 主动侦查 | SYN 持续、蜜罐触碰、DNS 隧道、多端口慢扫 | WHOIS/RDAP + ASN 归属 + nftables 限速(10req/min) + 滥用报告 |
| **C** | 50-75 | 掠食者 | 3+ 检测器告警、JA3 匹配 C2 工具、蜜罐交互、跨 IP 协同 | TCP Tarpit + 蜜罐 + nftables 封禁 + nmap 反击扫描 + nuclei 漏洞扫描 |
| **D** | 75-100 | 黑洞 | 持续高分、APT 特征、Raft 多数确认 | LLM 深渊蜜罐 + Kali 全武器链 + XDP_DROP 内核丢包 + 蜂群免疫 |

### 6.2 升级决策矩阵

```
情境                          推荐动作          理由
────────────────────────────────────────────────────────
单个端口 SYN 扫描             A阶 记录          常见扫描，不应激
连续 100+ 端口 SYN (1min)     B阶 限速          明显扫描行为，主动遏制
JA3 = Cobalt Strike           C阶 封禁+反击     明确攻击工具特征
蜜罐被触碰 1次                B阶 限速          可能误碰
蜜罐被交互 >3次               C阶 封禁+扫描     确有攻击意图
尝试 ssh 爆破 10+ 次           C阶 封禁          明确暴力破解
nuclei 检测到 RCE              D阶（确认后）    已存在漏洞利用
数据外泄检测 >1MiB/60s         D阶 紧急隔离      数据正在外流
队友 IP (白名单内)            永不超 B阶        友军火力保护
未知 IP 持续 20+ 分钟高分      D阶（投票）      确认为持续攻击者
```

### 6.3 友军火力防护

```bash
# === 战前必须执行的友军验证 ===
# 1. 列出所有白名单
cat /etc/fortress/fortress.yaml | yq '.whitelist[]'

# 2. 验证白名单 IP 不会被封禁
echo "10.0.0.5" | nc -w1 localhost 9999  # MCP whitelist/check

# 3. 向协同蓝队分发防御节点 IP 列表
#    "我们的防御节点 IP 列表: 192.168.x.x/32"
#    "请将我们的 IP 加入你们的白名单"

# 4. 建立带外通信渠道（微信/钉钉/对讲机）
#    如检测到我方 IP 被误拦，立即告知
```

### 6.4 护网法律边界

```
=== 护网行动框架内合法 ===
+ 被动流量监控与检测
+ 主动扫描攻击者 IP (nmap/nuclei)
+ eBPF 封禁攻击者 IP (XDP_DROP)
+ TCP Tarpit (连接保持，不破坏)
+ 蜜罐部署 (模拟服务)
+ 滥用报告自动生成
+ 数据投毒 (向攻击者返回虚假数据)

=== 严格禁止（即使在护网框架内） ===
- 攻击攻击者的第三方基础设施
- 利用对方的漏洞写入代码或持久化
- 破坏攻击者的系统
- 攻击护网裁判系统
- 干扰护网平台正常评分
- 向攻击者发起 DDoS
```

---

## 7. 红队对抗策略

### 7.1 常见红队工具及检测方法

| 红队工具 | 特征 | Fortress V6 检测引擎 |
|---------|------|---------------------|
| **Cobalt Strike** | JA3: `a0e9f5d64349fb131...`, DNS Beacon 心跳, 443/80/8080 端口 | L7 JA3 指纹 + L4 DNS 隧道 + L2 流量熵 |
| **Metasploit** | JA3: `6734f37431670b3a...`, 默认 meterpreter UA, 多阶段 shellcode | L7 JA3 指纹 + L5 HTTP UA 解析 |
| **Nmap** | SYN 扫描特征 (-sS), NULL/FIN/Xmas 探针, 端口序列模式 | L1 SYN 洪水 + L2 多窗口端口扫描 |
| **Sqlmap** | User-Agent: `sqlmap/1.x`, SQLi payload 模式, 时间盲注延迟 | L5 HTTP SQLi regex + L5 时序异常 |
| **Hydra** | 高频 SSH/RDP 连接, 密码字典时序, 失败-重试模式 | L5 爆破检测 (每秒连接计数) |
| **DNS Tunnel** | 高熵长域名查询, TXT/MX 非标准记录, 每请求唯一子域 | L4 DNS 熵 + 长度 + 频率 |
| **BloodHound** | LDAP/SMB 枚举, SharpHound 特征查询, AD 对象遍历 | L6 行为异常 + L3 流量基线偏移 |
| **Impacket** | SMB/RPC 工具集, wmiexec/smbexec 特征 DCE/RPC | L2 五元组流追踪 + L6 异常 |
| **Empire** | JA3: `b386946a5e...`, PowerShell 信标, HTTP GET/POST 交替 | L7 JA3 + L5 HTTP 模式 |

### 7.2 JA3/JA4 已知 C2 指纹库

```json
// /etc/fortress/rules.d/fingerprints.json
{
  "ja3_hashes": {
    "a0e9f5d64349fb131...": {"name": "Cobalt Strike 4.9", "severity": 80},
    "6734f37431670b3a...": {"name": "Metasploit 6.3", "severity": 75},
    "b386946a5e...": {"name": "Empire 5.x", "severity": 70},
    "7b4b4f4e...": {"name": "Sliver", "severity": 72},
    "d8e8fca2dc0f896f...": {"name": "Brute Ratel C4", "severity": 78}
  },
  "ja4_hashes": {
    "t13d1516h2_8daaf6152771_b186a0e5e2dd": {"name": "Cobalt Strike 4.10", "severity": 82},
    "t13d1516h2_002f1e7e7546_3c1cfc2cc0cc": {"name": "Metasploit 6.4", "severity": 76}
  }
}
```

### 7.3 常见 APT TTP 及对应响应

| TTP | MITRE ATT&CK | 检测点 | Fortress 响应 |
|-----|-------------|--------|-------------|
| 初始侦察 | T1595 | L1 端口扫描 + L2 流追踪 | A→B 升级：限速 + WHOIS |
| 漏洞利用 | T1190 | L5 HTTP 异常 + nuclei 规则匹配 | C 阶：封禁 + 蜜罐转移 |
| C2 建立 | T1071 | L7 JA3/JA4 + L4 DNS 隧道 | C 阶：tarpit 干扰 + 报告 |
| 横向移动 | T1021 | L3 内网流量基线偏移 | C 阶：封禁 + 蜂群广播 |
| 凭据窃取 | T1003 | L5 爆破 + L6 异常行为 | C 阶：封禁 + 蜜罐凭证投毒 |
| 数据外泄 | T1041 | TC 出口监控 1MiB/60s | D 阶：紧急隔离 + 数据投毒 |

### 7.4 欺骗策略

```
=== 蜜罐 + 数字替身联动 ===
红队常见玩法 → Fortress 欺骗反击

1. 红队扫描端口  → 返回虚假开放端口 (动态蜜罐)
2. 红队尝试 SSH   → 引导入 LLM 深渊 (GPT 对话式无限交互)
3. 红队跑漏洞扫描 → 返回虚假 "漏洞" (诱导浪费资源)
4. 红队下载 payload → 返回数据投毒文件 (混淆取证)
5. 红队扫描到 "资产" → 数字替身 (虚假的整个 C 段)
```

---

## 8. 操作流程

### 8.1 启动序列

```bash
# === 步骤 1: 确认配置文件正确 ===
cat /etc/fortress/fortress.yaml | yq '.whitelist'  # 检查白名单
grep aggressive /etc/fortress/fortress.yaml          # 确认激进模式

# === 步骤 2: 预创建目录结构 ===
mkdir -p /var/lib/fortress/{evidence,pcap} /var/log/fortress

# === 步骤 3: 启动容器（后台运行） ===
docker run -d \
    --privileged --network host \
    --name fortress-defender \
    --restart=unless-stopped \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /var/lib/fortress:/var/lib/fortress \
    -v /var/log/fortress:/var/log/fortress \
    -v /etc/fortress:/etc/fortress \
    -e FORTRESS_GOSSIP_KEY="$(cat /etc/fortress/gossip.key)" \
    fortress-v6:latest \
    --mode defend --config /etc/fortress/fortress.yaml

# === 步骤 4: 验证启动成功 ===
sleep 3
docker logs fortress-defender --tail 20
docker exec fortress-defender bpftool prog list | grep xdp
docker exec fortress-defender ls /sys/fs/bpf/

# === 步骤 5: 确认 MCP 服务可用 ===
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock
```

### 8.2 运行监控

```bash
# === 实时日志监控 ===
tail -f /var/log/fortress/fortress-$(date +%Y%m%d).jsonl | jq 'select(.score > 25)'

# === 威胁总览（MCP） ===
# 通过 MCP 工具 status 查询
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status"}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# === 当前封禁列表 ===
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block_list"}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# === 资源监控 ===
docker stats fortress-defender
watch -n 5 'free -h && df -h /var/lib/fortress'
```

### 8.3 手动控制

```bash
# === 手动封禁 IP ===
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","arguments":{"ip":"x.x.x.x","reason":"manual"}}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# === 手动解封 IP ===
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unblock","arguments":{"ip":"x.x.x.x"}}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# === 手动触发反击扫描（C阶等效） ===
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"counter_scan","arguments":{"target":"x.x.x.x"}}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# === 紧急降级所有到 A阶 ===
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deescalate","arguments":{"reason":"manual intervention"}}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock
```

### 8.4 紧急关停

```bash
# === 紧急关停（保留证据） ===
# 1. 发送 SIGTERM 触发生成最终证据快照
docker exec fortress-defender kill -TERM 1
sleep 5

# 2. 停止容器
docker stop fortress-defender -t 10

# 3. 导出证据
tar czf evidence-$(date +%Y%m%d-%H%M%S).tar.gz \
    /var/lib/fortress/evidence/ \
    /var/log/fortress/

# 4. 验证证据完整性
sha256sum evidence-*.tar.gz > evidence-checksums.txt
```

### 8.5 战后流程

```bash
# === 战后证据导出 ===
# 1. 收集所有日志
cat /var/log/fortress/fortress-*.jsonl.gz | gunzip > all-events.jsonl

# 2. 生成统计报告
cat all-events.jsonl | jq -r '.score' | sort -n | \
    awk '{sum+=$1; count++} END {print "Total:", sum, "Count:", count, "Avg:", sum/count}'

# 3. 按攻击者聚合
cat all-events.jsonl | jq -r '[.src_ip, .max_score, .response_level] | @tsv' | \
    sort | awk -F'\t' '
    {
        if($2 > max[$1]) max[$1]=$2
        if($3 == "D") ever_d[$1]=1
        seen[$1]++
    }
    END {
        for(ip in seen) print ip, max[ip], (ever_d[ip] ? "D阶达" : "")
    }' | sort -k2 -rn

# 4. 生成 AAR 草稿
cat all-events.jsonl | jq -s '
    {
        total_events: length,
        unique_attackers: (map(.src_ip) | unique | length),
        max_score: (map(.score) | max),
        d_level_triggers: (map(select(.response_level == "D")) | length),
        top_attackers: (group_by(.src_ip) | map({ip: .[0].src_ip, count: length, max_score: (map(.score) | max)}) | sort_by(-.max_score) | .[0:10])
    }' > after-action-summary.json
```

---

## 9. 得分策略

### 9.1 护网评分核心指标

| 指标 | 权重估计 | 最大化策略 |
|------|---------|-----------|
| **检测覆盖率** | 高 | 确保 L1-L7 全部引擎运行，不遗漏任何层面 |
| **响应速度** | 高 | 使用激进模式配置，B/C 阈值下移 |
| **证据质量** | 中 | pcap 保留完整包，日志含精确时间戳和 JA3/JA4 |
| **误报率** | 中高 | 白名单严格校验，D阶人工预授权避免误伤裁判 |
| **自动化程度** | 中 | 展示 A→B→C 自动化升级链（D 阶展示人工审批流程） |
| **欺骗成功** | 加分 | 记录蜜罐交互时长和攻击者行为捕获 |
| **协同防御** | 加分 | 蜂群广播记录（多节点加分） |

### 9.2 证据质量 > 证据数量

```
高质量证据:
  - 完整 pcap: tcpdump -w 完整三方握手 + payload
  - JA3/JA4 指纹: TLS ClientHello 完整哈希
  - 精确时间戳: RFC 3339 纳秒级
  - 攻击链还原: 扫描→探测→利用→C2 完整路径
  - 关联上下文: 同 IP 多个检测器交叉验证

低质量证据（避免）:
  - 孤立 SYN 包日志（噪声）
  - 无上下文的事件 ID
  - 缺少源端口、payload hash 的摘要
```

### 9.3 响应时间评分

```yaml
# 护网激进模式 — 响应速度优化
brain:
  aggressive_mode: true
  aggressive:
    b_threshold: 20      # 更快进入主动侦查
    c_threshold: 45      # 更快进入掠食者
    # 检测→响应 全链路延迟目标:
    # A→B: <30s
    # B→C: <60s
    # C→D: <5min (含人工确认)
```

### 9.4 欺骗成功追踪

```bash
# 统计蜜罐交互数据
cat /var/log/fortress/fortress-*.jsonl | jq 'select(.honeypot_interaction == true)' | \
    jq -s '
    {
        total_interactions: length,
        unique_attackers: (map(.src_ip) | unique | length),
        avg_duration: (map(.duration_seconds) | add / length),
        longest_interaction: (max_by(.duration_seconds) | {ip: .src_ip, duration: .duration_seconds}),
        abyss_time_wasted: (map(select(.type == "llm_abyss") | .duration_seconds) | add)
    }'
```

---

## 10. 应急预案

### 10.1 容器崩溃

```bash
# systemd 自动重启（宿主机侧）
# /etc/systemd/system/fortress-container.service
[Unit]
Description=Fortress V6 Defender Container
After=docker.service
Requires=docker.service

[Service]
ExecStart=/usr/bin/docker start -a fortress-defender
ExecStop=/usr/bin/docker stop -t 30 fortress-defender
Restart=always
RestartSec=10
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable fortress-container
systemctl start fortress-container
```

### 10.2 Kali 工具不可用

```bash
# 症状: 日志出现 "nmap: command not found" 或 "nuclei: not found"
# 方案 A: 手动安装
docker exec fortress-defender apk add nmap

# 方案 B: 使用 Go 引擎内置能力（降级）
# 在 fortress.yaml 中设置:
weapons:
  nmap_bin: ""          # 空值禁用外部工具
  nuclei_bin: ""
  # Fortress 将回退到内置扫描引擎（功能较基础）
```

### 10.3 蜂群分区

```bash
# 症状: 日志显示 "consensus: leader lost" 或 "gossip: peer timeout"
# 影响: D 阶需要 Raft 多数共识，分区后无法触发

# 方案: 降级到单机模式
# 1. 编辑 /etc/fortress/fortress.yaml
swarm:
  peers: []

# 2. 重启
docker restart fortress-defender

# 3. D 阶改为单机直接触发（安全风险，仅护网期间）
brain:
  auto_counterstrike: false           # 保留人工预授权
  counterstrike_threshold: 80         # 提高阈值补偿单人决策
```

### 10.4 D 阶误触发

```bash
# 症状: 系统自动封禁了合法 IP 或重要服务
# 危害: 可能误伤裁判/队友系统

# 紧急处理:
# 1. 立即降级所有
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deescalate","arguments":{"reason":"D误触发"}}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# 2. 解封误封 IP
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unblock","arguments":{"ip":"x.x.x.x"}}}' | \
    docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# 3. 加入白名单（防止再次触发）
echo "x.x.x.x/32" >> /etc/fortress/whitelist.conf
docker exec fortress-defender kill -HUP 1

# 4. 记录误报事件（用于事后复盘）
echo "$(date -Iseconds) D阶误触发: IP=x.x.x.x, 原因=XXX, 处理=立即降级+解封+加白" \
    >> /var/lib/fortress/evidence/false_positives.log
```

### 10.5 数据外泄检测触发

```bash
# 症状: 日志出现 "egress_alert: data exfiltration detected"
# 检测: TC 出口 1MiB/60s 阈值触发

# 处理:
# 1. 识别外泄目标 IP
cat /var/log/fortress/fortress-*.jsonl | jq 'select(.type == "egress_alert")'

# 2. 核对外泄数据量
cat /var/log/fortress/fortress-*.jsonl | jq 'select(.type == "egress_alert") | .egress_bytes'

# 3. 紧急网络隔离（极端情况下）
# 切断特定 IP 的所有网络通信
iptables -A OUTPUT -d <外泄目标IP> -j DROP
# 或全局切断
iptables -P OUTPUT DROP
# 仅允许白名单出站
iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT

# 4. 保存外泄证据
tcpdump -r /var/lib/fortress/pcap/egress-*.pcap -w exfil-evidence.pcap
```

---

## 附录 A: 快速参考卡片

```bash
# === 护网常用命令速查 ===

# 启动
docker run -d --privileged --network host --name fortress-defender --restart=unless-stopped -v /sys/fs/bpf:/sys/fs/bpf -v /var/lib/fortress:/var/lib/fortress -v /var/log/fortress:/var/log/fortress -v /etc/fortress:/etc/fortress fortress-v6:latest --mode defend

# 日志
tail -f /var/log/fortress/fortress-$(date +%Y%m%d).jsonl | jq '.'
docker logs -f fortress-defender

# 状态
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status"}}' | docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# 封禁/解封
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","arguments":{"ip":"X"}}}' | docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unblock","arguments":{"ip":"X"}}}' | docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# 紧急降级
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deescalate"}}' | docker exec -i fortress-defender nc -U /var/run/fortress-mcp.sock

# 重启
docker restart fortress-defender
```

## 附录 B: 配置差异 — 护网 vs 日常

| 参数 | 护网值 | 日常值 | 原因 |
|------|--------|--------|------|
| `brain.aggressive_mode` | `true` | `false` | 更敏感检测 |
| `b_threshold` | 20 | 25 | 提前进入主动侦查 |
| `c_threshold` | 45 | 50 | 提前进入反击 |
| `d_threshold` | 70 | 85 | 更早触发 APT 防御 |
| `ban_duration` | 7200s | 1800s | 延长封禁 |
| `decay_half_life` | 45min | 30min | 延长攻击者记忆 |
| `correlation_multiplier` | 1.5 | 1.0 | 增强关联检测 |
| `weapons.max_concurrent` | 80 | 50 | 更多并发反击 |
| `cpu_pin` | [2,3,4,5] | [2,3] | 更多 CPU 核心 |
| `D阶共识` | 单机或N/2+1 | N/2+1 | 护网期间简化决策链 |

---

## 附录 C: 战前 Check List

- [ ] WSL2 资源分配确认(12GB 内存, 8 核)
- [ ] 内核参数调优完成 (`sysctl --system`)
- [ ] Go 1.23+、Rust 1.80+、clang 17+ 安装确认
- [ ] `make build` 编译成功
- [ ] `make test` 全部通过
- [ ] BPF 程序可加载 (`bpftool prog list`)
- [ ] 白名单更新（队友 IP、裁判 IP、平台 IP）
- [ ] 蜜罐端口配置完成
- [ ] JA3/JA4 指纹库更新
- [ ] 日志目录创建 (`/var/log/fortress`, `/var/lib/fortress`)
- [ ] Docker 镜像构建并推送
- [ ] systemd 自动重启配置
- [ ] MCP 工具可用性验证
- [ ] 带外通信渠道建立（与协同蓝队）
- [ ] 友军 IP 双边白名单确认
- [ ] 护网平台评分系统 IP 确认
- [ ] D 阶人工预授权流程确认
- [ ] 紧急关停脚本就绪
- [ ] 证据导出脚本就绪
