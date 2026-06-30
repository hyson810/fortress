# Fortress V6 (Hydra-mini) · 运维手册 · Runbook

**版本:** v6.0.0-rc1 "Cyclops · 独眼巨人"
**部署目标:** Linux (bare metal / VM) — Ubuntu 22.04+, Debian 12+, Kali, Alpine
**前提:** Go 1.23+, Rust 1.80+, clang 15+, Linux kernel 5.4+

---

## 一、快速启动

### 1.1 编译

```bash
# 编译 BPF 字节码
cd kernel/bpf
clang -O2 -target bpf -c xdp_filter.c -o xdp_filter.o
clang -O2 -target bpf -c tc_egress.c -o tc_egress.o

# 编译 Rust muscle
cd ../muscle
cargo build --release

# 编译 Go brain
cd ..
CGO_ENABLED=1 go build -o fortress ./cmd/fortress/
```

### 1.2 启动

```bash
# 防御模式 (全管线: XDP → AF_XDP → Rust → Go → 检测 → 决策)
./fortress --config fortress.yaml --mode defend

# 扫描模式 (单目标侦察)
./fortress --config fortress.yaml --mode scan --target 192.168.1.0/24

# 融合模式 (全武器链
./fortress --config fortress.yaml --mode fusion --target 10.0.0.5
```

### 1.3 Docker 部署

```bash
docker build -t fortress-v6 .
docker run --privileged --network host \
  -v $(pwd)/fortress.yaml:/etc/fortress/fortress.yaml \
  fortress-v6 --mode defend
```

`--privileged` 是因为需要加载 BPF 程序和 AF_XDP socket。

---

## 二、运行时监控

### 2.1 仪表盘

```bash
# HTML 实时仪表盘 (默认端口 9090)
curl http://localhost:9090/

# JSON API
curl http://localhost:9090/api/status
```

### 2.2 Prometheus 指标

```bash
# 指标端点
curl http://localhost:9090/metrics

# 关键指标:
#   fortress_packets_processed      处理包数
#   fortress_threats_created        威胁创建数
#   fortress_decisions_total        决策总数
#   fortress_autonomous_counterstrikes  D阶自动反击次数
#   fortress_uptime_seconds         运行时间
```

### 2.3 日志

```bash
# 实时日志
tail -f /var/log/fortress/alerts.log

# 查看最近告警
./fortress --mode defend 2>&1 | grep "\[defense\]"
```

### 2.4 BPF 统计

```bash
# 查看 XDP 统计 (需要 bpftool)
bpftool map dump name stats

# 查看封禁列表
bpftool map dump name blocked_ips

# 查看白名单
bpftool map dump name whitelist

# 查看速率限制
bpftool map dump name rate_limit
```

---

## 三、手动操作

### 3.1 手动封禁 IP

```bash
# 通过 MCP 控制面
echo '{"tool":"fortress_block_ip","params":{"ip":"10.99.99.99"}}' | \
  nc -U /var/run/fortress/mcp.sock

# 或通过 BPF map 直接操作 (需要 root)
python3 -c "
from bpf import BPF
b = BPF(src_file='kernel/bpf/xdp_filter.c')
b['blocked_ips'][0xc0a80101] = 1  # 192.168.1.1
"
```

### 3.2 手动解封 IP

```bash
echo '{"tool":"fortress_unblock_ip","params":{"ip":"10.99.99.99"}}' | \
  nc -U /var/run/fortress/mcp.sock
```

### 3.3 手动触发反击 (需要 D阶 授权)

```bash
echo '{"tool":"fortress_launch_counterstrike","params":{"target":"10.99.99.99"}}' | \
  nc -U /var/run/fortress/mcp.sock
```

### 3.4 手动触发全武器链

```bash
./fortress --mode fusion --target 10.99.99.99
```

---

## 四、紧急操作

### 4.1 紧急停机

```bash
# 方法 1: Ctrl+C (SIGINT) — 优雅停机
#   1. 停止 packet inject loop
#   2. 卸载 BPF 程序
#   3. 关闭 AF_XDP sockets
#   4. 关闭 honeypot listeners
#   5. 关闭 swarm connections

# 方法 2: SIGTERM — 同上

# 方法 3: kill -9 — 强制终止 (不推荐，BPF 程序可能残留)
#   强制终止后需要手动清理:
sudo bpftool prog detach id <xdp_id> xdp eth0
sudo bpftool prog detach id <tc_id> tc egress eth0
```

### 4.2 全量解封

```bash
# 清空 blocked_ips map
bpftool map delete name blocked_ips key 0 0 0 0

# 或重启 Fortress (自动清空)
```

### 4.3 防护降级

如果内核层 BPF 出现问题，可以降级到纯用户态模式：

```bash
# 编辑 fortress.yaml，设置:
engine:
  use_ebpf: false  # 禁用内核层，仅使用用户态检测

# 重启
./fortress --config fortress.yaml --mode defend
```

### 4.4 内存压力处理

如果系统内存不足 (OOM risk):

```bash
# 减小流表大小
engine:
  max_flows: 2000  # 默认 10000

# 减小 channel buffer
pipeline:
  channel_buffer_size: 1024  # 默认 4096

# 减小 UMEM 帧数 (AF_XDP)
afxdp:
  frame_count: 1024  # 默认 4096
```

---

## 五、常见问题

### 5.1 "AF_XDP socket creation requires bare metal Linux"

**原因:** 在非 Linux 系统或虚拟机 (无 XDP 驱动) 上运行。
**解决:** 部署到 bare metal Linux，使用支持 XDP 的网卡 (Intel X710, Mellanox CX-5+)。

### 5.2 "BPF program load failed: operation not permitted"

**原因:** 缺少 CAP_BPF 或 CAP_SYS_ADMIN capability。
**解决:** 以 root 运行，或 `setcap cap_bpf,cap_sys_admin+ep ./fortress`。

### 5.3 "UMEM allocation requires huge pages"

**原因:** 没有足够的 locked memory 或 huge pages。
**解决:**
```bash
ulimit -l unlimited
echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### 5.4 "honeypot port already in use"

**原因:** 蜜罐端口被其他服务占用。
**解决:** 修改 `fortress.yaml` 中的 honeypot 端口配置。

### 5.5 "go vet: address format does not work with IPv6"

**原因:** V5 遗留代码使用了 `%s:%d` 格式而非 `net.JoinHostPort`。
**解决:** V5 已清理，V6 所有代码使用 `net.JoinHostPort`。

---

## 六、性能调优

### 6.1 调整检测阈值

```yaml
# fortress.yaml
engine:
  syn_flood_pps: 80       # SYN flood 阈值 (packets/sec)
  udp_flood_pps: 200      # UDP flood 阈值
  icmp_flood_pps: 30      # ICMP flood 阈值

brain:
  aggressive_mode: false  # true = 降低阈值 (更敏感/更多误报)
  counterstrike_threshold: 75.0  # D阶触发分数 (0-100)
  anomaly_z_threshold: 4.0       # 异常检测 Z-Score 阈值
```

### 6.2 调整 UMEM/AF_XDP

```yaml
afxdp:
  frame_count: 4096     # 帧数 (必须是 2 的幂)
  frame_size: 4096      # 帧大小 (2K 或 4K)
  batch_size: 64        # 每批处理包数
  use_huge_pages: false # true = 使用 huge pages 提升 TLB 效率
```

### 6.3 多核配置

AF_XDP 每个 NIC 队列一个 dispatcher，每个 dispatcher 绑定一个 CPU 核心。
推荐: 1-2 核给 OS，其余给 Fortress dispatcher。

```bash
# 查看 NIC 队列数
ethtool -l eth0

# 在 fortress.yaml 中配置:
afxdp:
  queues: [0, 1, 2, 3]  # 使用 4 个队列，绑定到核心 2-5
```

---

## 七、告警响应流程

```
1. 收到告警 (Webhook/Discord/Slack/Syslog)
   ↓
2. 查看仪表盘确认威胁等级
   ↓
3. A级 → 观察、记录
   B级 → 手动封锁 IP
   C级 → 部署蜜罐 + 加强监控
   D级 → 自动触发全武器链反击 (需 Raft 共识)
   ↓
4. 事后分析: 检查 evidence 链、attacker profile
   ↓
5. 更新规则: 将新 TTP 加入检测规则
```

---

## 八、联系与升级

- **项目代号:** Hydra-mini (Fortress V6)
- **版本:** v6.0.0-rc1
- **维护者:** 护网行动小组
- **升级:** `git pull && make rebuild`
- **零日响应热线:** 见 `aggressive.yaml`
