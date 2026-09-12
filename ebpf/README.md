# ebpf/ — SK_REUSEPORT steering prototype（Phase 2b，Linux only）

在 quic-bpf 容器（--privileged，ubuntu:24.04，clang/llvm/libbpf-dev/make 已装）：

```bash
cd /work/ebpf && make && ./steer_loader 9477
```

流程：loader 创建 4 个 SO_REUSEPORT UDP socket（9477 端口）→ 加载
`quic_steer.bpf.o`（SK_REUSEPORT 程序：解析 QUIC 头，SCID[0]/DCID[0] 为路由
字节 <N 时选中对应 socket，否则哈希回退）→ sockarray map 按 index 装入 4 个
socket → `SO_ATTACH_REUSEPORT_EBPF` 挂到组上 → 注入探测包（每个路由字节 5 个）
→ 统计各 socket 收包数，期望 5/5/5/5。

## 当前状态（未通过，待查）

- 程序加载、verifier、attach 全部成功；
- 运行时 `bpf_sk_select_reuseport()` 对任何 idx（含常量 0）都失败 → 全部包
  落入内核哈希回退（同一源端口 → 同一 socket，观测 20/0/0/0）；
- 对照实验证实：CBPF `SO_ATTACH_REUSEPORT_CBPF`（读偏移 9 的路由字节）同样
  不生效——所有"每偏移 20 包落同一 socket"的现象均为内核 4 元组哈希；
- 疑点：Docker Desktop VM 的内核/BPF 环境限制，或 sockarray map 填充时机
  （当前为 load 后 update；kernel selftest 顺序为 raw map create → 更新 →
  prog load）。**下一步在真 Linux 主机或调整装载顺序重试**；CBPF 版本可作为
  不依赖 libbpf 的备选实现（协议上已验证 attach 成功，仅差选择生效）。

## 包头视图要点（实测）

SK_REUSEPORT/CBPF 看到的包**从 UDP 头开始**（不含 IP 头）——QUIC 路由字节在
偏移 8+1=9 处（UDP(8)+DCID[0]）。曾按 IP 头起点解析导致程序把 UDP 头当 IP 头
检查而全部丢弃。
