# 单 ingress 收包路径：开销分解与优化设计

> 关联：design-quic-demux.md §6（demux 架构）。本文只讨论 QUIC 入站——TCP 的 ingress 只做 accept → fd 交接（一个整数，**零数据拷贝**），数据 I/O 全在 worker 自己的 socket 上，单 ingress 不是 TCP 吞吐瓶颈。

## 1. 为什么 QUIC 入站是唯一的"ingress 搬数据"路径

一个共享 UDP socket 收**所有连接**的包，ingress（demux）逐包 recv → 解析 DCID → 查 CID 表 → post 给 worker。出站不走 ingress（worker 直接 `sendmsg` 共享 fd，`ea_packets_out` 同步契约）。所以 **ingress 是 QUIC 入站 PPS 的序列化点**。

## 2. 当前每包开销分解

```
ingress（demux）                                        worker
─────────────────                                       ──────
recvfrom(fd, recv_buf_)       ① 内核→用户 拷1（固有）
解析 DCID（读 recv_buf_）      ② 只读，零拷
查 CID 表 → 选 worker         ③ 读共享表（mutex，临界极短）
make_shared<vector>(copy)     ④ 堆分配 + 用户→用户 拷2（可消除）
asio::post(worker, pkt)       ⑤ mutex + eventfd/pipe 唤醒   ─▶  被唤醒
                                                             lsquic_engine_packet_in
                                                             （TLS 解密、流处理——重活，已并行 N worker）
```

- **① 不可消除**：标准 socket 无 UDP 收包零拷贝（`io_uring` 也只是异步化 + 拷进注册缓冲）。
- **② 今天已零拷**：DCID 直接读收到的缓冲。
- **④ 可消除**：它存在的唯一原因 = demux 复用一个固定 `recv_buf_`，而 worker 异步晚跑、缓冲会被下一包覆盖，所以必须拷出来。
- **⑤ 每包一次唤醒**（互斥锁 + eventfd 写 + worker epoll 醒来），PPS 高时是真实开销。

## 3. 优化一：缓冲池（消掉 ④ 的拷贝 + 堆分配）—— 首选

### 原理

把"一个固定 `recv_buf_`"换成"预分配 N 个缓冲的池"。收包**直接落进池里的缓冲**，连同该缓冲的所有权 post 给 worker，worker 用完归还池。

```
池（N × 缓冲，缓冲大小按最大 UDP 负载 + 余量，分档更省）
  收包前：从池取一个缓冲 b
  recvfrom(fd, b)        ① 内核→用户，直接落进 b —— 唯一一次拷贝
  解析 DCID（读 b）
  查 CID 表 → 选 worker
  post(worker, b)        只移动所有权（指针），零数据拷贝
  ── worker 用完 → b 归还池 ──
```

**消除**：第二次 memcpy（用户→用户）+ 每包堆分配（缓冲循环复用，无 malloc/free churn）。worker 拿到的是"借用的池缓冲"（读 `b->data(), b->len`），不是又拷一份。

### 代价 / 权衡

| 项 | 说明 |
|---|---|
| 内存上界 | 池 = N × 缓冲大小。N 太小 → 阻塞收包（丢吞吐）/ 丢包 / 溢出分配新缓冲（退化为现状）。N 须 ≥ 峰值在途 datagram 数 |
| 生命周期 | 缓冲被 worker 借用期间不可复用 → 需要"用完归还"。实现 = 自定义 deleter 的 shared_ptr 池缓冲（`deliver_packet` 仍收裸指针 + len，lambda 持 handle） |
| 线程安全 | 池跨 ingress + N worker 共享 → acquire/release 需互斥（free-list 加锁，临界区极短，可接受）；进阶可 per-worker 归还缓存 |
| 缓冲大小 | 定死 64KB 浪费（多数 datagram ≤ 1500）；按最大 UDP 负载 + 余量或分档 |

## 4. 优化二：`recvmmsg` 批量收包

一次 syscall 收多个 datagram（Linux `recvmmsg`；**macOS 没有**，只能循环 `recvfrom`）。摊薄 ① 的 syscall 开销。配合缓冲池：一次取一批缓冲。

## 5. 优化三：批量 post（摊薄 ⑤ 的唤醒）

不逐包 post，积攒一小批（如 8~16 包）→ 一次 post，worker 一次性批量 `packet_in`。摊薄锁 + eventfd 唤醒，也顺带提高 worker 侧 CPU 效率（lsquic 批处理）。代价：微秒级延迟 + 队列缓冲。

## 6. 优化四：多线程分发（SO_REUSEPORT）

多个 recv 线程各持一个 socket（SO_REUSEPORT 内核分发）。**不破坏 CID 路由**：demux 按 DCID 查共享 CID 表投递，同连接恒落同一 worker，迁移安全依旧成立（§6.1）。即把 ①④⑤ 并行化。代价：CID 表锁竞争（读多写少，可忽略）、recv 顺序（同连接仍有序）。

## 7. 优化五：`io_uring`（仅 Linux）

注册缓冲 + 异步收包，内核直接写入注册缓冲，进一步减 syscall 与拷贝边界。macOS 无此机制（只有 kqueue）。仅 Linux 部署时可考虑。

## 8. 结论 / 建议

- **当前规模（几千~几万 QPS）单 ingress 足够，无需动。**
- 真到高 PPS：**先做缓冲池（方案一）**——收益最大、改动最小（集中在 demux 收包路径）；再上批量 post（方案三）；之后才考虑多线程分发（方案四）。
- 方案二/五受平台限制（Linux 专有），macOS 上只有 kqueue。

## 9. 现状记录（2026-09）

QUIC 入站每包做一次 `make_shared<vector>`（堆分配 + memcpy）再 post。README 特性未提性能指标。此文档为设计备忘，未实施。
