# 传输层深入：UDP 模型、lsquic 驱动、所有权与并发

本文回答三个最容易绕晕的问题：UDP socket 到底怎么用、lsquic 是怎么被驱动起来的、`conn_ctx`/`conn`/engine 到底谁属于谁。读完应当对 `src/transport/quic_transport.cpp` 的每一行都有把握。

## 1. UDP socket 与 TCP socket 不是一回事

| | TCP | UDP |
|---|---|---|
| 连接建立 | `listen()` + `accept()`，每个连接一个新 socket | 没有 `accept`，没有内核连接对象 |
| 标识 | 每个 socket 绑定唯一四元组 `{src ip:port, dst ip:port}` | 一个 `bind(port)` 的 socket 收**所有**发给该端口的包 |
| 发送 | 已建立的连接直接 `send` | `sendto(对端 ip:port)`，无连接、无确认 |

**一句话：TCP 的"连接"是内核维护的四元组状态机；UDP 的 socket 只是一个信箱，收所有打进来的 datagram。**

QUIC 在 UDP 之上把"连接"这一层搬到了**用户态**：一个 UDP socket 上可以承载无数条 QUIC 连接，靠包里的 **Connection ID (CID)** 区分。甚至同一个四元组上可以同时跑多条 QUIC 连接（CID 不同），这也是 QUIC 能连接迁移/NAT 重绑的原因。

所以 QUIC 侧的 `socket_` 必须是 **listener/engine 级共享资源**，绝不能放进 `QuicTransportSession`（那是每连接视角）：

```
QuicTransportListener (1)      socket_ (1 个 UDP fd) + engine_ + tick_timer_ + sessions_
QuicTransportSession   (N)     conn_ + remote_addr_ + 每连接回调   ← 即 conn_ctx
QuicTransportStream    (N×M)   lsquic stream 封装
```

## 2. lsquic 的驱动模型：你是事件循环，它是状态机

lsquic 引擎**没有**自己的线程、socket、定时器。它只是一台状态机，进出全靠你驱动：

```
你（event loop）                                   lsquic 引擎
─────────────────────                             ─────────────────────
收包回调 on_packet ──▶ lsquic_engine_packet_in(buf, n, local, peer)   ← 喂进
                     ──▶ lsquic_engine_process_conns()                ← 跑可执行连接
定时器 on_tick ──────▶ lsquic_engine_process_conns()                  ← 时间节拍
                      ──▶ ea_packets_out(specs) ──▶ sendmsg           ← 回调出发包
```

- **收包**：你调 `lsquic_engine_packet_in()`（server 模式 `peer_ctx` 传 NULL，解复用完全靠 CID）。
- **发包**：引擎回调 `ea_packets_out`，把要发的报文（`lsquic_out_spec[]`）交给你，**指望你在回调返回前处理完**——UDP 正确做法是同步 `sendmsg`（拷贝进内核发送队列）。不要在回调里做 asio 异步写：一旦你向引擎返回了"已发送 n 个"，引擎就认定这些包发出去了、不再负责重传。
- **时钟**：引擎告诉你下一次需要被驱动的时刻（`lsquic_engine_earliest_adv_tick`），你用 asio 定时器实现，到点调 `process_conns`。这一路负责 ACK 延迟、PTO/丢包重传、keepalive、空闲超时——**没有它连接会静默死掉**。
- **应用事件**：`ea_stream_if` 里的 `on_new_conn` / `on_new_stream` / `on_read` / `on_write` / `on_close` / `on_reset` 等，全在 `packet_in`/`process_conns` 的调用栈上**同步重入**触发。

因此你的 `read_cb_`（通过 `async_read_some` 注册）最终是在 **asio 收包回调 → lsquic 状态机 → 应用回调** 这条同一线程、同一栈的链上被调用的。

## 3. 读 / 写路径的语义（返回值要看清）

- `lsquic_stream_read`：`n ≥ 0` 返回读取字节数（**0 = EOF**）；`-1` 时看 errno：`EWOULDBLOCK`（暂无数据，保留 pending 并重新 `wantread`）、`ECONNRESET`（对端 RST）、`EBADF`（已关闭）。
- `lsquic_stream_write`：`n > 0` 返回写入字节数，**可能小于请求长度**（部分写）；`n == 0` 表示本次没写进（缓冲/流控满）；`-1` 看 errno（`ECONNRESET`、`EBADF`、H3 下未先发头时的 `EILSEQ`）。**不存在 `-2`**。
- `wantread`/`wantwrite` 是电平信号：置位后引擎在对应事件可发生时调 `on_read`/`on_write`。

据此，传输封装必须自己补足两件事：

1. **部分写要排队续写**（`WriteOp::offset`）：写不全就把剩余尾巴留在队里，等 `on_writeable` 再续，全部写完才回调。
2. **-1 要按 errno 区分**，不能一律当 EOF（否则 RST 被吞、无数据被误报结束）。

## 4. conn_t vs conn_ctx，为什么每次新建

- `lsquic_conn_t*`：**连接本身**，库分配/管理/释放。你永远不 `new` 它，回调里拿到的是只读句柄，对它调用库函数（`lsquic_conn_close`、`lsquic_conn_make_stream`…）。
- `lsquic_conn_ctx_t*`：**你的**每连接应用数据槽位（`struct lsquic_conn_ctx`，不透明）。你在 `on_new_conn` 里返回一个指针，引擎原样存下、在之后所有回调里原样还给你（`lsquic_conn_get_ctx`），也会出现在 `lsquic_out_spec.conn_ctx`。

**把 C++ 的 `QuicTransportSession*` 直接当 conn_ctx 是标准做法**（lsquic 从不解引用它）。"每次新建"是因为每个新连接都需要一份全新的 session 状态。关键约束是**生命周期**：conn_ctx 必须在连接的最后一次回调（`on_conn_closed`）执行期间仍然有效——因此 listener 用 `sessions_` map 持有 `shared_ptr`，并在 `on_conn_closed` 里用 `take_session()` 摘除。

`lsquic_stream_if` 等"函数指针结构体"就是 C 语言的 vtable / 接口——回调参数里的 `self` 就是 `this`，填表即实现接口。

## 5. 并发模型

- **单引擎单线程是 lsquic 的正确形态**（官方 echo_server 亦然）。引擎内部无锁，两个入口（`on_packet`、`on_tick`）不能并发摸它。
- 一个 `io_context` 不等于单线程：`io.run()` 由 N 个线程调就是 N 线程并行取任务。`num_threads > 1` 时 `on_packet` 与 `on_tick` 可能同时跑 → 数据竞争。
- **加锁不是答案**：给单引擎上锁等于把本来就不该并发的入口串行化，还引入回调链内死锁风险（回调在锁里，若它去等别的线程拿同一把锁就死锁）。
- **要扩展就按连接分片**：N 个引擎 × N 个线程，连接按 CID 哈希归属一个引擎，每引擎仍单线程、零锁。

## 6. 健壮性要点（含近期修复）

- `on_conn_closed_cb` 摘除 `sessions_`（防每连接泄漏），先 `take_session()` 拿一份 shared_ptr 再 `on_closed()`，避免在成员函数里销毁 `this`。
- UDP 收包错误后要重新 `do_recv()`（瞬时错误不能杀死整个监听循环）；`operation_aborted` 表示关闭，不再 re-arm。
- `on_packets_out` 遇 `EAGAIN/EWOULDBLOCK`：保留未发包，等 socket 可写（`socket_.async_wait(wait_write)`）再调 `lsquic_engine_send_unsent_packets()`，否则那些包永久滞留、连接最终超时。
- `on_reset`（对端 RST 流）要及时解阻塞挂起的读写回调，避免一直等到超时。
- **已知缺口**：H3 模式与手写帧解析的冲突、响应路径绕过 codec，见 [design-decisions.md](design-decisions.md)。
