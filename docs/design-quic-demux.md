# 设计蓝图：统一单入口 + co-located worker（TCP accept + QUIC demux）

> 状态：**已实现**（`src/transport/quic_demux.*`、`QuicServerEngine`、`main.cpp` N+1 线程）。配套最小原型：`examples/quic_demux_demo.cpp`（已验证 `lsquic_dcid_from_packet` 解析 + CID 路由 + 迁移安全 + 表清理）。
>
> 与真实 HTTP/3 客户端（curl/ngtcp2）的握手互操作缺陷已定位并修复：`docs/lsquic-4.7.0-http3-interop-a-b.patch`（两处，见 §15），由 `scripts/ensure_lsquic_patch.sh` 自动保持应用。
>
> 本文是 `docs/design-quic-demux.md` 的改写版。相对旧版，核心变化不是 demux 本身，而是**把 worker 的定位讲清楚**：worker 不是"TCP 线程"或"QUIC 引擎线程"的二选一，而是一条 io_context 线程，顺带挂着 0~2 个 lsquic 引擎 + 一堆 TCP socket，前端与后端、引擎与 relay 全在一条线程上（co-located）。demux 只是入站 QUIC 的"统一单入口"。

## 1. 目标

1. **QUIC 连接迁移正确**：连接由 CID 标识，源地址变化不断连，且不依赖内核 SO_REUSEPORT（macOS 不分发；Linux 按 4 元组分发会在迁移时断裂）。
2. **TCP/QUIC 统一工作模型**：所有 worker 都是同一种执行上下文——一条 io_context 线程；区别只在"顺带挂了几个引擎"，协议差异由 `ITransportStream` 抽象吸收。
3. **统一单入口**：一个 ingress 线程同时承担 TCP accept 与 QUIC demux，把连接/包投递给 worker，投递之后不再介入该请求的生命周期。

## 2. 现状与问题

```
现在：每 worker 自己的 UDP socket + SO_REUSEPORT（QUIC）
      每 worker 自己的 TCP acceptor + SO_REUSEPORT（TCP）
问题 1：macOS SO_REUSEPORT 不分发（实测全投一个 socket）
问题 2：Linux 按 4 元组分发，QUIC 连接迁移（Wi-Fi↔流量）→ 4 元组变 → 包进陌生引擎 → 断连
问题 3：旧文档"跑引擎的线程也要 io_context"表述不清，被误读为"引擎依赖 io_context"
```

问题 3 是本文要重点澄清的（见 §4、§5）。

## 3. 总体架构与线程布局

```
                        ┌─────────────────────────────────────────────┐
                        │            ingress 线程（1，自己的 io_context）│
                        │  TCP acceptor：accept → 选 worker → 投递 fd   │
                        │  QUIC demux：共享 UDP socket + recv          │
                        │            解析 DCID → 查 CID 表 → post 包    │
                        └───────┬──────────────────────┬───────────────┘
                           post│(TCP fd)          post │(UDP 包)
              ┌────────────────┴───────┐    ┌──────────┴──────────────┐
              │ worker 0（io_context 线程）│    │ worker N（io_context 线程） │
              │  TCP socket IO            │    │  ……                     │
              │  QUIC server engine       │    │                         │
              │  QUIC client engine       │    │                         │
              │  relay（业务，co-located） │    │                         │
              │  私有后端池（keep-alive）   │    │                         │
              └──────────────────────────┘    └─────────────────────────┘

总线程数 = N + 1（1 ingress + N worker）
```

- **唯一交接点 = ingress → worker**。之后这条请求的生死（前端 + 后端 + relay）全在同一个 worker 手里，不再跨线程。
- **worker 必须常驻**：worker 不再自持 acceptor/QUIC 定时器，空转时 `io_context::run()` 会立即返回、线程退出，ingress `post` 的投递 handler 永远不跑。实现用 `asio::make_work_guard` 让每个 io_context 有"伪 work、永不空返回"（§15 已踩过这个坑）。
- 后端连接由 worker **自己**建立，不存在"再交给另一边的 worker"（见 §10）。

## 4. 核心概念：worker 是什么

worker 不是"跑 TCP 的 io_context 线程"或"跑 QUIC 的 engine 线程"二选一。它是一条 **io_context 线程**，顺带挂着：

| 对象 | 是什么 | 由谁驱动 |
|---|---|---|
| 前端 TCP | acceptor 投递来的 socket | asio，本 worker 的 io_context |
| 前端 QUIC | server engine（`LSENG_SERVER\|LSENG_HTTP`） | lsquic，本 worker（post 的包 + tick） |
| 后端 TCP | `resolver` + 新 socket | asio，本 worker 的 io_context |
| 后端 QUIC | client engine（`LSENG_HTTP`，每 worker 一个） | lsquic，本 worker（自带临时端口 socket） |
| relay（业务） | `RelaySession` 相位机 | 本 worker 线程，与上述全部同线程 |

"后端走 QUIC 就要本 worker 有个 lsquic engine"不是障碍，是**现状**：每个 worker 的 `UpstreamPool` 在加入第一个 h3 后端时懒建自己的 `QuicClientEngine`（`upstream_pool.cpp:18-28`），挂在同一个 io_context 上。

## 5. 为什么 worker 线程有 io_context（而引擎本身不需要）

这是旧文档最容易被误读的一点。精确说法：

- **lsquic 引擎不需要 io_context**。它是一台纯状态机，进出全靠 `lsquic_engine_packet_in()` + `lsquic_engine_process_conns()` 两个同步调用；没有线程、没有 socket、没有定时器。
- **io_context 是给同线程的另外三样东西用的**：
  1. **relay 的 asio**：后端 TCP 连接（connect/read/write）与前端 TCP socket 的 IO。QUIC 前端流读写是 lsquic 同步调用、非 asio，但 relay 转发到 TCP 后端时必须有 asio。
  2. **引擎的 tick 定时器**：`steady_timer` 按 `earliest_adv_tick` 重挂。
  3. **接收 demux 的唤醒**：`io_context::post` 需要一个正在 `run()` 的 io_context 来执行（见 §6.2）。

一句话：**io_context 跑的是"这条请求链路上所有 asio socket 的 IO + 定时器 + demux 投递"，引擎只是搭在同一条线程上被 handler 顺带驱动的状态机。** 引擎自己一条 `while` + 条件变量就能驱动；但 relay 要 asio，所以 worker 线程统一用 io_context 更自然。

### 5.1 两种事件循环模型（lsquic 属于"状态机"这一极）

按"谁拥有事件循环 / 谁拥有 socket"可以把 QUIC 引擎粗分成**两个极**，分界线与"内核 TCP 栈 vs 手写 raw-IP TCP 栈"是同一条：

| 极 | 类比 | 代表 | 拥有循环/socket | 调用方式 |
|---|---|---|---|---|
| **状态机库（pull）** | 给你 raw IP，TCP 栈自己写 | lsquic、ngtcp2、quiche | 应用 | 应用泵包进去、定时 tick、同步 `packets_out` 回调 |
| **协议驱动 / 像 socket（push）** | 给你内核 TCP，栈库管 | msquic、quic-go、aioquic | 库（内部线程 + datapath） | 应用注册回调表，库主动驱动 |

"像 socket"这一极在**流层面**的手感确实和 TCP 很像：应用读/写一个 stream 对象，库管收包、重传、拥塞控制。但类比有三处不完美：

1. **多路复用**：一条 QUIC 连接 = 很多 stream，应用要分别管连接生命周期和流生命周期；内核 TCP 是"一个 socket = 一条有序字节流"，没有"连接对象挂很多通道"这回事。
2. **连接级事件仍漏到 API**：connect/accept、shutdown、对端地址变化（迁移）、0-RTT、TLS/ALPN——即使 msquic/quic-go 里这些也是应用写的连接回调，不像 TCP 那样内核全包。
3. **"同步接口"通常不是内核意义的阻塞**：quic-go 的 `Read` 阻塞的是一个 goroutine（事件循环在别的 goroutine 跑）；msquic 是纯异步回调 + `QUIC_STATUS_PENDING`。真正的阻塞读在 QUIC 里不存在——多路复用连接没法像单流 TCP 那样停住整个 socket。

本项目的意义：**我们明确站在左极**——应用（ingress + worker 的 io_context）拥有事件循环，lsquic 只是被 handler 顺带驱动的状态机。这正是 §5 成立的前提，也是为什么换引擎（如换到 msquic）要重写整个事件驱动层：不是换"引擎"，是换"谁拥有循环"这一整层。

## 6. QUIC 入站：demux + post（迁移安全）

### 6.1 CID 路由（level-1 路由：DCID → worker）

- 收包后 `lsquic_dcid_from_packet()` 解析 DCID（纯函数，不碰引擎，可在 demux 线程安全调用）。
- **已建立连接**：DCID = 服务端 SCID，查 CID 表 → 目标 worker（4 元组无关，迁移安全）。
- **新连接**：DCID 是客户端随机选的、未知 → **源地址哈希**挑 worker → post（**不登记**，见 §6.4）。
- lsquic 内部仍做 level-2 路由（DCID → 连接 → ctx），这级不变。

### 6.2 唤醒机制 = io_context::post（关键）

worker 阻塞在 `io.run()` 里，只对它自己 io_context 上注册的东西有反应。QUIC 前端包落在 **demux 的 socket** 上，对 worker 的 io_context 是"别人的事件"，**天然不唤醒它**。因此 demux 必须主动 `worker_io.post(handler)` 唤醒，handler 里 `packet_in + process_conns`。

```
demux 线程                               worker 线程（阻塞于 io.run()）
─────                                   ─────
recv 到包
  → 解析 DCID → 选 worker W
  → 拷贝包（recv buffer 会被下一包覆盖，必须拷）
  → asio::post(workers_[W].io, handler) ──▶ 唤醒 run()
                                            handler：
                                              packet_in(buf)
                                              process_conns()
                                              schedule_tick()
```

两种等价姿势：

- **(a) 队列 + post（批处理）**：demux 把包拷进 worker 的线程安全队列，post 一个"drain"任务；worker 醒来后一次性喂完队列。多包合并成一次 post，队列开销小。**推荐。**
- **(b) 每包一 post**：拷进 `shared_ptr<vector<char>>`，每包 post 一个 handler。实现简单，每包一次队列操作。

无论哪种，**包数据必须拷贝再 post**（post 到 handler 执行之间有窗口期，demux 的 `recv_buf_` 会被下一包覆盖）。

### 6.3 CID 表（共享状态）

- `std::map<CID, worker_idx>`，demux 线程在 `route()` 里**只读**、worker 线程写 → **互斥**。
- 写方只有 worker 一侧：`ea_new_scids` 登记服务端 SCID、`ea_old_scids` 删除（连接关闭/SCID 退役时触发）。
- 连接建立/关闭频率远低于收包频率，锁竞争可忽略。

### 6.4 表项登记与清理：走 lsquic 的 SCID 回调（单表项）

**CID 表只登记"服务端 SCID"这一种表项**，不登记客户端首包的 DCID。

- **登记**：引擎设 `ea_new_scids`。lsquic 在服务端连接签发新 SCID（初始 SCID + 迁移时补发的 SCID）时回调；`ctx` 是引擎（每 worker 一个），据此登记 `SCID → 本 worker`。
- **清理**：`ea_old_scids` 在 SCID 退役时回调（连接关闭、主动退役），据此删表项。表不泄漏。

**为什么不需要登记客户端 DCID**（旧版"两条表项"设计）：

- 客户端首包（Initial，DCID=客户端随机值）未知 → 源地址哈希选 worker，不登记。
- 重传的 Initial 源地址不变 → 哈希仍落同一 worker，路由正确。
- 引擎签发 SCID 并登记后，客户端后续包（Handshake 起）的 DCID = 服务端 SCID → 按 SCID 路由。
- 唯一缺口：握手期间（SCID 登记前）客户端恰好迁移源地址 → 重传 Initial 会落错 worker。握手期迁移实际不支持且极其罕见，可接受。

这样每条连接只占一条表项，且清理由 `ea_old_scids` 保证——旧版"demux 登记客户端 DCID"在握手失败时无法清理、有泄漏。

### 6.5 短头包解析必须固定 `es_scid_len`

短头（1-RTT）包的 DCID 长度**不在包里**，是连接协商值。统一解析必须把 `es_scid_len` 固定成一个值（默认 8），让所有连接的服务端 SCID 等长。长头包自描述，不受影响。

## 7. 入站 vs 出站 QUIC 的不对称

"QUIC 来信需要外部 post"只适用于**入站/前端**一侧：

```
入站 QUIC（server 侧）：客户端包 → demux 的共享 socket → 【需要 post 到 worker】
出站 QUIC（client engine）：上游包 → 本 worker 自己的临时端口 socket
                           → async_receive_from 直接在本 worker 的 io_context 触发，【不用 post】
```

原因：入站是所有客户端打同一个端口，必须靠 CID 把包拆给 N 个引擎，demux 的 socket 不属于任何 worker；出站每个 worker 自己的 socket 只承载它自己发起的连接，四元组天然唯一，内核直接路由回它自己。**"单入口"这个概念只适用于入站。**

## 8. 发送路径：ea_packets_out 契约

`ea_packets_out` 在 worker 线程 `process_conns` 的调用栈上**同步触发**。契约（`transport.md` §2）：

> 一旦你向引擎返回"已发送 n 个"，引擎就认定这些包发出去了、不再负责重传。

因此：

- **必须同步 `sendmsg`，返回真实 sent 数**（`quic_transport.cpp:864` 的现状做法）。
- **不能把 TX post 到 demux 的 io_context 队列再发**：回调里入队后立刻返回 count = 谎报已发；入队与真正 `sendmsg` 之间若丢包/队列满，lsquic 已把该批包从重传账本划掉 → 永久丢失。等于重写一层可靠传输，错的。
- **业务没有"直接发包"这条路**：业务 `lsquic_stream_write` → lsquic 缓冲 → 下次 `process_conns` 由 `ea_packets_out` 吐包 → 同步 sendmsg。一切 TX 都走 worker 线程的 `ea_packets_out`。

发包目标：**共享 socket fd**（demux 持有的那个监听 socket）。不能用 worker 自己的 socket——客户端严格认服务端源 5 元组，源端口变了直接丢包（迁移前的源地址校验）。

**EAGAIN 处理**（共享 socket 只有一个写就绪 watch 名额）：

- 任意 worker 遇 EAGAIN → 少报 sent 数（让 lsquic 保留未发包）→ 通知 demux 挂**一个**写 watch。
- 可写后 demux 对所有 worker 调 `lsquic_engine_send_unsent_packets`（或 post 到各 worker 让它们自己 flush）。
- demo 可再简化：EAGAIN 只记日志、少报 sent，靠 lsquic PTO 重传兜底（正确，因为少报了 sent 数）。

## 9. TCP 入站：accept → hand-off

accept 在 ingress 线程。accept 到的 socket 要投递给选定的 worker（round-robin / least-conn）。标准姿势（跨 io_context 移交 fd）：

```cpp
// ingress 线程
acceptor_.async_accept([this](asio::error_code ec, asio::ip::tcp::socket peer) {
    if (ec) { /* 重挂或关闭 */ return; }
    Worker& w = pick_worker();          // round-robin / least-conn
    int fd = peer.release();            // asio 放弃 fd 所有权，析构不 close
    asio::post(w.io, [fd, &w]() {
        asio::ip::tcp::socket s(w.io);
        s.assign(asio::ip::tcp::v4(), fd);  // s 接管 fd，此后全生命周期在 w 的线程
        w.on_new_tcp_socket(std::move(s));
    });
    do_accept();
});
```

- `release()` 必须先于 `peer` 析构，防止 fd 被 close；`assign()` 在 worker 线程接管。
- 备选：若单 accept 线程成为热点，TCP 可退回**每 worker 一个 SO_REUSEPORT acceptor**——TCP 连接不迁移，内核哈希分发是正确且可接受的，不像 QUIC 那样断裂。两方案可共存，蓝图默认单入口，瓶颈时再换。

## 10. relay co-located 与私有后端池

- **relay 与前端、后端同线程**：引擎回调（`on_read`/`on_write`）在 worker 线程同步触发 → 驱动 `QuicTransportStream` → 驱动 `RelaySession` → 后端 TCP asio 也在同一 io_context。**零跨线程、零锁**（这是现状 `quic_transport.cpp` 全程无锁的根基，必须保持）。
- **私有后端池**：每 worker 一个 `UpstreamPool`（现状已是：每 `ProxyCore` 构造自己的 pool，`proxy_core.cpp:16`），内含自己的 keep-alive 池 + 自己的 `QuicClientEngine`。**低耦合**（单线程无锁、注入依赖），代价是后端连接复用被钉死在单个 worker（资源效率，不是耦合问题）。
- 现状 `UpstreamPool` 里的 `std::mutex` / `std::atomic rr_index_`（`upstream_pool.h:90-91`）在私有 pool 单线程模型下是**多余的**（防御性写法），可移除或保留作廉价保险。

## 11. 组件与改动面

| 组件 | 变化 |
|---|---|
| `QuicPacketDemux`（新） | 共享 UDP socket + recv 循环 + CID 表 + `lsquic_dcid_from_packet` 解析 + post。向引擎暴露 `register_cid`/`remove_cid`。 |
| `QuicTransportListener` → `QuicServerEngine` | 去掉自己的 UDP socket 与 recv 循环；保留引擎 + TLS ctx + `on_packets_out`（改发共享 fd）；新增 `deliver_packet(buf, len, peer, local)`（由 post 的 handler 调用）与 tick 定时器。 |
| `ProxyCore`（worker） | 前端 TCP 由"自己 accept"改为"收 ingress 投递的 socket"；QUIC 由"自己 recv"改为"被 post 喂包"；后端池与 relay 不变。 |
| `main.cpp` | 线程布局 1 ingress + N worker（共 N+1）。 |
| TLS | 不变：server SSL_CTX 一次性创建、不可变、跨线程共享只读（现状已是）；每 worker 自建 client SSL_CTX。 |
| `UpstreamPool` | 不变（已是私有 pool + 自带 client engine）。 |

## 11.5 服务编排与优雅关闭（ReverseProxyServer）

`src/proxy/reverse_proxy_server.{h,cpp}` 把本蓝图（§3 的 N+1 线程布局）封装成一个类：

- `run()`：装 SIGINT/SIGTERM → `start()` → `wait()`，信号后优雅退出返回 0。嵌入用 `start()/wait()/stop()`。
- `start()`：建 ingress/worker io_context + work guard、demux、共享 server TLS ctx、N 个 ProxyCore、TCP acceptor，起 N+1 线程。acceptor 与 demux 全挂在 ingress 上，与 §3 一致。
- `stop()`（线程安全）→ 在 ingress 线程上执行：
  1. `acceptor_.cancel()` + `demux_->stop()`（cancel UDP recv，`on_packet` 遇 `operation_aborted` 不复位）——**不再接新连接**。
  2. 每 worker `ProxyCore::graceful_shutdown()`（post 到该 worker）：遍历 `live_relays_`（弱引用表），对空闲 keep-alive 客户端 `shutdown_send`（FIN，pending read 会看到对端 EOF → teardown）；在途请求置 `draining_`，响应完成后 FIN + drain 到 EOF 再 close（`close()` 无未读数据 → 不触发 RST）。UDP/QUIC 无 FIN 语义，靠 `grace` 硬停兜底。
  3. `grace`（默认 5s）后 `hard_stop()`：停所有 io_context → 线程 join → 进程退出。

## 12. 迁移走查

```
连接建立：首包（Initial）按源地址哈希落到 W；worker 的 ea_new_scids 登记 SCID→W
客户端 Wi-Fi → 流量：源地址变，但包 DCID = SCID（不变）
demux：按 SCID → W（不看 4 元组）→ 连接不断
```

## 13. 风险 / 开放问题

1. **EAGAIN 共享排空**：需要一个 demux 侧单写 watch + 全 worker flush；demo 可先少报 sent 靠 PTO 兜底。
2. **CID 表是共享状态**：demux 在 `route()` 里只读、worker 的 SCID 回调写 → 互斥。锁竞争可忽略。
3. **`es_scid_len` 固定**：所有连接 SCID 等长，长 CID（防跟踪）不可用——demo 无影响。
4. **demux 线程是收包序列化点**：recv 系统调用天然单 socket 串行；引擎处理已并行（N worker），收益在"处理"侧。
5. **QUIC 版本协商 / Retry**：`lsquic_dcid_from_packet` 对版本协商（无 DCID）、Retry 包的处理需实测确认。
6. **post 的包缓冲生命周期**：必须拷贝（§6.2）。
7. **握手期迁移（罕见）**：SCID 登记前的 Initial 按源地址哈希路由；若此刻客户端迁移，重传 Initial 会落错 worker（§6.4 已说明，可接受）。
8. **单 ingress 线程是 accept 热点**：TCP 高建连率下可能成瓶颈，备选每 worker SO_REUSEPORT（§9）。

## 14. 配套最小原型

`examples/quic_demux_demo.cpp` 已验证 §6.1/§6.4 的路由逻辑（`lsquic_dcid_from_packet` + CID→槽表 + 迁移安全 + 表清理），不含真实引擎与 post 集成。

## 15. 已知问题：与真实 HTTP/3 客户端（curl/ngtcp2）握手互操作缺陷

**最终结论：lsquic 库级缺陷，非本 refactor 引入（新旧代码同样失败），且已修复。** 完整调查报告在 `docs/lsquic-handshake-bug-report.md`（upstream issue #680 草稿），下面是结论摘要。

**三个缺陷，前两个被两处补丁修复，第三个是第二个的并发症（不是独立 bug）**：

1. **无 SNI → `CERT_CB_ERROR`**。按 IP 连接（curl 到 `127.0.0.1`，RFC 6066 不发 SNI）时 `iquic_lookup_cert` 在 HTTP/3 模式直接 `return 0` → BoringSSL 中止握手。lsquic 自己的客户端对 IP 也发 SNI，所以 lsquic↔lsquic 不触发。
2. **ack-eliciting Initial 未填到 1200 字节（RFC 9000 §14.1）**。`lsquic_mini_conn_ietf.c` 里填充被注释（"改为 coalesced 后填，省一个包"），但"coalesced 后填"从未实现 → 服务端回 ~60 字节 Initial → ngtcp2 严格校验直接丢弃 → 握手死锁。
3. 早期观测到的 "TLS 永远 WANT_READ、ServerHello 永不生成" **不是独立缺陷**——它是缺陷 2 的下游症状：客户端丢弃未填充的 Initial，服务端永远收不到 Handshake。

**修复**：`docs/lsquic-4.7.0-http3-interop-a-b.patch`（两处 hunk：回退默认证书 + 恢复 Initial 填充）。打上后，完整 H3→H1 代理链路用 `curl -k --http3-only` 在 `localhost`（有 SNI）和 `127.0.0.1`（无 SNI）**均返回 200**。

> ⚠️ **先前的根因结论（SCID 不一致 / 20 字节 DCID）是错误归因**，已推翻：那是在 TLS 停滞触发 SREJ 后，把 **Retry 包的 SCID** 误当成 Initial 的 SCID；20 字节 DCID 也是障眼法（curl 恰好同时满足 20 字节 DCID + OpenSSL + 对 IP 无 SNI，三个变量与 lsquic 客户端全不同）。此教训已写进 issue。

**补丁维护**：`third_party/` 被 gitignore，`git submodule update`/重检出会静默回退补丁。构建钩子 `scripts/ensure_lsquic_patch.sh`（CMake `lsquic-patch-guard` target）会在链接 lsquic 的目标构建前自动重新应用，并在 `liblsquic.a` 由未打补丁源码编出时**响亮失败**（给出重建命令）。

最小复现 harness：`examples/lsquic_h3_server_min.cpp`（纯 lsquic+BoringSSL，不依赖代理层）——未打补丁的 lsquic 上 `curl --http3` 即复现。

**顺带修复的真 bug（本 refactor 引入，非此缺陷）**：worker 的 io_context 空转时 `io_context::run()` 立即返回、线程退出，导致 ingress `post` 的投递 handler（TCP fd / QUIC 包）永不执行——`quic_port=0` 且空闲时尤其明显。修复 = `asio::make_work_guard` 让每个 io_context 常驻（见 §3）。
