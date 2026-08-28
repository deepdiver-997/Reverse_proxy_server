# 设计决策（ADR）与开放问题

记录本项目关键取舍背后的动机，以及**尚未拍板、需要决策**的事项。

## 已决策

### ADR-1：双协议监听，共享 ProxyCore

**背景**：TCP/HTTP/1.1 是成熟路径，QUIC/HTTP/3 是目标特性，两者请求转发逻辑完全一致。
**决策**：`ITransportSession`/`ITransportStream` 屏蔽传输差异，`ICodec` 屏蔽协议差异；`ProxyCore` 按 `session->protocol()` 选 codec，路由/转发对协议无感。
**后果**：新协议只需新增一个 transport + codec 对，核心逻辑零改动。

### ADR-2：lsquic 采用"你当事件循环，它当状态机"的同步驱动

**背景**：lsquic 无自带线程/IO，所有进出都要宿主提供。
**决策**：UDP 收包回调里同步 `lsquic_engine_packet_in` + `process_conns`；发包用同步 `sendmsg`（不缓存不异步）；用 `earliest_adv_tick` + asio 定时器实现时间节拍。
**后果**：全部回调单线程重入、无锁；但要求回调不做阻塞操作，且引擎必须单线程驱动。
**依据**：详见 [transport.md](transport.md) §2、§5。

### ADR-3：单引擎单线程，扩展走"多引擎分片"

**背景**：lsquic 引擎非线程安全，`num_threads > 1` 时收包/定时器两个入口会并发摸引擎。
**决策**：保持 `num_threads = 1`（默认值）；未来要多核，按连接（CID）哈希分片到 N 个引擎、每引擎一线程，而不是给单引擎加锁。
**后果**：现在零锁零并发问题；加锁方案被否决（收益为零 + 回调链死锁风险）。

### ADR-4：`QuicTransportSession*` 直接作为 `lsquic_conn_ctx_t`

**背景**：lsquic 的 conn_ctx 是不透明指针，只存原样还。
**决策**：session 即 ctx；listener 用 `sessions_` map（key=ctx）持有 shared_ptr；`on_conn_closed` 通过 session 上的 listener 回指 `take_session()` 摘除并保活。
**后果**：免去一层 ctx 结构体；生命周期由 map + `on_conn_closed` 清理保证。

### ADR-5：`lsquic_global_init` 必须在引擎创建前调用一次

**背景**：曾因遗漏导致 BoringSSL `CRYPTO_set_ex_data(index=-1)` 直接 `abort()`，SIGABRT。
**决策**：构造 `QuicTransportListener` 时一次性 `lsquic_global_init(LSQUIC_GLOBAL_SERVER)`。
**依据**：完整排查记录见 [crash_report.md](crash_report.md)。

## 开放问题（需要决策）

### ① HTTP/3 头处理：手写帧解析 vs lsquic 原生 H3 ⭐ 最重要

现状是**两套架构混在一起，互不兼容**：

- `QuicTransportListener` 用 `LSENG_HTTP` 标志 + 一个返回 `nullptr` 的假 `hsi_prepare_decode`（当前工作区改动，未提交）。
- 而 `H3Codec` 是**从头解析裸 H3 帧**（HEADERS/DATA varint 帧头）。

问题：`LSENG_HTTP` 下 lsquic **自己拥有 H3 帧层**——它解码 QPACK、消费 HEADERS 帧、把 `lsquic_stream_write` 的内容包进 DATA 帧、并要求先 `lsquic_stream_send_headers`。此时流里读到的不是裸帧，`H3Codec` 解析不了；返回 `nullptr` 的假 HSI 还可能导致 header decode 失败路径。**两者只能选一个：**

- **路线 A：裸模式（与现有 H3Codec 自洽）**。`LSENG_SERVER`（去掉 `LSENG_HTTP`），不设 `ea_hsi_if`，让 `H3Codec` 从裸流解析、响应也手写 H3 帧。改动小，但与 lsquic 自带的 H3 支持重复造轮子。
- **路线 B：lsquic 原生 H3**。实现完整 HSI（QPACK/lsxpack）、用 `on_hset_in`/`lsquic_stream_get_hset` 取头、用 `lsquic_stream_send_headers` 发响应。更"正统"，但要写 QPACK 相关胶水。

**建议**：demo 阶段走 A 更务实；想贴近生产走 B。决策前不要在这两种状态间反复横跳。

### ② 响应路径绕过 codec

`ProxyCore::forward_request` 把上游的 HTTP/1.1 字节直接写回客户端流，`H3Codec::async_write_response` 从未被调用。TCP 成立，H3 下响应缺 HEADERS 帧。应在响应方向也接 codec（至少为 H3 客户端）。

### ③ 上游连接复用

当前 `UpstreamPool::async_connect` 每个请求新开一条 TCP 连接（lazy、无池）。高并发下开销大、无 keep-alive 复用。后续可加连接池 / HTTP/1.1 keep-alive / 或对支持 QUIC 的上游用 QUIC。

### ④ 多引擎水平扩展

见 ADR-3：按 CID 分片到多引擎。目前未实现，`QuicTransportListener` 仍是单例。

## 决策检查表（改动前对照）

1. 我动的是不是 **listener 级**（socket/engine/timer）还是 **session 级**（conn_ctx）的状态？别混。
2. 新回调是否在 lsquic 回调栈上同步执行？里面不要阻塞、不要等另一个线程拿引擎锁。
3. `lsquic_stream_read/write` 的返回值/errno 是否按本文语义处理？
4. 新加对象是否被 map/shared_ptr 正确持有？`on_conn_closed`/`on_close` 是否清理？
5. `num_threads > 1` 时，会不会有两个入口同时摸引擎？
