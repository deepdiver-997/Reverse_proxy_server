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
**决策**：session 即 ctx；**session 用自持 `shared_ptr`（`self_`）承担所有权**（刻意可破的循环，非泄漏）——`on_new_conn` 里 `adopt_self()`，`on_conn_closed` 里先取 `shared_from_this()` 保活拷贝、再 `on_closed()`、最后 `release_self()`，析构发生在最后一个 lsquic 回调返回之后。
**后果**：免去一层 ctx 结构体 + 免去 listener 的 `sessions_` 注册表；`find_session` 直接 reinterpret ctx。生命周期契约见 [transport.md §4](transport.md)。

### ADR-5：`lsquic_global_init` 必须在引擎创建前调用一次

**背景**：曾因遗漏导致 BoringSSL `CRYPTO_set_ex_data(index=-1)` 直接 `abort()`，SIGABRT。
**决策**：构造 `QuicTransportListener` 时一次性 `lsquic_global_init(LSQUIC_GLOBAL_SERVER)`。
**依据**：完整排查记录见 [crash_report.md](crash_report.md)。

### ADR-6：共享 HTTP 语义 IR + "四方 codec"

**背景**：同一份代理核心要同时服务 HTTP/1.1 与 HTTP/3 客户端，且转发到 HTTP/1.1 上游。
**决策**：共享一个协议无关的 HTTP 语义 IR（≈ RFC 9110 消息模型，即现有 `HttpRequestHead`/`HttpResponseHead`）；每个 wire 协议各自实现 parser 与 generator，做 `wire ↔ IR` 双向转换，**没有 H1→H3 直连映射器**。反代 = 四方 codec：H1Parser（客户端/上游入）、H1Generator（上游出）、H3Parser（客户端入）、H3Generator（客户端响应出）。
**语义差异都在 codec 内部消化（不是字段拷贝）**：
- 请求行 ↔ pseudo-headers（`:method/:path/:scheme/:authority/:status`）：H1 从请求行 + Host 派生，H3 写 pseudo-header。
- **hop-by-hop 头**（Connection/Keep-Alive/Transfer-Encoding/Upgrade）跨协议必须剥离（RFC 9113 §8.1.2.2）——朴素映射最容易错的地方。
- Body 帧格式：IR 的 body 是流、无帧格式；H1 去/re-chunked，H3 的 DATA 帧归传输层。
- Trailer、Upgrade/101 各有跨协议映射（H2/3 用 Extended CONNECT 机制）。
**后果**：新增协议 = 新增一对 codec；现有 IR 需补充 `scheme`/`authority`/`version` 一等字段（正向代理绝对 URI 必需）。

### ADR-7：代理核心 = 后端选择 + 双向 relay session

**背景**：反代与正代在传输层是同一件事。
**决策**：核心抽象为一个 `RelaySession`：持有客户端流 + 后端流，把「客户端读 ↔ 后端写」「后端读 ↔ 客户端写」双向泵起来。**正反代理的唯一差异在后端选择**：
- 反代：客户端不指明目标 → 按 Host/SNI 走路由表选后端。
- 正代：客户端给出目标（绝对 URI 或 `CONNECT host:port`）→ 解析目标直接连。
选择完成后两者完全相同：建立连接 → 双向泵。
**泵的粒度**：纯隧道（CONNECT / WebSocket / 裸 TCP）按字节泵、不经 codec；HTTP 若要改写头（Host/Via/X-Forwarded-For）需按消息粒度泵（解析 → 改写 → 转发），codec 参与。
**现状（Step 1 已实现）**：RelaySession 为**相位机**（Request → 路由 + 连接后端 → Response → 按 codec 的 `keep_alive` 回环或关闭）。`ICodec` 解析回调带 `keep_alive` 标志——由内容决定（H1 按 Connection/版本/body 定界算；H3 流恒 false，连接在 session 层持续）。**客户端 H1 keep-alive 已通**；后端仍每请求新建连接（Step 2 连接池待做）。

**RelaySession 骨架**：
```cpp
struct RelaySession : std::enable_shared_from_this<RelaySession> {
    ITransportStreamPtr client;     // 客户端流（TCP 或 QUIC stream）
    ITransportStreamPtr backend;    // 后端流（TCP）
    ICodec* client_codec;           // 解析客户端请求 / 生成客户端响应（H1 或 H3）
    ICodec* backend_codec;          // 生成后端请求 / 解析后端响应（目前 H1）
    // 需要时注入 Router / UpstreamPool
};
```
- 两条流用 shared_ptr 持有：后端流将来归还连接池时，pool 与 relay 各持一份，relay 结束释放自己那份 = 天然支持「借用/归还」复用。
- 依赖注入优于背一个裸 `ProxyCore*`（relay 真正需要的是 codec + router + pool 三样）。
- **泵粒度分界**：先解析请求头 → IR → 路由；同协议且不改写 → 头原样转发 + body/响应字节泵（快速路径）；跨协议或需改写 → 整条消息走 IR 转换；CONNECT/WebSocket 握手后完全字节泵、不经 codec。

### ADR-8：HTTP/3 头处理走 lsquic 原生（路线 B）

**背景**：原开放问题 ①——H3 头处理是手写帧解析（路线 A）还是 lsquic 原生（路线 B）。
**决策**：**路线 B**。lsquic 拥有 H3 帧层 + QPACK；实现完整 HSI（QPACK/lsxpack）、用 `on_hset_in`/`lsquic_stream_get_hset` 取头、用 `lsquic_stream_send_headers` 发响应。
**理由**：
- QPACK（RFC 9204）与 HPACK 同量级复杂度（动态表/静态表/Huffman/blocked stream），手写正确且互操作 = 数周工作量 + 大正确性风险，demo 不值得。
- 现状 `H3Codec` 的 literal-headers（无 QPACK）**不可与真实客户端互操作**——浏览器 / `curl --http3` 发的是 QPACK 压缩头。
- "减少依赖"不成立：QUIC 层本就依赖 lsquic；路线 A 只是换成自写 QPACK（或 vendoring lshpack/nghttp3 的更多胶水）。
**实现状态（已完成核心）**：
- `QuicTransportListener` 的 HSI 已实现（`QuicH3HeaderSet`：QPACK 解码缓冲 + 头部收集，`hsi_create/prepare_decode/process/discard`），假 HSI 已移除。
- `QuicTransportStream` 新增 `async_take_headers`（`lsquic_stream_get_hset` 认领解码头 → IR）与 `async_send_headers`（`lsquic_stream_send_headers`），`on_readable` 优先投递解码头。
- `H3Codec::async_parse_request` 走 transport 解码头 → IR，body 为 DATA 读到 FIN；`async_write_response` 走 `send_headers` + body 泵。手写帧解析状态机已移除（varint + `h3_detail::parse_request_headers` 工具保留，仍有单测）。
- **未接**：H3 上游（`async_parse_response`/`async_write_request`）——后端仍是 HTTP/1.1，这两个保持 `operation_not_supported` 占位。

## 开放问题（需要决策）

### ① HTTP/3 头处理 ⭐ 已决策

已决策：**路线 B（lsquic 原生 H3）**，理由与实现待办见 [ADR-8](#adr-8http3-头处理走-lsquic-原生路线-b)。原"手写 vs 原生"二选一已关闭；剩余是 ADR-8 里的实现待办。

### ② 响应路径绕过 codec ✅ 已解决

`RelaySession`（ADR-7）让响应方向走 codec：后端 codec 解析响应 → 客户端 codec 写回。H1 响应（CL/chunked/close-delimited）已实现；H3 响应走 `H3Codec::async_write_response` → `lsquic_stream_send_headers` + DATA body（ADR-8）。

### ③ 上游连接复用（keep-alive pool）✅ Step 1 + Step 2 已完成

- **Step 1**：客户端 H1 keep-alive（`RelaySession` 相位机按 `keep_alive` 回环）。
- **Step 2**：后端连接池。`UpstreamPool` 增加 `release()`（归还空闲连接 + 每 endpoint 上限 8）与 `async_connect_fresh()`；`async_connect` 优先复用空闲连接。`RelaySession::finish_backend` 按后端响应的 `keep_alive` 决定归还池还是关闭。陈旧池连接（后端空闲时关闭）在写入失败时用新鲜连接**重试一次**（仅无请求体时）。chunked 响应已消费 trailer 段，保证归还的连接处于干净边界。

剩余考虑点：
- **HTTP/1.1 keep-alive**：一条连接可顺序服务多个请求 → 需要「借用/归还」池，且要处理：响应定界（无 Content-Length 时）、陈旧连接回收、每 host 连接数上限、请求串行化（H1 一条连接同时只能一个在途请求）。
- **若后端支持 HTTP/2/3**：一条连接多路复用多条流 → 复用收益更大（N 并发请求共享一条连接），但上游也要换 codec。
- 反代通常必须复用上游连接（Envoy/nginx 标准做法）；demo 阶段按请求新建可接受。

### ④ 多引擎水平扩展

见 ADR-3：按 CID 分片到多引擎。目前未实现，`QuicTransportListener` 仍是单例。

## 决策检查表（改动前对照）

1. 我动的是不是 **listener 级**（socket/engine/timer）还是 **session 级**（conn_ctx）的状态？别混。
2. 新回调是否在 lsquic 回调栈上同步执行？里面不要阻塞、不要等另一个线程拿引擎锁。
3. `lsquic_stream_read/write` 的返回值/errno 是否按本文语义处理？
4. 新加对象是否被 map/shared_ptr 正确持有？`on_conn_closed`/`on_close` 是否清理？
5. `num_threads > 1` 时，会不会有两个入口同时摸引擎？
